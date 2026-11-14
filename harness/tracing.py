"""OpenTelemetry trace export for worker tasks, model calls and tool calls (epic #52, issue #51). Off by default.

Spans follow the OpenTelemetry GenAI semantic conventions (still in Development upstream):
  invoke_agent riskvoid-worker   one per worker task run (gen_ai.operation.name=invoke_agent)
  chat <model>                   each model call (gen_ai.request.model, gen_ai.response.model, gen_ai.usage.*)
  execute_tool <tool>            each tool call (gen_ai.tool.name, gen_ai.tool.call.id)
with rv.engagement and rv.task on each. A task's trace id comes from its id, so a task that pauses for an approval
and continues stays one trace.

Settings (.env, passed to worker-mcp):
  RV_TRACING            on | off (default off)
  RV_TRACE_ENDPOINT     the OTLP/HTTP endpoint: the bundled Jaeger (http://otel-collector:4318, on the internal
                        rvtrace network; worker-mcp has no route anywhere else). .env's RV_TRACE_ENDPOINT moves only
                        LiteLLM's spans (to Langfuse, say).
  RV_TRACE_CONTENT      on | off (default off). on: messages, tool arguments and tool results go into spans, but
                        only for engagements whose Client data rule allows RV_TRACE_DESTINATION (default "local":
                        a self-hosted collector) and that aren't Network: offline. Otherwise spans carry names,
                        timings, models, token counts and statuses only: no tool output, no client code.

No dependency: spans are posted as OTLP JSON by a background thread. Export never blocks or fails a task; a
collector that doesn't answer loses spans, nothing else.
"""
import contextvars, hashlib, json, os, queue, random, threading, time, urllib.request

ENABLED = os.environ.get("RV_TRACING", "off").lower() in ("on", "1", "true", "yes")
ENDPOINT = os.environ.get("RV_TRACE_ENDPOINT", "http://otel-collector:4318").rstrip("/")
CONTENT = os.environ.get("RV_TRACE_CONTENT", "off").lower() in ("on", "1", "true", "yes")
DESTINATION = os.environ.get("RV_TRACE_DESTINATION", "local")
SERVICE = os.environ.get("RV_TRACE_SERVICE", "riskvoid-worker")
MAX_ATTR = 8000
_current = contextvars.ContextVar("rv_span", default=None)
_queue = queue.Queue(maxsize=5000)
_thread = None
_lock = threading.Lock()
sent = []   # tests: the batches posted (kept only when RV_TRACE_KEEP is set)


def _headers():
    h = {"Content-Type": "application/json"}
    for part in (os.environ.get("RV_TRACE_HEADERS") or "").split(","):
        k, sep, v = part.partition("=")
        if sep and k.strip():
            h[k.strip()] = v.strip()
    return h


def content_allowed(rules):
    """May content (messages, tool arguments and results) of this engagement go into spans?"""
    if not CONTENT or not isinstance(rules, dict):
        return False
    if rules.get("network") == "offline":
        return False
    allowed = rules.get("client_data")
    return allowed is None or DESTINATION in allowed


def _value(v):
    if isinstance(v, bool):
        return {"boolValue": v}
    if isinstance(v, int):
        return {"intValue": str(v)}
    if isinstance(v, float):
        return {"doubleValue": v}
    if isinstance(v, (list, tuple)) and all(isinstance(x, str) for x in v):
        return {"arrayValue": {"values": [{"stringValue": x[:MAX_ATTR]} for x in v]}}
    if not isinstance(v, str):
        v = json.dumps(v, default=str)
    return {"stringValue": v[:MAX_ATTR]}


class Span:
    def __init__(self, name, attrs=None, parent=None, trace_id=None, kind=1, content=False):
        self.name, self.kind, self.content = name, kind, content
        self.trace_id = trace_id or (parent.trace_id if parent else "%032x" % random.getrandbits(128))
        self.span_id = "%016x" % random.getrandbits(64)
        self.parent_id = parent.span_id if parent else None
        self.start_ns, self.end_ns = time.time_ns(), None
        self.attrs = {k: v for k, v in (attrs or {}).items() if v is not None}
        self.status, self.message, self._token = 0, None, None

    def set(self, key, value):
        if value is not None:
            self.attrs[key] = value
        return self

    def content_attr(self, key, value):
        """An attribute that carries content: kept only when the engagement allows it (content_allowed)."""
        if self.content and value is not None:
            self.attrs[key] = value
        return self

    def error(self, message):
        self.status, self.message = 2, str(message)[:500]
        self.attrs["error.type"] = str(message).split(":")[0][:100]
        return self

    def end(self):
        if self.end_ns is None:
            self.end_ns = time.time_ns()
            _emit(self)

    def otlp(self):
        d = {"traceId": self.trace_id, "spanId": self.span_id, "name": self.name, "kind": self.kind,
             "startTimeUnixNano": str(self.start_ns), "endTimeUnixNano": str(self.end_ns or time.time_ns()),
             "attributes": [{"key": k, "value": _value(v)} for k, v in self.attrs.items()],
             "status": {"code": self.status, **({"message": self.message} if self.message else {})}}
        if self.parent_id:
            d["parentSpanId"] = self.parent_id
        return d

    def __enter__(self):
        self._token = _current.set(self)
        return self

    def __exit__(self, et, ev, tb):
        if et is not None and self.status == 0:
            self.error(f"{et.__name__}: {ev}")
        _current.reset(self._token)
        self.end()
        return False


class _NoSpan:
    content = False

    def set(self, *a):
        return self

    content_attr = error = set

    def end(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


NOSPAN = _NoSpan()


def span(name, attrs=None, kind=1, trace_key=None, content=None):
    """A child of the current span (or a root). trace_key: a stable id (a task id) for the trace. content: whether
    content attributes are kept (default: the parent's)."""
    if not ENABLED:
        return NOSPAN
    parent = _current.get()
    tid = hashlib.sha256(trace_key.encode()).hexdigest()[:32] if trace_key and not parent else None
    return Span(name, attrs, parent, tid, kind, content if content is not None else bool(parent and parent.content))


def _emit(s):
    global _thread
    try:
        _queue.put_nowait(s)
    except queue.Full:
        return
    with _lock:
        if _thread is None or not _thread.is_alive():
            _thread = threading.Thread(target=_drain, daemon=True)
            _thread.start()


def flush(timeout=5):
    end = time.time() + timeout
    while not _queue.empty() and time.time() < end:
        time.sleep(0.05)
    time.sleep(0.1)


def _drain():
    while True:
        batch = [_queue.get()]
        time.sleep(0.5)
        while len(batch) < 200:
            try:
                batch.append(_queue.get_nowait())
            except queue.Empty:
                break
        body = {"resourceSpans": [{"resource": {"attributes": [
            {"key": "service.name", "value": {"stringValue": SERVICE}}]},
            "scopeSpans": [{"scope": {"name": "riskvoid.harness"}, "spans": [s.otlp() for s in batch]}]}]}
        if os.environ.get("RV_TRACE_KEEP"):
            sent.append(body)
        try:
            urllib.request.urlopen(urllib.request.Request(ENDPOINT + "/v1/traces", data=json.dumps(body).encode(),
                                                          headers=_headers()), timeout=10).read()
        except Exception:  # noqa: BLE001  a collector that doesn't answer loses spans, nothing else
            pass
