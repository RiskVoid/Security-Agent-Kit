"""A scripted, OpenAI-compatible chat model for testing the worker's agent loop without a GPU or an API key.

It answers /v1/chat/completions the way a tool-calling model would, following a fixed plan:
  1. kali_run  ls -la <first /src path in the system prompt's scope>
  2. record_candidate  citing the path kali_run printed after "output saved as verified evidence"
  3. finish
Each step depends on what came back from the previous one (the tool result in the conversation), so the test
exercises the real loop: the request format, tool-call parsing, the kali sandbox, evidence and findings.

  python3 evals/mock_llm.py [port]       serve on 127.0.0.1:<port> (default 8099)
  import mock_llm; mock_llm.serve(port)  start in a background thread (evals/agent_loop_test.sh does this
                                          inside the worker container)
Also records every request in REQUESTS, so a test can check what the worker sent.

Scenario mode: a deterministic stub for any client (the planner path, the model log, error handling), no GPU and no
provider account. A scenario is a list of steps; the reply to a request is the step for its turn (how many assistant
messages the conversation already has), the last step repeating, so the same conversation always gets the same answer:
  {"content": "text"}                                   a plain answer
  {"tool_call": {"name": "...", "arguments": {...}}}    one tool call
  {"status": 429, "error": "rate limited"}              an HTTP error in the OpenAI error format (402, 500, ...)
  {"refusal": true}                                     an empty answer with finish_reason content_filter
Streaming requests ("stream": true, as OpenHands sends) get the same answer as server-sent chunks.
  python3 evals/mock_llm.py <port> --scenario <file.json>
  mock_llm.SCENARIO = [...]               from a test
"""
import json, re, sys, threading, time, uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REQUESTS = []
TITLE = "Mock finding from the agent-loop test"
SCENARIO = None  # list of steps (see above); None: the worker agent-loop plan


def _call(name, args):
    return {"id": "call_" + uuid.uuid4().hex[:8], "type": "function",
            "function": {"name": name, "arguments": json.dumps(args)}}


def reply(body):
    """The next assistant message for this conversation."""
    msgs = body.get("messages", [])
    tools = {t["function"]["name"] for t in body.get("tools", [])}
    tool_results = [m for m in msgs if m.get("role") == "tool"]
    system = next((m.get("content", "") for m in msgs if m.get("role") == "system"), "")
    if not {"kali_run", "record_candidate", "finish"} <= tools:
        return {"role": "assistant", "content": "missing tools: expected kali_run, record_candidate, finish"}
    if not tool_results:
        m = re.search(r'"(/src/[^"]+)"', system)
        target = m.group(1) if m else "/src"
        return {"role": "assistant", "content": None, "tool_calls": [_call("kali_run", {"command": f"ls -la {target}"})]}
    last = tool_results[-1]["content"]
    if len(tool_results) == 1:
        m = re.search(r"output saved as verified evidence: (\S+?)\]", last)
        if not m:
            return {"role": "assistant", "content": None, "tool_calls": [_call("finish", {
                "summary": "kali_run returned no evidence path: " + last[:300], "confidence": "low"})]}
        return {"role": "assistant", "content": None, "tool_calls": [_call("record_candidate", {
            "title": TITLE, "severity": "info", "asset": "/src", "cwe": "CWE-0",
            "description": "Recorded by the scripted test model; not a real issue.", "evidence": [m.group(1)]})]}
    return {"role": "assistant", "content": None, "tool_calls": [_call("finish", {
        "summary": "Listed the source folder and recorded one test candidate. " + last[:120],
        "observations": ["mock model"], "confidence": "high"})]}


def scenario_step(body, steps):
    """The scenario step for this conversation's turn."""
    if not steps:
        raise ValueError("empty scenario")
    turn = sum(1 for m in body.get("messages", []) if m.get("role") == "assistant")
    return steps[min(turn, len(steps) - 1)]


def scenario_reply(step):
    """(http status, message or error text, finish_reason) for a scenario step."""
    if "status" in step:
        return int(step["status"]), str(step.get("error", "mock error")), None
    if step.get("refusal"):
        return 200, {"role": "assistant", "content": ""}, "content_filter"
    if "tool_call" in step:
        c = step["tool_call"]
        return 200, {"role": "assistant", "content": None, "tool_calls": [_call(c["name"], c.get("arguments", {}))]}, \
            "tool_calls"
    return 200, {"role": "assistant", "content": str(step.get("content", ""))}, "stop"


def _chunks(msg, finish, model):
    """The answer as OpenAI streaming chunks."""
    base = {"id": "mock-" + uuid.uuid4().hex[:8], "object": "chat.completion.chunk", "created": int(time.time()),
            "model": model}
    delta = {"role": "assistant"}
    if msg.get("tool_calls"):
        delta["tool_calls"] = [{**c, "index": i} for i, c in enumerate(msg["tool_calls"])]
    else:
        delta["content"] = msg.get("content") or ""
    yield {**base, "choices": [{"index": 0, "delta": delta, "finish_reason": None}]}
    yield {**base, "choices": [{"index": 0, "delta": {}, "finish_reason": finish}]}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, code, obj):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(n) or b"{}")
        REQUESTS.append(body)
        model = "mock-" + str(body.get("model"))
        if SCENARIO is not None:
            code, msg, finish = scenario_reply(scenario_step(body, SCENARIO))
            if code != 200:
                return self._json(code, {"error": {"message": msg, "type": "mock_error", "code": code}})
        else:
            msg, finish = reply(body), "tool_calls"
        if body.get("stream"):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            for c in _chunks(msg, finish, model):
                self.wfile.write(f"data: {json.dumps(c)}\n\n".encode())
            self.wfile.write(b"data: [DONE]\n\n")
            return
        self._json(200, {"id": "mock-" + uuid.uuid4().hex[:8], "object": "chat.completion", "created": int(time.time()),
                         "model": model, "choices": [{"index": 0, "message": msg, "finish_reason": finish}],
                         "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}})


def serve(port=8099, background=True):
    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    if background:
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv
    srv.serve_forever()


if __name__ == "__main__":
    args = sys.argv[1:]
    if "--scenario" in args:
        i = args.index("--scenario")
        SCENARIO = json.load(open(args[i + 1]))
        del args[i:i + 2]
    port = int(args[0]) if args else 8099
    print(f"mock model on http://127.0.0.1:{port}/v1")
    serve(port, background=False)
