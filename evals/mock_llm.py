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
"""
import json, re, sys, threading, time, uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REQUESTS = []
TITLE = "Mock finding from the agent-loop test"


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


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(n) or b"{}")
        REQUESTS.append(body)
        out = {"id": "mock-" + uuid.uuid4().hex[:8], "object": "chat.completion", "created": int(time.time()),
               "model": "mock-" + str(body.get("model")), "choices": [{"index": 0, "message": reply(body),
               "finish_reason": "tool_calls"}], "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}}
        data = json.dumps(out).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def serve(port=8099, background=True):
    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    if background:
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv
    srv.serve_forever()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8099
    print(f"mock model on http://127.0.0.1:{port}/v1")
    serve(port, background=False)
