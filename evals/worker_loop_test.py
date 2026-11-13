"""The worker's loop with a scripted model and fake tools: no stack, no GPU, no mcp package (epic #52, phase 2).

Covers what the loop decides on its own: malformed tool calls, what a tool result shows the model (head and tail,
digests), stall and repeat detection, the advisor, and how old results shrink. The real tools and the real model
path are covered by evals/agent_loop_test.sh.

Run: python3 evals/worker_loop_test.py
"""
import json, os, sys, tempfile, time, types, unittest, warnings

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(KIT, "harness"))


def _stub_mcp():
    """worker.py imports the MCP SDK at module level; the loop doesn't need it."""
    if "mcp" in sys.modules and not getattr(sys.modules["mcp"], "_rv_stub", False):
        return
    class FastMCP:
        def __init__(self, *a, **k):
            pass

        def tool(self, *a, **k):
            return lambda f: f

        def run(self, *a, **k):
            pass
    mods = {"mcp": types.ModuleType("mcp"), "mcp.client": types.ModuleType("mcp.client"),
            "mcp.client.streamable_http": types.ModuleType("mcp.client.streamable_http"),
            "mcp.server": types.ModuleType("mcp.server"), "mcp.server.fastmcp": types.ModuleType("mcp.server.fastmcp")}
    mods["mcp"].ClientSession = object
    mods["mcp"]._rv_stub = True
    mods["mcp.client.streamable_http"].streamablehttp_client = None
    mods["mcp.server.fastmcp"].FastMCP = FastMCP
    sys.modules.update(mods)


_stub_mcp()
import worker  # noqa: E402


def call(name, args, raw=None, cid=None):
    return {"id": cid or f"c{call.n}", "type": "function",
            "function": {"name": name, "arguments": raw if raw is not None else json.dumps(args)}}


call.n = 0


class Loop(unittest.TestCase):
    """Drive worker._loop with a script: each model turn is a list of tool calls (or a text answer)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        worker.db.WORK = self.tmp.name
        os.makedirs(os.path.join(self.tmp.name, "eng", "evidence"), exist_ok=True)
        self.saved = {k: getattr(worker, k, None) for k in ("chat", "engagement_info", "IMPL", "advise")}
        self.ran = []                 # what the fake tools were asked to do
        self.sent = []                # the messages each model call got
        worker.engagement_info = lambda eng: {"halted": False, "rules": {"tiers": ["passive"]},
                                              "scope": {"paths": ["/src/x"]}}

        def fake_kali(task, command, timeout_s=600, approval_id=""):
            self.ran.append(command)
            out = self.outputs.get(command, f"exit=0 tier=passive\nran {command}\n")
            n = len(self.ran)
            return out + f"\n[output saved as verified evidence: /work/eng/evidence/runs/{n:03d}.txt]"
        worker.IMPL = {**worker.IMPL, "kali_run": fake_kali,
                       "record_candidate": lambda task, **a: (task["candidates"].append("F-001"), "recorded F-001")[1]}
        self.outputs = {}

    def tearDown(self):
        for k, v in self.saved.items():
            setattr(worker, k, v)
        self.tmp.cleanup()

    def run_script(self, turns, max_steps=20, **task_extra):
        script = list(turns)

        def chat(messages, model=None, task=None):
            self.sent.append(json.loads(json.dumps(messages)))
            turn = script.pop(0) if script else [call("finish", {"summary": "done", "confidence": "low"})]
            if isinstance(turn, str):
                return {"role": "assistant", "content": turn}
            for c in turn:
                call.n += 1
            return {"role": "assistant", "content": None, "tool_calls": turn}
        worker.chat = chat
        task = worker._defaults({"id": "t1", "goal": "Test the thing.", "engagement": "eng", "tier": "passive",
                                 "info": worker.engagement_info("eng"), "max_steps": max_steps, "timeout_min": 5,
                                 "status": "running", "started": time.time(), **task_extra})
        os.makedirs(worker.task_dir(task), exist_ok=True)
        with open(os.devnull, "w") as log:
            try:
                status = worker._loop(task, log)
            except worker.Stop as s:
                status = s.args[0]
                task["error"] = s.args[1]
        task["status"] = status
        return task, worker.load_messages(task)

    def tool_texts(self, messages):
        return [m["content"] for m in messages if m.get("role") == "tool"]


class MalformedCalls(Loop):
    """#33: broken arguments go back to the model as an error; the tool doesn't run."""

    def test_broken_json_is_not_run(self):
        task, msgs = self.run_script([[call("kali_run", None, raw='{"command": "ls /src/x"')],
                                      [call("kali_run", {"command": "ls /src/x"})]])
        self.assertEqual(self.ran, ["ls /src/x"])                      # only the valid call ran
        err = self.tool_texts(msgs)[0]
        self.assertIn("not valid JSON", err)
        self.assertIn("position", err)
        self.assertIn("Nothing was run", err)
        self.assertEqual(task["malformed"], 1)
        self.assertEqual(task["status"], "done")

    def test_missing_required_and_unknown_tool(self):
        task, msgs = self.run_script([[call("kali_run", {"timeout_s": 5})], [call("nmap", {"x": 1})]])
        self.assertEqual(self.ran, [])
        texts = self.tool_texts(msgs)
        self.assertIn("missing required argument: command", texts[0])
        self.assertIn("no tool named 'nmap'", texts[1])
        self.assertEqual(task["malformed"], 2)

    def test_three_in_a_row_stop_the_task(self):
        bad = [call("kali_run", None, raw="{nope")]
        task, _ = self.run_script([bad, [call("kali_run", None, raw="{nope")], [call("kali_run", None, raw="[")]])
        self.assertEqual(task["status"], "tool_failure")
        self.assertIn("3 malformed tool calls in a row", task["error"])
        self.assertEqual(self.ran, [])

    def test_a_good_call_resets_the_streak(self):
        task, _ = self.run_script([[call("kali_run", None, raw="{")], [call("kali_run", None, raw="{")],
                                   [call("kali_run", {"command": "id"})], [call("kali_run", None, raw="{")]])
        self.assertEqual(task["status"], "done")
        self.assertEqual(task["malformed"], 3)


if __name__ == "__main__":
    warnings.simplefilter("ignore", ResourceWarning)
    unittest.main(verbosity=1)
