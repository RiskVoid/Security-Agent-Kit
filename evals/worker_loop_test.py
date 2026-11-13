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
import digest  # noqa: E402


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


class Stalls(Loop):
    """#34 and #37: repeats, repeated errors and no progress get a nudge, then advice, then a stop."""

    def setUp(self):
        super().setUp()
        self.asked = []
        worker.advise = lambda task, kind, detail: (self.asked.append((kind, detail)),
                                                    task.setdefault("advisor", []).append({"kind": kind}),
                                                    self.advice)[2] if len(task.get("advisor") or []) < 2 else None
        self.advice = "Try the /api path instead, or finish."

    def same(self, n, cmd="curl -s http://x/"):
        return [[call("kali_run", {"command": cmd})] for _ in range(n)]

    def test_repeat_nudge_then_advice_then_stop(self):
        task, msgs = self.run_script(self.same(12))
        texts = self.tool_texts(msgs)
        self.assertIn("[harness] You look stuck", texts[2])           # third identical call: nudge
        self.assertIn("Advice from the lead consultant", texts[5])    # sixth: first consult
        self.assertIn("Advice from the lead consultant", texts[8])    # ninth: second consult
        self.assertEqual(task["status"], "stalled")                  # twelfth: no more consults, stop
        self.assertEqual(len(texts), 12)
        self.assertEqual([s["action"] for s in task["stalls"]], ["nudge", "advice", "advice", "stop"])
        self.assertEqual(self.asked[0][0], "repeat")
        self.assertIn("stalled", task["error"])

    def test_without_advisor_the_second_stall_stops(self):
        worker.advise = lambda task, kind, detail: None
        task, _ = self.run_script(self.same(10))
        self.assertEqual(task["status"], "stalled")
        self.assertEqual([s["action"] for s in task["stalls"]], ["nudge", "stop"])
        self.assertEqual(len(self.ran), 6)

    def test_same_error_with_different_commands(self):
        for i in range(4):
            self.outputs[f"cat /nope{i}"] = f"exit=2 tier=passive\n[stderr]\ncat: /nope{i}: No such file or directory"
        task, msgs = self.run_script([[call("kali_run", {"command": f"cat /nope{i}"})] for i in range(4)])
        self.assertEqual(task["stalls"][0]["kind"], "error")
        self.assertIn("You look stuck", self.tool_texts(msgs)[2])

    def test_no_progress(self):
        for i in range(10):
            self.outputs[f"echo {i}"] = "exit=0 tier=passive\nsame output"
        task, _ = self.run_script([[call("kali_run", {"command": f"echo {i}"})] for i in range(10)])
        self.assertEqual(task["stalls"][0]["kind"], "no-progress")
        self.assertEqual(task["stalls"][0]["step"], 9)       # the first output was new; 8 idle calls after it

    def test_progress_resets(self):
        task, _ = self.run_script([[call("kali_run", {"command": f"echo {i}"})] for i in range(12)])
        self.assertFalse(task.get("stalls"))
        self.assertEqual(task["status"], "done")


class Advisor(unittest.TestCase):
    """#37: what goes to the planner model, and when it isn't asked."""

    def setUp(self):
        self.saved = worker.urllib.request.urlopen
        self.sent = []

        class R:
            def __init__(s, body):
                s.body = body

            def read(s):
                return json.dumps({"model": "planner", "usage": {"total_tokens": 99},
                                   "choices": [{"message": {"content": "Finish now."}}]}).encode()
        def fake(req, timeout=None):
            self.sent.append((req.full_url, dict(req.header_items()), json.loads(req.data)))
            return R(None)
        worker.urllib.request.urlopen = fake

    def tearDown(self):
        worker.urllib.request.urlopen = self.saved

    def task(self, **rules):
        return {"id": "t", "engagement": "eng", "goal": "Find SQLi in /src/x", "tier": "passive", "step": 4,
                "info": {"rules": rules}, "lines": {"c1": "[shrunk] kali_run grep -r SELECT /src/x | exit=0 | 3 hits"}}

    def test_sends_the_digest_not_the_output(self):
        t = self.task()
        self.assertEqual(worker.advise(t, "repeat", "kali_run x sent 3 times"), "Finish now.")
        url, headers, body = self.sent[0]
        self.assertTrue(url.endswith("/chat/completions"))
        self.assertEqual(body["model"], worker.ADVISOR_MODEL)
        self.assertEqual({k.lower(): v for k, v in headers.items()}["x-rv-engagement"], "eng")
        text = json.dumps(body["messages"])
        self.assertIn("[shrunk] kali_run grep", text)
        self.assertEqual(t["advisor"][0]["tokens"], {"total_tokens": 99})

    def test_limits(self):
        t = self.task()
        for _ in range(3):
            worker.advise(t, "repeat", "x")
        self.assertEqual(len(self.sent), worker.ADVISOR_MAX)
        self.assertIsNone(worker.advise(self.task(worker="private"), "repeat", "x"))   # no egress for a private worker
        self.assertEqual(len(self.sent), worker.ADVISOR_MAX)


class Compact(unittest.TestCase):
    """#35: the latest results stay whole, older ones shrink to one line, once."""

    def conv(self, n, size=20000):
        msgs = [{"role": "system", "content": "RULES " + "r" * 5000}, {"role": "user", "content": "GOAL " + "g" * 5000}]
        lines = {}
        for i in range(n):
            msgs.append({"role": "assistant", "content": None, "tool_calls": [call("kali_run", {"command": f"c{i}"},
                                                                                 cid=f"id{i}")]})
            msgs.append({"role": "tool", "tool_call_id": f"id{i}", "content": f"out{i} " + "x" * size})
            lines[f"id{i}"] = f"[shrunk] kali_run c{i} | exit=0 | full output: /work/e/{i}.txt"
        return msgs, lines

    def test_keeps_recent_and_shrinks_old_to_one_line(self):
        msgs, lines = self.conv(8)
        worker.compact(msgs, lines)
        tools = [m["content"] for m in msgs if m["role"] == "tool"]
        self.assertEqual(tools[:3], [lines["id0"], lines["id1"], lines["id2"]])
        self.assertTrue(all(t.startswith(f"out{i + 3} ") and len(t) > 20000 for i, t in enumerate(tools[3:])))
        self.assertTrue(msgs[0]["content"].startswith("RULES") and len(msgs[0]["content"]) > 5000)
        self.assertTrue(msgs[1]["content"].startswith("GOAL") and len(msgs[1]["content"]) > 5000)

    def test_only_as_much_as_needed_and_never_twice(self):
        msgs, lines = self.conv(8, size=10500)
        worker.compact(msgs, lines)
        tools = [m["content"] for m in msgs if m["role"] == "tool"]
        self.assertEqual(sum(t.startswith("[shrunk]") for t in tools), 1)    # one old result was enough
        lines["id0"] = "[shrunk] SOMETHING ELSE"
        worker.compact(msgs + [{"role": "user", "content": "y" * 20000}], lines)
        self.assertNotEqual(tools[0], "[shrunk] SOMETHING ELSE")
        self.assertEqual([m["content"] for m in msgs if m["role"] == "tool"][0], tools[0])

    def test_under_budget_nothing_changes(self):
        msgs, lines = self.conv(3, size=1000)
        before = json.dumps(msgs)
        worker.compact(msgs, lines)
        self.assertEqual(json.dumps(msgs), before)


SQLMAP_OUT = "exit=0 tier=intrusive\n" + "[INFO] testing 'AND boolean-based blind'\n" * 400 + """\
sqlmap identified the following injection point(s) with a total of 46 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 5523=5523
---
[INFO] the back-end DBMS is SQLite
back-end DBMS: SQLite
[INFO] fetched data logged to text files under '/work/eng/sqlmap'
[output saved as verified evidence: /work/eng/evidence/runs/sqlmap.txt]"""


class Digests(unittest.TestCase):
    """#32: head and tail with the cut marked, and digests for tools the kit can read."""

    def test_head_and_tail(self):
        text = "A" * 5000 + "MIDDLE" + "Z" * 5000
        out = digest.clip(text, 4000, 2000, "/work/x.txt")
        self.assertTrue(out.startswith("A" * 4000))
        self.assertTrue(out.endswith("Z" * 2000))
        self.assertNotIn("MIDDLE", out)
        self.assertIn("characters cut: full output in /work/x.txt", out)
        self.assertEqual(digest.clip("short"), "short")

    def test_sqlmap_verdict_survives(self):
        shown = digest.shown("kali_run", {"command": "sqlmap -u http://x/?id=1 --batch"}, SQLMAP_OUT)
        self.assertTrue(shown.startswith("DIGEST (sqlmap): injection point(s) found"))
        self.assertIn("Parameter: id (GET)", shown)
        self.assertIn("back-end DBMS: SQLite", shown)
        self.assertLess(len(shown), 6000)
        none = digest.shown("kali_run", {"command": "sqlmap -u x"},
                            "exit=0\n[CRITICAL] all tested parameters do not appear to be injectable.")
        self.assertIn("no injection found", none)

    def test_nmap_and_nuclei(self):
        nmap = ("exit=0 tier=active\nStarting Nmap 7.95\nNmap scan report for 10.250.0.18\nHost is up.\n"
                "PORT     STATE SERVICE VERSION\n22/tcp   closed ssh\n8000/tcp open   http    nginx 1.14.0\n"
                "Nmap done: 1 IP address (1 host up) scanned in 3.1 seconds\n")
        d = digest.shown("kali_run", {"command": "nmap -sV 10.250.0.18"}, nmap)
        self.assertIn("DIGEST (nmap): 1 host(s), 1 open port(s)", d)
        self.assertIn("8000/tcp open http nginx 1.14.0", d)
        nuc = ("exit=0\n[git-config] [http] [medium] http://x/.git/config\n"
               "[tech-detect:nginx] [http] [info] http://x/\n[CVE-2021-1] [http] [critical] http://x/a [\"v\"]\n")
        d = digest.shown("kali_run", {"command": "nuclei -u http://x"}, nuc)
        self.assertIn("3 match(es): 1 critical, 1 medium, 1 info", d)
        self.assertLess(d.index("CVE-2021-1"), d.index("git-config"))       # most severe first
        failed = "exit=126 tier=active\n[stderr]\n/usr/bin/nmap: exec: Operation not permitted"
        self.assertNotIn("DIGEST", digest.shown("kali_run", {"command": "nmap -sV x"}, failed))   # not "0 hosts"

    def test_json_outputs_are_parsed(self):
        sg = {"version": "1.0", "errors": [], "paths": {"scanned": ["a.py"]}, "results": [
            {"check_id": "python.sqli", "path": "/src/a.py", "start": {"line": 3}, "end": {"line": 3},
             "extra": {"severity": "ERROR", "message": "SQL built from input", "lines": "q = 'x' + y"}},
            {"check_id": "python.debug", "path": "/src/a.py", "start": {"line": 9}, "end": {"line": 9},
             "extra": {"severity": "INFO", "message": "debug on", "lines": "app.run(debug=True)"}}]}
        out = "exit=1 tier=passive\n" + json.dumps(sg) + "\n[output saved as verified evidence: /work/eng/e/sg.json]"
        d = digest.shown("kali_run", {"command": "semgrep --json"}, out)
        self.assertIn("DIGEST (semgrep): 2 result(s): 1 high, 1 low", d)
        self.assertIn("python.sqli at /src/a.py:3", d)
        self.assertIn("(full output: /work/eng/e/sg.json)", d)
        self.assertNotIn('"check_id"', d)
        gl = [{"RuleID": "aws-key", "File": "/src/.env", "StartLine": 2, "Description": "AWS key", "Secret": "x",
               "Match": "AKIA", "Fingerprint": "f"}]
        self.assertIn("DIGEST (gitleaks): 1 result(s)", digest.shown("kali_run", {"command": "gitleaks"},
                                                                     "exit=1\n" + json.dumps(gl)))

    def test_unknown_output_is_clipped(self):
        out = "exit=0\n" + "x" * 9000 + "THE-END"
        shown = digest.shown("kali_run", {"command": "curl -s http://x/"}, out, "/work/s.txt")
        self.assertTrue(shown.endswith("THE-END"))
        self.assertIn("characters cut", shown)

    def test_one_line(self):
        line = digest.one_line("kali_run", {"command": "sqlmap -u http://x/?id=1 --batch"}, SQLMAP_OUT)
        self.assertEqual(line, "[shrunk] kali_run sqlmap -u http://x/?id=1 --batch | exit=0 | DIGEST (sqlmap): "
                               "injection point(s) found | full output: /work/eng/evidence/runs/sqlmap.txt")


class ToolOutputInTheLoop(Loop):
    def test_worker_sees_the_sqlmap_verdict(self):
        self.outputs["sqlmap -u http://x/?id=1 --batch"] = SQLMAP_OUT.rsplit("\n", 1)[0]
        task, msgs = self.run_script([[call("kali_run", {"command": "sqlmap -u http://x/?id=1 --batch"})]])
        shown = self.tool_texts(msgs)[0]
        self.assertIn("injection point(s) found", shown)
        self.assertIn("back-end DBMS: SQLite", shown)
        self.assertTrue(task["lines"])


if __name__ == "__main__":
    warnings.simplefilter("ignore", ResourceWarning)
    unittest.main(verbosity=1, warnings="ignore")
