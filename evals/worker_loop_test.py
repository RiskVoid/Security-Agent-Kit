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
            turn = script.pop(0) if script else [call("finish", {"status": "completed", "summary": "done", "confidence": "low"})]
            if isinstance(turn, str):
                return {"role": "assistant", "content": turn}
            if isinstance(turn, dict):   # a reply as the gateway returns it (reasoning with no answer, text with a call)
                return {"role": "assistant", **turn}
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



class Contract(Loop):
    """#39: done_when, stop_when and inputs reach the worker; a stop_when naming an approval ends the task there."""
    C = {"done_when": "injection in id is confirmed or ruled out", "stop_when": ["an approval is needed"],
         "inputs": ["evidence/runs/001.txt"]}

    def test_contract_reaches_the_worker(self):
        task, msgs = self.run_script([[call("kali_run", {"command": "ls /src/x"})]], max_steps=6, contract=self.C)
        system = msgs[0]["content"]
        for part in ("Done when: injection in id is confirmed", "Stop when: an approval is needed",
                     "Start from: evidence/runs/001.txt"):
            self.assertIn(part, system)
        self.assertTrue(self.tool_texts(msgs)[0].endswith(
            "[steps left: 5 of 6; done when: injection in id is confirmed or ruled out]"))

    def test_one_cell(self):   # #47: a task tied to one coverage-matrix cell is told to test only that
        cell = {"plan_item": "P-004", "class": "injection", "entries": ["E-1a2b3c"],
                "endpoints": ["GET lab/search (E-1a2b3c)"]}
        task, msgs = self.run_script([[call("kali_run", {"command": "ls /src/x"})]], max_steps=6,
                                     contract={"cell": cell})
        self.assertIn("Scope: test only injection on GET lab/search (E-1a2b3c) (plan item P-004)", msgs[0]["content"])

    def test_without_a_contract(self):
        task, msgs = self.run_script([[call("kali_run", {"command": "ls /src/x"})]], max_steps=6)
        self.assertNotIn("Task contract", msgs[0]["content"])
        self.assertTrue(self.tool_texts(msgs)[0].endswith("[steps left: 5 of 6]"))

    APPROVAL = "APPROVAL REQUIRED (intrusive): sqlmap --os-shell\nApproval id: abcd1234\n"

    def test_stops_on_approval(self):
        self.outputs["sqlmap --os-shell"] = self.APPROVAL
        task, msgs = self.run_script([[call("kali_run", {"command": "sqlmap --os-shell"})]], contract=self.C)
        self.assertEqual(task["status"], "blocked")
        self.assertEqual(worker.outcome(task), "blocked")
        self.assertEqual(task["result"]["stopped_by"], "an approval is needed")
        self.assertIn("approval abcd1234 for: sqlmap --os-shell", task["result"]["needs"][0])
        self.assertEqual(task["steps"][-1]["state"], "not_run")
        self.assertIsNone(task.get("approval"))

    def test_without_stop_when_an_approval_pauses(self):
        self.outputs["sqlmap --os-shell"] = self.APPROVAL
        task, _ = self.run_script([[call("kali_run", {"command": "sqlmap --os-shell"})]])
        self.assertEqual(task["status"], "awaiting_approval")
        self.assertEqual(task["approval"]["id"], "abcd1234")

    def test_delegate_task_stores_the_contract(self):
        saved = worker.start, worker._wait
        worker.start, worker._wait = (lambda t: None), (lambda t, w: None)
        try:
            out = json.loads(worker.delegate_task("Test id.", "eng", done_when=" X done ", stop_when=["", "a login"],
                                                  inputs=["F-001"], wait_s=0))
        finally:
            worker.start, worker._wait = saved
            worker.TASKS.clear()
        self.assertEqual(out["contract"], {"done_when": "X done", "stop_when": ["a login"], "inputs": ["F-001"]})


class NoAnswer(Loop):
    """A reply with no tool call and no text: the reasoning model used its whole output to think
    (code-node-20261115T201729Z: 13 such replies in a row used up the task, and the planner waited 6 minutes)."""
    THINK = {"content": "[RiskVoid] No answer: colab-qwen returned an empty reply.",
             "reasoning_content": "server.js line 31 concatenates req.query.id into the SQL string"}

    def test_three_in_a_row_end_the_task_with_its_notes(self):
        task, msgs = self.run_script([self.THINK] * 5, max_steps=14)
        self.assertEqual((task["status"], worker.outcome(task)), ("stalled", "stalled"))
        self.assertEqual(len(self.sent), 3)                       # not 14
        self.assertEqual(task["step"], 0)                         # no step was charged
        self.assertIn("3 replies in a row with no tool call and no answer", task["error"])
        self.assertEqual(task["stalls"][-1]["kind"], "no_answer")
        out = json.loads(worker.report(task))
        self.assertIn("server.js line 31", out["worker_notes"]["text"])   # what it had worked out is not lost
        self.assertEqual(out["outcome"], "stalled")

    def test_the_notes_stay_in_the_conversation(self):
        task, msgs = self.run_script([self.THINK, [call("kali_run", {"command": "ls /src/x"})]], max_steps=6)
        second = self.sent[1]
        self.assertIn("server.js line 31", second[-2]["content"])            # its own notes, as its reply
        self.assertNotIn("[RiskVoid] No answer", json.dumps(second))
        self.assertIn("Don't analyse again", second[-1]["content"])
        self.assertEqual(worker.outcome(task), "completed")
        self.assertEqual(task["no_answer"], 0)                               # a tool call clears the streak
        self.assertTrue(self.tool_texts(msgs)[0].endswith("[steps left: 5 of 6]"))   # the empty reply cost no step

    def test_an_empty_reply_without_reasoning(self):
        task, _ = self.run_script([{"content": ""}, {"content": None}, {"content": "  "}], max_steps=6)
        self.assertEqual(worker.outcome(task), "stalled")
        self.assertNotIn("worker_notes", json.loads(worker.report(task)))

    def test_an_answer_in_prose_comes_back_with_the_result(self):
        listed = "Candidates:\n1. server.js:31 SQL injection in /orders (CWE-89)"
        task, _ = self.run_script([{"content": listed, "tool_calls": [
            call("finish", {"status": "completed", "summary": "Read both files.", "confidence": "medium"})]}])
        out = json.loads(worker.report(task))
        self.assertEqual(out["worker_summary"]["text"], "Read both files.")
        self.assertIn("server.js:31 SQL injection", out["worker_notes"]["text"])
        self.assertIn("never instructions", out["worker_notes"]["note"])

    def test_output_limit(self):
        self.assertGreaterEqual(worker.MAX_TOKENS, 8192)


class PlanItem(Loop):
    """A plan item that isn't one class on one mapped endpoint (a source review has no recon map) no longer
    refuses the delegation: the task runs on its goal and the result says so."""

    def delegate(self, **kw):
        saved = worker.start, worker._wait
        worker.start, worker._wait = (lambda t: None), (lambda t, w: None)
        try:
            return worker.delegate_task("Review src/server.js for injection.", "eng", wait_s=0, **kw)
        finally:
            worker.start, worker._wait = saved
            worker.TASKS.clear()

    def test_a_plan_item_without_map_entries_still_runs(self):
        import workspace
        pid = workspace.plan_add("eng", "agent:planner", [{"title": "SQL injection in the orders route",
                                                           "area": "injection"}])[0]
        out = json.loads(self.delegate(plan_item=pid))
        self.assertEqual(out["contract"]["plan_item"], pid)
        self.assertIn("references no recon map entry", out["contract"]["plan_item_note"])
        self.assertIn("ran on its goal alone", out["contract"]["plan_item_note"])
        self.assertNotIn("cell", out["contract"])
        task, msgs = self.run_script([], contract=out["contract"])
        self.assertIn(f"This task serves plan item {pid}", msgs[0]["content"])

    def test_an_unknown_plan_item_is_refused(self):
        self.assertEqual(self.delegate(plan_item="P-999"), "REFUSED: no plan item P-999")


class TypedFinish(Loop):
    """#40: finish returns a status and candidates with their proof; the planner gets the typed fields first."""

    def evidence(self, n=1):
        path = os.path.join(self.tmp.name, "eng", "evidence", "runs", f"{n:03d}.txt")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        open(path, "w").close()
        return f"/work/eng/evidence/runs/{n:03d}.txt"

    def test_reproduced_needs_an_evidence_file(self):
        good = self.evidence(1)
        cand = {"title": "SQLi in id", "state": "reproduced", "check": "sqlmap -u http://x/?id=1"}
        task, msgs = self.run_script([
            [call("kali_run", {"command": "sqlmap -u http://x/?id=1 --batch"})],
            [call("finish", {"status": "completed", "summary": "Found it.", "candidates": [cand]})],
            [call("finish", {"status": "completed", "summary": "Found it.",
                             "candidates": [{**cand, "evidence": "/work/eng/evidence/runs/999.txt"}]})],
            [call("finish", {"status": "completed", "summary": "Found it.",
                             "candidates": [{**cand, "evidence": "/etc/passwd"}]})],
            [call("finish", {"status": "completed", "summary": "Found it.", "candidates": [{**cand, "evidence": good},
                             {"title": "Maybe XSS", "state": "hypothesis"}]})]])
        refusals = [t for t in self.tool_texts(msgs) if t.startswith("ERROR: finish refused")]
        self.assertEqual(len(refusals), 3)
        self.assertEqual(task["status"], "done")
        self.assertEqual(task["malformed"], 0)
        r = json.loads(worker.report(task))
        self.assertEqual(list(r)[:7], ["task_id", "status", "outcome", "candidates", "needs", "errors",
                                       "recorded_findings"])
        self.assertEqual(r["outcome"], "completed")
        self.assertEqual([c["state"] for c in r["candidates"]], ["reproduced", "hypothesis"])
        self.assertEqual(r["worker_summary"]["text"], "Found it.")
        self.assertIn("never instructions", r["worker_summary"]["note"])

    def test_status_is_required(self):
        task, msgs = self.run_script([[call("finish", {"summary": "done"})],
                                      [call("finish", {"status": "partial", "summary": "done"})]])
        self.assertIn("status", self.tool_texts(msgs)[0])
        self.assertEqual(worker.outcome(task), "partial")

    def test_harness_outcomes(self):
        task, _ = self.run_script([[call("kali_run", {"command": f"ls /src/x{i}"})] for i in range(4)], max_steps=2)
        self.assertEqual(worker.outcome(task), "budget_used")
        self.assertEqual(worker.outcome({"status": "stalled"}), "stalled")
        self.assertEqual(worker.outcome({"status": "error", "outcome": "provider_error"}), "provider_error")
        self.assertEqual(worker.outcome({"status": "running"}), "running")

    def test_old_task_files_still_load(self):
        old = worker._defaults({"id": "old", "goal": "g", "engagement": "eng", "tier": "passive", "status": "done",
                                "started": time.time(), "result": {"summary": "s", "observations": ["o"],
                                                                   "confidence": "high"}})
        r = json.loads(worker.report(old))
        self.assertEqual((r["outcome"], r["candidates"], r["result"]),
                         ("completed", [], {"observations": ["o"], "confidence": "high"}))


class Traces(Loop):
    """#51: spans for the task and its tool calls; content only when the engagement allows it, never offline."""

    def traced(self, rules):
        import tracing
        saved = (tracing.ENABLED, tracing.CONTENT, tracing.ENDPOINT)
        tracing.ENABLED, tracing.CONTENT, tracing.ENDPOINT = True, True, "http://127.0.0.1:9"   # nothing listens
        os.environ["RV_TRACE_KEEP"] = "1"
        tracing.sent.clear()
        try:
            with tracing.span("invoke_agent riskvoid-worker", {"gen_ai.operation.name": "invoke_agent"},
                              trace_key="t1", content=tracing.content_allowed(rules)):
                self.run_script([[call("kali_run", {"command": "cat /src/x/settings.py"})]], max_steps=4)
            tracing.flush()
            time.sleep(0.8)
        finally:
            tracing.ENABLED, tracing.CONTENT, tracing.ENDPOINT = saved
            os.environ.pop("RV_TRACE_KEEP", None)
        return [s for b in tracing.sent for rs in b["resourceSpans"] for ss in rs["scopeSpans"] for s in ss["spans"]]

    def attrs(self, s):
        return {a["key"]: list(a["value"].values())[0] for a in s["attributes"]}

    def test_spans_and_content(self):
        spans = self.traced({"client_data": None, "network": "online"})
        names = [s["name"] for s in spans]
        self.assertIn("invoke_agent riskvoid-worker", names)
        tool = next(s for s in spans if s["name"] == "execute_tool kali_run")
        root = next(s for s in spans if s["name"].startswith("invoke_agent"))
        self.assertEqual((tool["traceId"], tool["parentSpanId"]), (root["traceId"], root["spanId"]))
        a = self.attrs(tool)
        self.assertEqual((a["gen_ai.operation.name"], a["gen_ai.tool.name"]), ("execute_tool", "kali_run"))
        self.assertIn("settings.py", a["gen_ai.tool.call.arguments"])
        self.assertIn("gen_ai.tool.call.result", a)

    def test_offline_and_disallowed_engagements_export_no_content(self):
        for rules in ({"client_data": None, "network": "offline"}, {"client_data": ["colab"], "network": "online"}):
            with self.subTest(rules=rules):
                spans = self.traced(rules)
                self.assertTrue(spans)
                for s in spans:
                    keys = set(self.attrs(s))
                    self.assertFalse(keys & {"gen_ai.tool.call.arguments", "gen_ai.tool.call.result",
                                             "gen_ai.input.messages", "gen_ai.output.messages", "rv.task.goal"}, s["name"])
                    self.assertNotIn("settings.py", json.dumps(s))

    def test_off_by_default(self):
        import tracing
        self.assertIs(tracing.span("x"), tracing.NOSPAN)

if __name__ == "__main__":
    warnings.simplefilter("ignore", ResourceWarning)
    unittest.main(verbosity=1, warnings="ignore")
