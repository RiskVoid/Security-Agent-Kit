"""The worker's loop with a scripted model and fake tools: no stack, no GPU, no mcp package (epic #52, phase 2).

Covers what the loop decides on its own: malformed tool calls, what a tool result shows the model (head and tail,
digests), stall and repeat detection, the advisor, and how old results shrink. The real tools and the real model
path are covered by evals/agent_loop_test.sh.

The epic #77 phase-0 fixtures (issue #81) are here too, each recording the current behaviour as the baseline the
research-loop phases (A to E) are compared with: a long tool beside a short task, an exhausted provider, and a
refuted hypothesis.

Run: python3 evals/worker_loop_test.py
"""
import json, os, sys, tempfile, threading, time, types, unittest, warnings

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

    def run_script(self, turns, max_steps=20, id="t1", **task_extra):
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
        task = worker._defaults({"id": id, "goal": "Test the thing.", "engagement": "eng", "tier": "passive",
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


    def test_run_task_records_its_queue_wait(self):   # #79: queue_s - the wait before the task's first model call
        worker.chat = lambda messages, model=None, task=None: {
            "role": "assistant", "content": None,
            "tool_calls": [call("finish", {"status": "completed", "summary": "done", "confidence": "low"})]}
        task = worker._defaults({"id": "t-q", "goal": "g", "engagement": "eng", "tier": "passive",
                                 "info": worker.engagement_info("eng"), "max_steps": 3, "timeout_min": 5,
                                 "status": "running", "started": time.time() - 120})
        os.makedirs(worker.task_dir(task), exist_ok=True)
        worker.run_task(task)
        self.assertEqual(task["status"], "done")
        self.assertIn("queue_s", task)                      # measured once, at the first model call
        self.assertGreaterEqual(task["queue_s"], 0.0)
        first = task["queue_s"]
        worker.run_task(task)                               # a resumed task doesn't re-measure the queue
        self.assertEqual(task["queue_s"], first)


class MalformedCalls(Loop):
    def test_broken_json_is_not_run(self):
        """#33: broken arguments go back to the model as an error; the tool doesn't run."""
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

    def test_the_result_carries_the_citable_evidence_not_the_transcripts(self):
        """A planner cited the task's step files as coverage evidence (the result used to name their folder
        'evidence_dir'): the result now names the verified-evidence files each command produced (run_evidence)
        and calls the step files what they are."""
        task, _ = self.run_script([[call("kali_run", {"command": "semgrep /src/x"})],
                                   [call("finish", {"status": "completed", "summary": "done."})]])
        out = json.loads(worker.report(task))
        self.assertEqual(out["run_evidence"], ["/work/eng/evidence/runs/001.txt"])
        self.assertTrue(out["transcripts_dir"].endswith("evidence/tasks/t1"))
        self.assertNotIn("evidence_dir", out)

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

    def test_evidence_path_with_a_note_after_it_counts(self):
        # as a model writes it: the path, then what it shows (seen on a benchmark run, where finish was refused)
        good = self.evidence(2)
        task = {"engagement": "eng"}
        for text in (good, "evidence/runs/002.txt", "evidence/runs/002.txt:14",
                     "evidence/runs/002.txt — check_id python.flask.x at app.py:6, CWE-489",
                     "see /work/eng/evidence/runs/002.txt; /src/x/app.py:6 (B105)",
                     "bandit.json / /work/eng/evidence/runs/002.txt."):
            self.assertTrue(worker._evidence_file(task, text), text)
        for text in ("", None, "bandit.json / evidence run 002.txt; /src/x/app.py:6", "evidence/runs/999.txt — x",
                     "/etc/passwd", "evidence/../../outside.txt", "../other-eng/evidence/runs/002.txt"):
            self.assertIsNone(worker._evidence_file(task, text), text)

    def test_a_finish_refused_at_the_last_step_keeps_its_summary(self):
        # the bandit task of a benchmark run: three steps lost, then the forced finish was refused for its evidence
        # field, and the planner got "Stopped without calling finish." instead of what the task found
        good = self.evidence(3)
        bad = {"title": "Hardcoded SECRET_KEY", "state": "reproduced", "evidence": "bandit.json / app.py:6 (B105)"}
        proven = {"title": "Debug mode", "state": "reproduced", "evidence": good}
        task, msgs = self.run_script([
            [call("kali_run", {"command": "bandit -r /src/x -f json -o bandit.json"})],
            [call("kali_run", {"command": "cat bandit.json"})],
            [call("finish", {"status": "completed", "summary": "Bandit found 7 issues in app.py.",
                             "confidence": "high", "candidates": [bad, proven, {"title": "Maybe", "state": "hypothesis"}]})],
        ], max_steps=2)
        self.assertEqual(task["status"], "done")
        r = task["result"]
        self.assertEqual(worker.outcome(task), "budget_used")       # still not a clean finish
        self.assertIn("Bandit found 7 issues in app.py.", r["summary"])
        self.assertNotIn("without calling finish", r["summary"])
        self.assertEqual([c["state"] for c in r["candidates"]], ["hypothesis", "reproduced", "hypothesis"])
        self.assertEqual(r["confidence"], "low")
        self.assertNotIn("refused_finish", task)
        # with no finish at all, the old result stands
        task, _ = self.run_script([[call("kali_run", {"command": f"ls /src/x{i}"})] for i in range(5)], max_steps=2,
                                  id="t2")
        self.assertEqual(task["result"]["summary"], "Stopped without calling finish.")
        # a refused finish followed by one that passes leaves nothing behind
        task, _ = self.run_script([
            [call("finish", {"status": "completed", "summary": "First.", "candidates": [bad]})],
            [call("finish", {"status": "completed", "summary": "Second.", "candidates": [proven]})]], id="t3")
        self.assertEqual(task["result"]["summary"], "Second.")
        self.assertNotIn("refused_finish", task)

    def test_read_file_takes_a_path_relative_to_the_engagement_folder(self):
        # kali_run works in the engagement folder, so a command's "-o bandit.json" lands there; the worker then asked
        # read_file for "bandit.json" three times and was refused each time
        with open(os.path.join(self.tmp.name, "eng", "bandit.json"), "w") as f:
            f.write("line one\nline two\n")
        task = {"engagement": "eng", "info": {"scope": {"paths": ["/src/x"]}}}
        for path in ("bandit.json", "./bandit.json", "/work/eng/bandit.json",
                     os.path.join(self.tmp.name, "eng", "bandit.json")):
            self.assertEqual(worker.read_file(task, path), "1: line one\n2: line two", path)
        self.assertIn("no such file", worker.read_file(task, "missing.json"))
        self.assertIn("/work/eng/", worker.read_file(task, "missing.json"))
        for path in ("../other/secret.txt", "/etc/passwd", "/work/other/findings.db"):
            self.assertIn("only files under", worker.read_file(task, path), path)

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


class TokenUse(Loop):
    """#78: each worker model call adds its usage to the task, so task.json holds the worker's total. The real
    chat() runs here, against a scripted model behind a fake gateway."""

    REPLIES = [({"prompt_tokens": 1200, "completion_tokens": 80, "prompt_tokens_details": {"cached_tokens": 1000}},
                [call("kali_run", {"command": "ls /src/x"}, cid="u1")]),
               ({"prompt_tokens": 1500, "completion_tokens": 40},
                [call("finish", {"status": "completed", "summary": "Listed it."}, cid="u2")])]

    def setUp(self):
        super().setUp()
        self.urlopen = worker.urllib.request.urlopen
        script = list(self.REPLIES)

        class R:
            def __init__(s, body):
                s.body = body

            def read(s):
                return json.dumps(s.body).encode()

        def fake(req, timeout=None):
            usage, calls = script.pop(0)
            return R({"model": "colab-qwen", "usage": usage,
                      "choices": [{"finish_reason": "tool_calls",
                                   "message": {"role": "assistant", "content": None, "tool_calls": calls}}]})
        worker.urllib.request.urlopen = fake

    def tearDown(self):
        worker.urllib.request.urlopen = self.urlopen
        super().tearDown()

    def test_the_task_total_is_the_sum_of_its_calls(self):
        chat = self.saved["chat"]
        task = worker._defaults({"id": "t1", "goal": "List it.", "engagement": "eng", "tier": "passive",
                                 "info": worker.engagement_info("eng"), "max_steps": 6, "timeout_min": 5,
                                 "status": "running", "started": time.time(), "tokens": dict(worker.NO_TOKENS)})
        worker.chat = chat
        os.makedirs(worker.task_dir(task), exist_ok=True)
        with open(os.devnull, "w") as log:
            self.assertEqual(worker._loop(task, log), "done")
        want = {"prompt_tokens": 2700, "completion_tokens": 120, "cached_tokens": 1000, "calls": 2}
        self.assertEqual(task["tokens"], want)
        worker.save(task)
        saved = json.load(open(os.path.join(worker.task_dir(task), "task.json")))
        self.assertEqual(saved["tokens"], want)                     # in task.json, where the benchmark reads it

    def test_a_task_without_a_total_gets_one(self):   # a task saved before #78 and resumed
        t = {"id": "old"}
        worker.add_usage(t, {"prompt_tokens": 10, "completion_tokens": 2})
        worker.add_usage(t, None)                                   # a reply with no usage: a call, no tokens
        self.assertEqual(t["tokens"], {"prompt_tokens": 10, "completion_tokens": 2, "cached_tokens": 0, "calls": 2})


class FetchInParts(Loop):
    """#114: fetch_url takes start, passes it on, and the hint at the end of a part names fetch_url."""

    PAGE = "".join(f"line {i:06d}\n" for i in range(14000))       # 168,000 characters

    def setUp(self):
        super().setUp()
        self.fetched = []
        self.mcp = worker._mcp
        page = self.PAGE

        async def fake_mcp(url, tool, args, timeout_s=60):   # web-mcp's fetch, as harness/web.py cuts a page
            self.fetched.append((tool, dict(args)))
            start, n = args.get("start", 0), args["max_chars"]
            part = page[start:start + n]
            more = len(page) - (start + len(part))
            return part + (f"\n\n[… {more} more characters: call fetch again with start={start + len(part)}]"
                           if more > 0 else "")
        worker._mcp = fake_mcp
        worker.IMPL = {**worker.IMPL, "fetch_url": worker.fetch_url}

    def tearDown(self):
        worker._mcp = self.mcp
        super().tearDown()

    def test_a_long_page_is_continued_with_start(self):
        url = "https://example.com/vendor.js"
        task, msgs = self.run_script([[call("fetch_url", {"url": url})],
                                      [call("fetch_url", {"url": url, "start": 100000})]])
        self.assertEqual([a.get("start") for _, a in self.fetched], [0, 100000])
        self.assertEqual({a["max_chars"] for _, a in self.fetched}, {worker.FETCH_CHARS})
        first, second = self.tool_texts(msgs)[:2]
        self.assertIn("68000 more characters: call fetch_url again with the same url and start=100000]", first)
        self.assertNotIn("call fetch again", first)
        self.assertIn("line 008334", second)                       # the second part, not the first again
        self.assertNotIn("more characters", second)                 # the page ends there
        self.assertNotIn("malformed", json.dumps(msgs))

    def test_the_tool_says_how_a_long_page_is_continued(self):
        spec = worker.SCHEMA["fetch_url"]
        self.assertEqual(spec["properties"]["start"]["type"], "integer")
        desc = next(t["function"]["description"] for t in worker.TOOLS if t["function"]["name"] == "fetch_url")
        self.assertIn("call fetch_url again with the same url and that start", desc)
        self.assertIn("read_file", desc)                            # the middle of a part is in its step file


class LongToolBesideAShortTask(Loop):
    """#81 (epic #77, phase 0), updated by #106: one task's tool runs long while a second, short task is
    dispatched. Before #106 the short task's first model call waited for the first task's whole loop, because
    run_task held MODEL_LOCK across tool calls; since #106 the semaphore is held only around each model call,
    so the short task gets the model while the long tool runs. #107's waits (the engagement's own task limit,
    a writer's identity lock, a busy target) are judged against this same fixture."""

    def test_the_short_task_gets_the_model_while_the_long_tool_runs(self):
        sleep_s = 0.4
        tool_started, tool_done = threading.Event(), []
        chats = []                    # (task id, time) of every model call, in order

        def slow_tool(task, command, timeout_s=600, approval_id=""):
            tool_started.set()
            time.sleep(sleep_s)
            tool_done.append(time.time())
            self.ran.append(command)
            return ("exit=0 tier=passive\nthe long scan finished\n"
                    "[output saved as verified evidence: /work/eng/evidence/runs/001.txt]")
        worker.IMPL = {**worker.IMPL, "kali_run": slow_tool}

        def chat(messages, model=None, task=None):
            chats.append((task["id"], time.time()))
            finish = call("finish", {"status": "completed", "summary": f"{task['id']} done", "confidence": "low"})
            if task["id"] == "long" and len([1 for tid, _ in chats if tid == "long"]) == 1:
                return {"role": "assistant", "content": None,
                        "tool_calls": [call("kali_run", {"command": "slow-scan --hours 2"}, cid="L1")]}
            return {"role": "assistant", "content": None, "tool_calls": [finish]}
        worker.chat = chat

        def make(tid):
            return worker._defaults({"id": tid, "goal": f"Goal {tid}.", "engagement": "eng", "tier": "passive",
                                     "info": worker.engagement_info("eng"), "max_steps": 6, "timeout_min": 5,
                                     "status": "running", "started": time.time()})
        long_t, short_t = make("long"), make("short")
        for t in (long_t, short_t):
            os.makedirs(worker.task_dir(t), exist_ok=True)
        first = threading.Thread(target=worker.run_task, args=(long_t,))
        first.start()
        self.assertTrue(tool_started.wait(5), "the long task never reached its tool call")
        dispatch_at = time.time()
        second = threading.Thread(target=worker.run_task, args=(short_t,))
        second.start()
        first.join(30)
        second.join(30)
        self.assertFalse(first.is_alive() or second.is_alive())

        self.assertEqual((long_t["status"], short_t["status"]), ("done", "done"))
        long_ts = [t for tid, t in chats if tid == "long"]
        short_ts = [t for tid, t in chats if tid == "short"]
        self.assertEqual((len(long_ts), len(short_ts)), (2, 1))
        waited = short_ts[0] - dispatch_at
        self.assertLess(waited, sleep_s)                 # #106: no waiting for the first task's whole loop
        self.assertLess(short_ts[0], tool_done[0])       # its model call happens while the long tool runs
        self.assertLess(long_ts[0], tool_done[0])         # (the first task did get the model before its tool)

    def tearDown(self):
        worker.TASKS.clear()   # run_task registers tasks; nothing after this class needs them
        super().tearDown()


class BusyProvider(Loop):
    """A rate limit or an overloaded provider is waited out instead of ending the task. Seen on a benchmark run with
    OpenRouter's free models (20 requests a minute for planner and worker together): one 429 ended the worker task
    as "the model gateway refused the call"."""

    def drive(self, answers, cancel_after=None):
        """Run a task whose model endpoint gives these answers in turn: an HTTP status, or a list of tool calls."""
        import io
        import urllib.error
        answers, self.asked, self.slept = list(answers), 0, []

        def fake(req, timeout=None):
            self.asked += 1
            a = answers.pop(0) if len(answers) > 1 else answers[0]
            if isinstance(a, int):
                body = json.dumps({"error": {"message": (
                    'colab-qwen is rate-limited by its provider. {"error":{"message":"Rate limit exceeded: '
                    'free-models-per-min. ","code":429,"metadata":{"headers":{"X-RateLimit-Limit":"20",'
                    '"X-RateLimit-Reset":"%d"}}}}' % ((time.time() + 20) * 1000))}}).encode()
                raise urllib.error.HTTPError(req.full_url, a, "busy", {}, io.BytesIO(body))

            class R:
                def read(s):
                    return json.dumps({"model": "colab-qwen", "usage": {"prompt_tokens": 100, "completion_tokens": 10},
                                       "choices": [{"finish_reason": "tool_calls", "message": {
                                           "role": "assistant", "content": None, "tool_calls": a}}]}).encode()
            return R()

        task = worker._defaults({"id": "busy", "goal": "Probe it.", "engagement": "eng", "tier": "passive",
                                  "info": worker.engagement_info("eng"), "max_steps": 6, "timeout_min": 5,
                                  "status": "running", "started": time.time(), "tokens": dict(worker.NO_TOKENS)})

        def sleep(s):
            self.slept.append(s)
            if cancel_after is not None and len(self.slept) >= cancel_after:
                task["_cancel"] = True
        urlopen, real_sleep = worker.urllib.request.urlopen, worker.time.sleep
        worker.urllib.request.urlopen, worker.time.sleep = fake, sleep
        try:
            os.makedirs(worker.task_dir(task), exist_ok=True)
            worker.run_task(task)
        finally:
            worker.urllib.request.urlopen, worker.time.sleep = urlopen, real_sleep
        return task

    def test_a_rate_limit_is_waited_out_and_the_task_goes_on(self):
        task = self.drive([429, 503, [call("kali_run", {"command": "curl -s http://x/a"}, cid="b1")],
                           [call("finish", {"status": "completed", "summary": "done", "confidence": "low"}, cid="b2")]])
        self.assertEqual(task["status"], "done")
        self.assertEqual(self.ran, ["curl -s http://x/a"])
        self.assertEqual(self.asked, 4)                               # two busy answers, then the two real turns
        self.assertEqual([w["code"] for w in task["model_waits"]], [429, 503])
        self.assertTrue(18 <= task["model_waits"][0]["seconds"] <= 22)   # until the reset time the provider gave
        self.assertEqual(sum(self.slept), sum(w["seconds"] for w in task["model_waits"]))
        self.assertEqual(task["tokens"]["calls"], 2)                  # a refused call is not a model call

    def test_a_provider_that_stays_busy_ends_the_task_as_a_provider_error(self):
        task = self.drive([429])
        self.assertEqual(self.asked, len(worker.BUSY_WAITS) + 1)
        self.assertEqual(task["status"], "error")
        self.assertEqual(worker.outcome(task), "provider_error")     # not model_refused: nothing was refused
        self.assertIn("rate-limited or overloaded", task["error"])
        self.assertIn("429", task["error"])
        self.assertNotIn("refused the call", task["error"])

    def test_a_cancelled_task_stops_waiting(self):
        task = self.drive([429], cancel_after=2)
        self.assertEqual(task["status"], "cancelled")
        self.assertEqual(self.asked, 1)

    def test_how_long_to_wait(self):
        w = worker.busy_wait
        self.assertEqual(w({"Retry-After": "7"}, "", 30, now=1000), 7)
        self.assertEqual(w({}, 'x "X-RateLimit-Reset":"1795358340000" y', 5, now=1795358300), 41)   # milliseconds
        self.assertEqual(w({}, "X-RateLimit-Reset: 1795358340", 5, now=1795358300), 41)             # seconds
        self.assertEqual(w({}, 'X-RateLimit-Reset":"1795358340000"', 5, now=1795358000), worker.BUSY_MAX_WAIT)
        self.assertEqual(w({}, 'X-RateLimit-Reset":"1795358340000"', 15, now=1795359000), 15)       # already past
        self.assertEqual(w(None, "no hint", 30), 30)
        self.assertEqual(w({"Retry-After": "soon"}, "", 12), 12)


class ExhaustedProvider(Loop):
    """#81 (epic #77, phase 0): the model endpoint returns a quota error mid-task. Baseline: the task ends typed
    as model_refused (a quota error and a policy refusal are the same type today), the finished call and its result
    are kept in the on-disk checkpoint, and the task cannot be resumed: only interrupted ones can. A resumable,
    non-repeating path is what the packet at resume (#84) and the capacity work (#106) build on."""

    def test_quota_error_ends_the_task_typed_with_its_checkpoint_kept(self):
        import io
        import urllib.error
        replies = [call("kali_run", {"command": "curl -s http://x/probe"}, cid="q1")]

        class R:
            def read(s):
                return json.dumps({"model": "colab-qwen", "usage": {"prompt_tokens": 100, "completion_tokens": 10},
                                   "choices": [{"finish_reason": "tool_calls",
                                                "message": {"role": "assistant", "content": None,
                                                            "tool_calls": replies}}]}).encode()

        def fake(req, timeout=None):
            if getattr(fake, "spent", False):
                body = json.dumps({"error": {"message": "insufficient quota: the billing hard limit is reached"}}).encode()
                raise urllib.error.HTTPError(req.full_url, 402, "Payment Required", {}, io.BytesIO(body))
            fake.spent = True
            return R()
        fake.spent = False
        self.urlopen = worker.urllib.request.urlopen
        worker.urllib.request.urlopen = fake
        try:
            task = worker._defaults({"id": "quota", "goal": "Probe it.", "engagement": "eng", "tier": "passive",
                                      "info": worker.engagement_info("eng"), "max_steps": 6, "timeout_min": 5,
                                      "status": "running", "started": time.time(),
                                      "tokens": dict(worker.NO_TOKENS)})
            os.makedirs(worker.task_dir(task), exist_ok=True)
            worker.run_task(task)
        finally:
            worker.urllib.request.urlopen = self.urlopen

        self.assertEqual(task["status"], "error")
        self.assertEqual(worker.outcome(task), "model_refused")     # the typed status a failure record reads
        self.assertIn("the model gateway refused the call", task["error"])
        self.assertIn("quota", task["error"])
        self.assertNotIn("402", task["error"])   # baseline: only the gateway's message is kept, not its code
        self.assertEqual(self.ran, ["curl -s http://x/probe"])       # the finished call ran exactly once
        saved = json.load(open(os.path.join(worker.task_dir(task), "task.json")))
        self.assertEqual(saved["status"], "error")                   # the checkpoint keeps the state
        msgs = worker.load_messages(task)
        self.assertTrue(any(m.get("role") == "tool" and "ran curl -s http://x/probe" in str(m.get("content"))
                            for m in msgs))                          # ... and the conversation, finished call included
        with self.assertRaises(ValueError) as refused:               # today it is not resumable: the gap #84 closes
            worker.resume(task["id"])
        self.assertIn("only interrupted tasks can be resumed", str(refused.exception))

    def tearDown(self):
        worker.TASKS.clear()   # run_task registers tasks; nothing after this class needs them
        super().tearDown()


class RefutedHypothesis(Loop):
    """#81 (epic #77, phase 0): an attractive hypothesis whose clean control behaves the same as the probe.
    Baseline: the finish validator never checks the candidate state's enum, so a 'refuted' state passes into the
    typed result untouched — but the schema the model reads offers only hypothesis and reproduced, so a
    schema-faithful model cannot even say it — and nothing tells the next task for the same cell. The experiment
    records (#90) and the packet (#83, #84) are the issues that change the last two parts."""
    C = {"cell": {"plan_item": "P-004", "class": "injection", "entries": ["E-1a2b3c"],
                  "endpoints": ["GET lab/search (E-1a2b3c)"]}}

    def test_the_refutation_reaches_the_typed_result_but_not_the_next_task(self):
        self.outputs["curl -s 'http://x/search?q=1'"] = "exit=0 tier=active\n500 Internal Server Error"
        self.outputs["curl -s 'http://x/search?q=clean'"] = "exit=0 tier=active\n500 Internal Server Error"
        cand = {"title": "SQL injection in /search", "state": "refuted",
                "check": "probe q=1' and the clean control q=clean both got the same 500: refuted on this route"}
        first, msgs = self.run_script([
            [call("kali_run", {"command": "curl -s 'http://x/search?q=1'"}),
             call("kali_run", {"command": "curl -s 'http://x/search?q=clean'"})],
            [call("finish", {"status": "partial",
                             "summary": "The control behaves the same as the probe: not confirmed on this route.",
                             "candidates": [cand], "confidence": "low"})],
        ], max_steps=6, id="refuted-a", contract=self.C)
        self.assertEqual(worker.outcome(first), "partial")
        r = json.loads(worker.report(first))
        self.assertEqual(r["candidates"][0]["state"], "refuted")          # recorded, with its conditions
        self.assertIn("both got the same 500", r["candidates"][0]["check"])

        # the schema the model reads never offered that state (the enum is the baseline; the phases widen it)
        enum = worker.SCHEMA["finish"]["properties"]["candidates"]["items"]["properties"]["state"]["enum"]
        self.assertEqual(enum, ["hypothesis", "reproduced"])

        # the next task for the same cell: the cell contract is there, the refutation is not (baseline)
        second, msgs2 = self.run_script([[call("kali_run", {"command": "curl -s 'http://x/search?q=2'"})]],
                                        max_steps=4, id="refuted-b", contract=self.C)
        system2 = msgs2[0]["content"]
        self.assertIn("test only injection on GET lab/search (E-1a2b3c)", system2)
        self.assertNotIn("refuted", system2)
        self.assertNotIn("500 Internal Server Error", system2)


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
class Packet(Loop):
    """#84: a task bound to a plan item starts from what the records already say (the packet), a resume appends
    only a material change, compact keeps the latest packet; #85: read_record opens one record of each kind."""

    def setUp(self):
        super().setUp()
        import reconmap, workspace
        self.ws = workspace
        e = os.path.join(self.tmp.name, "eng")
        os.makedirs(os.path.join(e, "evidence/map"), exist_ok=True)
        json.dump({"observations": [
            {"method": "POST", "url": "http://lab/api/fetch", "source": "openapi", "status": 200, "auth": "unknown",
             "params": {"body": ["callback_url", "role"]}}]},
            open(os.path.join(e, "evidence/map/map-1.json"), "w"))
        self.eid = next(x["id"] for x in reconmap.build("eng")["entries"] if x["path"] == "/api/fetch")
        self.pid = workspace.plan_add("eng", "agent:planner", [
            {"title": "mass-assignment on POST /api/fetch", "area": "mass-assignment", "refs": [self.eid],
             "hypothesis": "the role field may be writable", "prerequisites": ["a session"]}])[0]
        self.fid = worker.db.record("eng", actor="agent:planner", title="mass-assignment on POST /api/fetch",
                             severity="high", asset="http://lab/api/fetch", description="role accepted",
                             status="candidate", evidence=["evidence/http/r1.txt"])["id"]
        self.tid = "20261123-100000-aaaa"
        os.makedirs(os.path.join(e, "evidence/tasks", self.tid), exist_ok=True)
        json.dump({"id": self.tid, "engagement": "eng", "goal": "Test mass-assignment on POST /api/fetch",
                   "status": "done", "started": 100,
                   "contract": {"cell": {"class": "mass-assignment", "entries": [self.eid],
                                         "plan_item": self.pid, "identity": "alice"}},
                   "result": {"status": "partial", "summary": "role rejected, org field not tried yet"},
                   "run_evidence": ["/work/eng/evidence/runs/step-01.txt"]},
                  open(os.path.join(e, "evidence/tasks", self.tid, "task.json"), "w"))

    def contract(self):
        return {"cell": {"class": "mass-assignment", "entries": [self.eid], "plan_item": self.pid,
                         "endpoints": [f"POST http://lab/api/fetch ({self.eid})"]}}

    def test_a_bound_task_starts_from_the_packet(self):
        task, _ = self.run_script([[call("finish", {"status": "completed", "summary": "done",
                                                   "confidence": "low"})]], id="p1", contract=self.contract())
        first = self.sent[0]                       # the messages the first model call saw
        packet = [m for m in first if m.get("role") == "user" and m["content"].startswith("# Packet:")]
        self.assertEqual(len(packet), 1)           # one packet message, after the goal
        text = packet[0]["content"]
        for part in (f"Plan item {self.pid}", f"{self.eid} POST lab/api/fetch",
                     f"task {self.tid} partial as alice", f"{self.fid} candidate",
                     "worker summary (not a verified fact)", "read_record"):
            self.assertIn(part, text)
        self.assertEqual(task["packet"]["ids"]["findings"], [self.fid])
        self.assertEqual(task["packet"]["ids"]["tried"], [self.tid])
        # a task with no plan item runs on its goal alone: no packet message
        self.run_script([[call("finish", {"status": "completed", "summary": "done", "confidence": "low"})]],
                        id="p2", contract={"cell": None})
        self.assertFalse([m for m in self.sent[-1] if m.get("role") == "user"
                          and m["content"].startswith("# Packet:")])

    def test_a_resume_appends_only_a_material_change(self):
        task, _ = self.run_script([[call("kali_run", {"command": "curl -s http://lab/api/fetch"})],
                                   [call("finish", {"status": "partial", "summary": "half",
                                                    "confidence": "low"})]], id="r1", contract=self.contract())
        messages = worker.load_messages(task)
        n = len(messages)
        worker._packet_refresh(task, messages)    # the task's own experiment arrived with its finish: a change
        self.assertEqual(len(messages), n + 1)
        self.assertIn("new experiment(s): X-001", messages[-1]["content"])
        worker._packet_refresh(task, messages)    # nothing further changed: nothing more is appended
        self.assertEqual(len(messages), n + 1)
        # the build moves, a second finding lands on the same route, the earlier task is re-run
        self.ws.set_value("eng", "agent:planner", "current_build", "def789abc012")
        fid2 = worker.db.record("eng", actor="agent:planner", title="org field accepted too", severity="high",
                         asset="http://lab/api/fetch", status="candidate")["id"]
        worker._packet_refresh(task, messages)
        self.assertEqual(len(messages), n + 2)     # exactly the change, as one more message
        text = messages[-1]["content"]
        self.assertTrue(text.startswith("[harness] Since this task started"))
        self.assertIn(f"new finding(s): {fid2}", text)
        self.assertIn("build now def789abc012", text)
        self.assertIn("# Packet:", text)            # the current packet rides with the change
        worker._packet_refresh(task, messages)     # and a second no-change refresh appends nothing
        self.assertEqual(len(messages), n + 2)

    def test_compact_keeps_the_latest_packet(self):
        old = {"role": "user", "content": "# Packet: test mass-assignment on POST /api/fetch\n"
                                          + f"{self.eid} POST http://lab/api/fetch\n"
                                          + f"task {self.tid} partial\n{self.fid} candidate"}
        new = {"role": "user", "content": "[harness] Since this task started, the records changed ().\n\n"
                                          "# Packet: test mass-assignment on POST /api/fetch\n"
                                          f"{self.eid} POST http://lab/api/fetch\n{self.fid} candidate"}
        saved_keep = worker.KEEP_RESULTS
        worker.KEEP_RESULTS = 0                        # shrink every old result, the packet rule is the point
        try:
            messages = [{"role": "system", "content": "s"},
                        {"role": "user", "content": "goal"}, old,
                        *[{"role": "tool", "content": "x" * 5000, "tool_call_id": f"c{i}"} for i in range(20)],
                        dict(new)]
            worker.compact(messages)
        finally:
            worker.KEEP_RESULTS = saved_keep
        self.assertIn("superseded by a newer one", old["content"])    # the old packet shrank to its ids
        self.assertIn(self.tid, old["content"])
        self.assertIn(self.eid, old["content"])
        self.assertTrue(new["content"].startswith("[harness] Since this task started"))   # the latest stays whole
        self.assertIn(f"task {self.tid}", old["content"])   # its id list, not the whole line
        self.assertTrue(messages[3]["content"].startswith("[shrunk]"))    # oldest results shrink first
        self.assertLess(len(messages[3]["content"]), 400)
        self.assertEqual(messages[-2]["content"], "x" * 5000)              # the budget break stops mid-list

    def test_read_record_opens_each_kind_and_refuses_cross_engagement(self):
        t = {"engagement": "eng", "id": self.tid}
        oid = self.ws.add_manual("eng", "agent:planner", "callback_url param takes a URL",
                                 "http://lab/api/fetch", "the target fetches it", "high")["id"]
        for rid, expect in ((oid, ("state: new", "location: http://lab/api/fetch")),
                            (self.fid, ("candidate", "reproduction: not recorded")),
                            (self.pid, ("hypothesis: the role field may be writable", f"refs: {self.eid}")),
                            (self.eid, ("POST lab/api/fetch", "params:")),
                            (self.tid, ("partial", "worker words, not a verified fact"))):
            body = worker.read_record(t, rid)
            for part in expect:
                self.assertIn(part, body, f"{rid}: {body[:200]}")
        self.assertIn("no record F-999 in engagement eng", worker.read_record(t, "F-999"))
        self.assertIn("ids never cross engagements", worker.read_record(t, "F-999"))
        # a record that lives in another engagement's folder is simply not here
        other = os.path.join(self.tmp.name, "eng2", "evidence", "tasks", "20261123-100000-bbbb")
        os.makedirs(other, exist_ok=True)
        json.dump({"id": "20261123-100000-bbbb", "engagement": "eng2", "goal": "x", "status": "done"},
                  open(os.path.join(other, "task.json"), "w"))
        self.assertIn("no record 20261123-100000-bbbb in engagement eng",
                      worker.read_record(t, "20261123-100000-bbbb"))
        # and a foreign task record planted under this engagement is refused by name
        moved = os.path.join(self.tmp.name, "eng", "evidence", "tasks", "20261123-100000-cccc")
        os.makedirs(moved, exist_ok=True)
        json.dump({"id": "20261123-100000-cccc", "engagement": "eng2", "goal": "x", "status": "done"},
                  open(os.path.join(moved, "task.json"), "w"))
        self.assertIn("REFUSED: 20261123-100000-cccc is a task of engagement eng2, not eng",
                      worker.read_record(t, "20261123-100000-cccc"))
        # a large record stays within the bound
        big = self.ws.add_manual("eng", "agent:planner", "huge", "http://lab", "x" * 9000, "info")["id"]
        self.assertLess(len(worker.read_record(t, big)), worker.RECORD_CHARS + 60)
class Ledger(Loop):
    """#115: the call ledger - a second task's identical scan carries the first one's entry, an unchanged read is
    answered with no new call, a changed file is read again, a stale entry is never reused. #120: a note
    survives compactions in the pinned block. #116: recall finds a task's agent notes."""

    def setUp(self):
        super().setUp()
        self.file = os.path.join(self.tmp.name, "eng", "evidence", "r1.txt")
        open(self.file, "w").write("line one\nline two\n")
        self.info = dict(worker.engagement_info("eng"))
        worker.engagement_info = lambda eng: dict(self.info)

    def test_a_second_tasks_identical_scan_carries_the_firsts_entry(self):
        cmd = lambda: [[call("kali_run", {"command": "curl -s http://lab/api/fetch"})]]  # noqa: E731
        first, _ = self.run_script(cmd(), id="l1")
        second, msgs2 = self.run_script(cmd(), id="l2")
        tool2 = [m for m in msgs2 if m.get("role") == "tool"][-1]
        self.assertIn("[ledger] an earlier call in this engagement already did this", tool2["content"])
        self.assertIn("run by l1", tool2["content"])
        self.assertEqual(second["ledger"], {"notices": 1})
        self.assertEqual(first.get("ledger"), None)          # the first call had nothing to point at
        # and a command that differs in a run stamp only is still the same work
        third, msgs3 = self.run_script(cmd(), id="l3")
        self.assertIn("[ledger]", [m for m in msgs3 if m.get("role") == "tool"][-1]["content"])

    def test_an_unchanged_read_is_answered_and_a_changed_file_is_not(self):
        read = lambda: [[call("read_file", {"path": "evidence/r1.txt"})]]  # noqa: E731
        _, _ = self.run_script(read(), id="r1")
        second, msgs2 = self.run_script(read(), id="r2")
        tool2 = [m for m in msgs2 if m.get("role") == "tool"][-1]
        self.assertIn("from the ledger, no new call", tool2["content"])
        self.assertIn("unchanged since", tool2["content"])
        self.assertEqual(second["ledger"]["reused"], 1)
        # fresh=true reads it anyway
        self.run_script([[call("read_file", {"path": "evidence/r1.txt", "fresh": True})]], id="r3")
        tool3 = [m for m in self.run_script(read(), id="r3b")[1] if m.get("role") == "tool"][-1]
        self.assertIn("line one", tool3["content"])
        # a changed file is read again, not answered from the ledger
        open(self.file, "w").write("line one changed\nline two\n")
        tool4 = [m for m in self.run_script(read(), id="r4")[1] if m.get("role") == "tool"][-1]
        self.assertIn("line one changed", tool4["content"])

    def test_a_stale_entry_is_shown_and_never_reused(self):
        read = lambda: [[call("read_file", {"path": "evidence/r1.txt"})]]  # noqa: E731
        self.info["policy_version"] = 5
        self.run_script(read(), id="s1")
        import workspace
        workspace.set_value("eng", "agent:planner", "current_policy_revision", "6")
        tool = [m for m in self.run_script(read(), id="s2")[1] if m.get("role") == "tool"][-1]
        self.assertIn("line one", tool["content"])           # the entry is stale: the read runs, no reuse

    def test_a_note_survives_compactions_in_the_pinned_block(self):
        task, _ = self.run_script([[call("note", {"fact": "the session token from login works on /api/fetch",
                                                  "evidence": "evidence/http/r1.txt"})],
                                   [call("note", {"fact": "a hunch without proof"})],
                                   [call("kali_run", {"command": "curl -s http://lab/api/fetch"})]], id="n1")
        messages = worker.load_messages(task)
        blocks = [m for m in messages if str(m.get("content") or "").startswith("# Established so far")]
        self.assertEqual(len(blocks), 1)
        self.assertIn("the session token from login works on /api/fetch", blocks[0]["content"])
        self.assertIn("[rests on evidence/http/r1.txt]", blocks[0]["content"])
        self.assertIn("a hunch without proof [unsupported]", blocks[0]["content"])
        before = blocks[0]["content"]
        worker.compact(messages, task.get("lines"), task=task)
        worker.compact(messages, task.get("lines"), task=task)   # twice: the block is rebuilt, never shrunk
        blocks2 = [m for m in messages if str(m.get("content") or "").startswith("# Established so far")]
        self.assertEqual(len(blocks2), 1)
        self.assertEqual(blocks2[0]["content"], before)
        self.assertIn("the session token", blocks2[0]["content"])
        # and the typed finish carries them back to the planner: the default finish still injects them
        self.assertIn("notes", task["result"])
        self.assertEqual(task["result"]["notes"][0]["fact"], "the session token from login works on /api/fetch")
        self.assertEqual(task["result"]["notes"][1]["evidence"], None)   # kept, and marked unsupported

    def test_recall_finds_a_tasks_notes_and_the_packet_carries_them(self):
        import workspace
        self.run_script([[call("note", {"fact": "parameter role reflects on the fetch endpoint"})],
                         [call("kali_run", {"command": "curl -s http://lab/api/fetch"})]], id="k1")
        out = workspace.recall("eng", "fetch endpoint")
        self.assertIn("k1", out)
        self.assertIn("agent notes", out)
        self.assertIn("parameter role reflects", out)
        # a query for another engagement's subject finds nothing here
        self.assertIn("nothing in eng matches", workspace.recall("eng", "parcels routing table"))
class Capacity(Loop):
    """#106: a queued task's timeout no longer shrinks while it waits; #107: a busy engagement is waited for,
    not handed to the model as an error, and two writers through one identity run one after another."""

    def setUp(self):
        super().setUp()
        worker.TOOL_WAIT_S, self.saved_poll = 2.0, worker.BUSY_POLL_S
        worker.BUSY_POLL_S = 0.08

    def tearDown(self):
        worker.BUSY_POLL_S = self.saved_poll
        worker.TOOL_WAIT_S = 120.0
        super().tearDown()

    def test_a_queued_tasks_timeout_does_not_shrink_while_it_waits(self):
        task = worker._defaults({"id": "q-timeout", "goal": "g", "engagement": "eng", "tier": "passive",
                                 "info": worker.engagement_info("eng"), "max_steps": 4, "timeout_min": 5,
                                 "status": "running", "started": time.time() - 3600})   # an hour in the queue
        os.makedirs(worker.task_dir(task), exist_ok=True)
        worker.chat = lambda messages, model=None, task=None: {
            "role": "assistant", "content": None,
            "tool_calls": [call("finish", {"status": "completed", "summary": "done", "confidence": "low"})]}
        worker.run_task(task)
        self.assertEqual(task["status"], "done")            # the timeout counts its own running time, not the wait
        self.assertGreater(task["queue_s"], 3000)           # the wait itself is recorded, not charged

    def test_a_busy_refusal_becomes_a_bounded_wait(self):
        tries = []

        def busy_then_ok(task, command, timeout_s=600, approval_id=""):
            tries.append(command)
            if len(tries) == 1:
                return ("REFUSED: 2 network command(s) already running for eng (Max parallel: 2); "
                        "wait for one to finish")
            return "exit=0 tier=passive\nran fine"

        worker.IMPL = {**worker.IMPL, "kali_run": busy_then_ok}
        task, _ = self.run_script([[call("kali_run", {"command": "curl -s http://lab/api/fetch"})]], id="busy-1")
        msgs = worker.load_messages(task)
        tool = [m for m in msgs if m.get("role") == "tool"][-1]
        self.assertIn("ran fine", tool["content"])           # the model never saw the refusal
        self.assertEqual(len(tries), 2)                      # the refused call was sent again, and it never ran
        self.assertGreater(task["queue"].get("tool", 0), 0)  # the wait is recorded by kind
        self.assertGreater(task["waited_s"], 0)              # and not charged to the task's timeout
        # past the bound the refusal goes to the model after all
        worker.TOOL_WAIT_S = 0.0
        tries.clear()
        task2, msgs2 = self.run_script([[call("kali_run", {"command": "curl -s http://lab/api/other"})]], id="busy-2")
        tool2 = [m for m in worker.load_messages(task2) if m.get("role") == "tool"][-1]
        self.assertIn("REFUSED", tool2["content"])

    def test_two_writers_on_one_identity_run_one_after_another(self):
        windows = []          # (start, end) of each intrusive call through the same identity

        def slow_write(task, command, timeout_s=600, approval_id=""):
            w = [time.time(), None]              # a local entry: windows[-1] would race with the other thread
            windows.append(w)
            time.sleep(0.15)
            w[1] = time.time()
            return "exit=0 tier=passive\nwritten"

        worker.IMPL = {**worker.IMPL, "kali_run": slow_write}
        seen = {}
        def chat(messages, model=None, task=None):
            seen[task["id"]] = seen.get(task["id"], 0) + 1
            return {"role": "assistant", "content": None,
                    "tool_calls": [call("kali_run", {"command": "write --to shared-fixture"})] if
                    seen[task["id"]] == 1 else
                    [call("finish", {"status": "completed", "summary": "done", "confidence": "low"})]}
        worker.chat = chat

        def make(tid, tier, identity):
            return worker._defaults({"id": tid, "goal": "g", "engagement": "eng", "tier": tier,
                                     "info": worker.engagement_info("eng"), "max_steps": 4, "timeout_min": 5,
                                     "status": "running", "started": time.time(),
                                     "contract": {"cell": {"class": "mass-assignment", "identity": identity,
                                                           "entries": [], "plan_item": None,
                                                           "endpoints": ["POST http://lab/x (E-1)"]}}})
        a, b = make("w-a", "intrusive", "alice"), make("w-b", "intrusive", "alice")
        r_only = make("r-c", "active", "alice")            # read-only: no identity lock
        for t in (a, b, r_only):
            os.makedirs(worker.task_dir(t), exist_ok=True)
        threads = [threading.Thread(target=worker.run_task, args=(t,)) for t in (a, b, r_only)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(30)
        self.assertTrue(all(not t.is_alive() for t in threads))
        self.assertEqual((a["status"], b["status"]), ("done", "done"))
        ws = sorted((w[0], w[1]) for w in windows if w[1])
        self.assertEqual(len(ws), 3)
        intrusive = ws[:2]
        self.assertLess(intrusive[0][1], intrusive[1][0])   # the two writers never overlapped


class Experiment(Loop):
    """#90: every finished task bound to a plan item leaves an experiment record - a completed, a blocked and a
    stalled task each - and the finish's conclusions keep their exact conditions and rest on the experiment."""

    def contract(self):
        return {"cell": {"class": "mass-assignment", "entries": [], "plan_item": "P-plan",
                         "identity": "alice", "endpoints": ["POST http://lab/x (E-1)"]}}

    def setUp(self):
        super().setUp()
        import workspace
        self.ws = workspace
        self.pid = workspace.plan_add("eng", "agent:planner", [
            {"title": "mass-assignment on POST /api/fetch", "area": "mass-assignment",
             "identity": "alice"}])[0]   # the question's identity: the repeat matches on it
        self.contract = lambda: {"cell": {"class": "mass-assignment", "entries": [],
                                          "plan_item": self.pid, "identity": "alice",
                                          "endpoints": ["POST http://lab/x (E-1)"]}}

    def test_a_completed_task_leaves_its_experiment_and_conclusions(self):
        task, _ = self.run_script(
            [[call("finish", {"status": "completed", "summary": "role rejected on register",
                              "confidence": "medium",
                              "conclusions": [{"claim": "role is not writable through register",
                                               "state": "refuted",
                                               "conditions": "identity alice, POST /register",
                                               "evidence": "evidence/http/r1.txt"}]})]],
            id="x-done", contract=self.contract())
        self.assertEqual(task["experiment"], "X-001")
        x = self.ws.experiments_of("eng", plan_item=self.pid)[0]
        self.assertEqual((x["outcome"], x["status"], x["identity"], x["task"]), ("ran", "completed", "alice", "x-done"))
        self.assertEqual(x["method"], "mass-assignment")
        c = self.ws.conclusions_of("eng", experiment="X-001")[0]
        self.assertEqual((c["state"], c["conditions"]), ("refuted", "identity alice, POST /register"))
        self.assertEqual(task["result"]["conclusions"][0]["claim"], "role is not writable through register")
        # the report carries the experiment id, and a repeat shows on the next packet
        rep = json.loads(worker.report(task))
        self.assertEqual(rep["experiment"], "X-001")
        pk = self.ws.packet("eng", "Test mass-assignment on POST /api/fetch", self.pid, chars=4000)
        self.assertEqual(pk["repeat"][0]["experiment"], "X-001")

    def test_a_blocked_and_a_stalled_task_leave_their_records(self):
        blocked, _ = self.run_script(
            [[call("finish", {"status": "blocked", "summary": "no second identity", "confidence": "low",
                              "needs": ["a second tenant identity"]})]], id="x-blocked", contract=self.contract())
        self.assertEqual(blocked["experiment"], "X-001")
        x = [e for e in self.ws.experiments_of("eng", plan_item=self.pid) if e["task"] == "x-blocked"][0]
        self.assertEqual((x["outcome"], x["status"]), ("blocked", "blocked"))
        # a stalled task ends without calling finish: run_task writes the record on its way out
        saved_limit = worker.NO_ANSWER_LIMIT
        worker.NO_ANSWER_LIMIT = 2
        try:
            task = worker._defaults({"id": "x-stall", "goal": "g", "engagement": "eng", "tier": "passive",
                                     "info": worker.engagement_info("eng"), "max_steps": 6, "timeout_min": 5,
                                     "status": "running", "started": time.time(),
                                     "contract": self.contract()})
            os.makedirs(worker.task_dir(task), exist_ok=True)
            worker.chat = lambda messages, model=None, task=None: {"role": "assistant", "content": None}
            worker.run_task(task)
            self.assertEqual(task["status"], "stalled")
            self.assertEqual(task["experiment"], "X-002")
            xs = [e for e in self.ws.experiments_of("eng", plan_item=self.pid) if e["task"] == "x-stall"][0]
            self.assertEqual(xs["outcome"], "inconclusive")
        finally:
            worker.NO_ANSWER_LIMIT = saved_limit



if __name__ == "__main__":
    warnings.simplefilter("ignore", ResourceWarning)
    unittest.main(verbosity=1, warnings="ignore")
