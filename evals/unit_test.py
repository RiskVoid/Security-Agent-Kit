"""Fast checks that need no Docker, no model and no network: tier classification (tiers.yaml), rate caps, scope and rules
parsing, the scope pre-check, the findings database, the web-fetch guard and the console's request checks.
They run on every pull request in about a second. The full stack is tested by the Integration workflow.
Run: python3 evals/unit_test.py
"""
import importlib.util, os, sys, tempfile, unittest

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [os.path.join(KIT, "kali-mcp"), os.path.join(KIT, "harness"), os.path.join(KIT, "scripts")]
import core  # noqa: E402
import policy  # noqa: E402
import tierconf  # noqa: E402
import findings_db as db  # noqa: E402
import webfetch  # noqa: E402


class Tiers(unittest.TestCase):
    def test_classify(self):
        cases = {
            "ls -la /src": "passive",
            "cat out.txt | grep x": "passive",
            "nmap -sV 10.0.0.1": "active",
            "nmap --script vuln 10.0.0.1": "intrusive",
            "nuclei -u http://a.test -tags fuzz": "intrusive",
            "nuclei -u http://a.test": "active",
            "sudo timeout 60 sqlmap -u http://a.test": "intrusive",
            "echo hi && hydra -l a -P p ssh://h": "intrusive",
            "rv-llm payloads": "passive",
            "rv-llm probe --target http://a.test": "intrusive",
            "jwt_tool eyJ...": "passive",
            "jwt_tool eyJ... -t http://a.test/api": "active",
            "jwt_tool eyJ... -t http://a.test/api -X a": "intrusive",
            "x=$(curl http://a.test)": "active",
        }
        for cmd, tier in cases.items():
            with self.subTest(cmd=cmd):
                self.assertEqual(core.classify(cmd), tier)

    def test_rate(self):
        self.assertEqual(core.apply_rate("nmap -sV h", 50)[0], "nmap --max-rate 50 -sV h")
        self.assertIsNone(core.apply_rate("nmap --max-rate 500 h", 50)[0])
        self.assertEqual(core.apply_rate("nmap --max-rate 10 h", 50)[0], "nmap --max-rate 10 h")
        self.assertEqual(core.apply_rate("ls", 50)[0], "ls")
        self.assertIn("run --rate-limit 5/s", core.apply_rate("schemathesis run spec.json", 5)[0])
        self.assertEqual(core.apply_rate("rv-llm payloads", 5)[0], "rv-llm payloads")  # only 'probe' takes --rate
        self.assertEqual(core.apply_rate("bash -c 'nmap h'", 5)[0], "bash -c 'nmap --max-rate 5 h'")
        self.assertIsNone(core.apply_rate('sh -c "nmap --max-rate 900 h"', 5)[0])

    def test_shell_strings(self):  # what sh -c '...' and eval run counts, in every mode
        self.assertEqual(core.classify('bash -c "sqlmap -u http://a.test; ls"'), "intrusive")
        self.assertEqual(core.classify("sh -lc 'hydra -l a h'"), "intrusive")
        self.assertEqual(core.classify('eval "nmap h"'), "active")
        self.assertEqual(core.classify("bash -c 'ls -la'"), "passive")

    def test_strict(self):
        cases = {
            "ls -la /src": "passive",
            "cat f | grep sh": "passive",
            "python3 --version": "passive",
            "python3 exploit.py http://a.test": "intrusive",
            'python3.12 -c "print(1)"': "intrusive",
            "perl x.pl": "intrusive",
            "bash run.sh": "intrusive",
            'bash -c "ls; cat x"': "passive",
            "curl http://a.test": "active",
            "curl -d a=1 http://a.test": "intrusive",
            "curl -X POST http://a.test": "intrusive",
            "curl --data-binary @f http://a.test": "intrusive",
            "wget --post-data=x http://a.test": "intrusive",
            "nmap -sV h": "active",
        }
        for cmd, tier in cases.items():
            with self.subTest(cmd=cmd):
                self.assertEqual(core.classify(cmd, strict=True), tier)
        self.assertEqual(core.classify("python3 exploit.py"), "passive")  # not strict: by program name
        self.assertEqual(core.classify("curl -d a=1 http://a.test"), "active")
        self.assertTrue(core.parse_rules("- Strict tiers: on")["strict"])
        self.assertFalse(core.parse_rules("- Strict tiers: off")["strict"])
        self.assertFalse(core.parse_rules("- Max rate: 5")["strict"])


class TierFile(unittest.TestCase):
    """kali-mcp/tiers.yaml and its loader (kali-mcp/tierconf.py)."""
    TEXT = open(os.path.join(KIT, "kali-mcp", "tiers.yaml")).read()

    def test_file_loads(self):
        p = core.POLICY
        self.assertIn("sqlmap", p["intrusive"])
        self.assertIn("nmap", p["active"])
        self.assertEqual(p["rate_flags"]["st"], {"flags": ["--rate-limit"], "format": "{}/s", "after": "run"})
        self.assertIn("python3", p["interpreters"])

    @unittest.skipUnless(importlib.util.find_spec("yaml"), "PyYAML not installed")
    def test_same_as_pyyaml(self):  # the fallback parser reads the file exactly as a real YAML parser does
        import yaml
        self.assertEqual(tierconf.parse_yaml(self.TEXT), yaml.safe_load(self.TEXT))

    def test_parser(self):
        y = tierconf.parse_yaml(r"""
a:            # comment
  - x
  - 'q # not a comment'
  - {k: v, n: [1, 'two', "th\\ree"]}
b: [p, q,
    r]
c:
- program: z
  match: 'a''b\s'
d: true
""")
        self.assertEqual(y, {"a": ["x", "q # not a comment", {"k": "v", "n": [1, "two", "th\\ree"]}],
                             "b": ["p", "q", "r"], "c": [{"program": "z", "match": "a'b\\s"}], "d": True})
        for bad in ("a: [x", "a: 'x", "a: 1\na: 2", "a:\n\t- x", "a: &anchor x", "  a: 1"):
            with self.subTest(bad=bad), self.assertRaises(tierconf.ConfigError):
                tierconf.parse_yaml(bad)

    def test_checks(self):
        for bad in ({"intrusive": ["nmap"], "active": ["nmap"]},           # in two tiers
                    {"activ": ["nmap"]},                                      # unknown key
                    {"subcommands": [{"program": "x", "match": "(", "tier": "active"}]},   # bad regex
                    {"subcommands": [{"program": "x", "match": ".", "tier": "loud"}]},     # bad tier
                    {"rate_flags": {"x": {"flags": ["rate"]}}},               # not an option
                    {"intrusive": ["rm -rf"]}):                               # not a program name
            with self.subTest(bad=bad), self.assertRaises(tierconf.ConfigError):
                tierconf.build(bad)


class LiteLLMConfig(unittest.TestCase):
    """scripts/render_litellm.py: planner models on OpenRouter or a direct provider."""
    def test_planners(self):
        import contextlib, io, re, render_litellm as r
        t = open(os.path.join(KIT, "litellm", "config.yaml")).read()
        self.assertEqual(r.planners(t, {"PLANNER_MODEL": "openrouter/a/b", "PLANNER_FALLBACK_MODEL": "openrouter/c"}, "20"), t)
        with contextlib.redirect_stderr(io.StringIO()):
            out = r.planners(t, {"PLANNER_MODEL": "anthropic/m", "PLANNER_FALLBACK_MODEL": "openai/n"}, "7")
        block = lambda n: re.search(r"  - model_name: %s\n(?:    .*\n)+" % n, out).group(0)
        self.assertIn("os.environ/ANTHROPIC_API_KEY", block("planner"))
        self.assertNotIn("zdr", block("planner"))                         # OpenRouter-only routing option dropped
        self.assertIn("max_budget: 7\n      budget_duration: 1d", block("planner-fallback"))  # not a provider budget:
        self.assertNotIn("    openai: {budget_limit", out)                 # the worker also counts as "openai"
        self.assertIn("    anthropic: {budget_limit: 7, time_period: 1d}", out)
        self.assertIn("zdr: true", block("colab-qwen-fallback"))           # worker fallback untouched
        with self.assertRaises(SystemExit):
            r.planners(t, {"PLANNER_MODEL": "gemini/x"}, "20")

    def test_worker_on_openrouter(self):  # ./rvkit worker openrouter: no GPU
        import re, render_litellm as r
        t = open(os.path.join(KIT, "litellm", "config.yaml")).read()
        self.assertEqual(r.worker(t, {"WORKER_MODEL_ID": "openai/qwen38-27b"}), t)
        out = r.worker(t, {"WORKER_MODEL_ID": "openrouter/deepseek/x", "OPENROUTER_API_KEY": "k"})
        for name in ("colab-qwen", "private-llm"):
            block = re.search(r"  - model_name: %s\n(?:    .*\n)+" % name, out).group(0)
            self.assertIn("os.environ/OPENROUTER_API_KEY", block)
            self.assertNotIn("WORKER_API_BASE", block)
            self.assertIn("zdr: true", block)


class Scope(unittest.TestCase):
    def test_parse_scope(self):
        pol = policy.parse_scope("""
- https://app.example.com/login   # a URL path: request tool only
- https://www.example.com          # the whole host on 443
- *.example.io
- example.io:80,8000-8100
- 203.0.113.0/28
- 10.0.0.5:8080
- !10.0.0.7
- !admin.example.io
- !https://www.example.com/admin
- /src/repo
- /etc/passwd
- 127.0.0.1
- 169.254.169.254
- ::1
- not a host!
- example.org:70000
""")
        self.assertEqual([(h["name"], h["wildcard"], h["ports"]) for h in pol["hosts"]],
                         [("www.example.com", False, [443]), ("example.io", True, None),
                          ("example.io", False, [80, "8000-8100"])])
        self.assertEqual([(n["cidr"], n["ports"]) for n in pol["nets"]], [("203.0.113.0/28", None), ("10.0.0.5/32", [8080])])
        self.assertEqual([(u["host"], u["port"], u["prefix"]) for u in pol["urls"]], [("app.example.com", 443, "/login")])
        self.assertEqual(pol["exclude"]["nets"], ["10.0.0.7/32"])
        self.assertEqual(pol["paths"], ["/src/repo"])
        self.assertEqual(len(pol["errors"]), 7, pol["errors"])  # nothing is silently ignored any more (the 7th: example.io vs *.example.io ports)
        self.assertIn("IPv6", " ".join(pol["errors"]))
        self.assertIn("need the same ports", " ".join(policy.parse_scope("- a.test\n- *.a.test:443")["errors"]))

    def test_matching(self):
        pol = policy.effective("- example.com\n- *.example.io:443\n- !x.example.io\n- 10.0.0.0/24:80\n- !10.0.0.9\n"
                               "- https://shop.example.com/api/\n- !https://example.com/admin", "")
        raw = {n: policy.raw_host(pol, n) is not None for n in
               ("example.com", "www.example.com", "a.example.io", "example.io", "x.example.io", "y.x.example.io",
                "shop.example.com")}
        self.assertEqual(raw, {"example.com": False, "www.example.com": False, "a.example.io": True,
                               "example.io": False, "x.example.io": False, "y.x.example.io": False,
                               "shop.example.com": False})  # example.com has a URL exclusion: request tool only
        self.assertTrue(policy.raw_net(pol, "10.0.0.5"))
        self.assertFalse(policy.raw_net(pol, "10.0.0.9"))
        urls = {u: policy.check_url(pol, u) is None for u in (
            "https://shop.example.com/api/x", "https://shop.example.com/apix", "https://shop.example.com/api/../admin",
            "https://shop.example.com/api%2f..%2fadmin", "https://example.com/admin/x", "https://example.com/ok",
            "https://a.example.io/", "http://a.example.io/", "http://10.0.0.5/", "http://10.0.0.5:81/",
            "http://10.0.0.9/", "http://user:pw@example.com/", "ftp://example.com/")}
        self.assertEqual(urls, {
            "https://shop.example.com/api/x": True, "https://shop.example.com/apix": False,
            "https://shop.example.com/api/../admin": False, "https://shop.example.com/api%2f..%2fadmin": False,
            "https://example.com/admin/x": False, "https://example.com/ok": True, "https://a.example.io/": True,
            "http://a.example.io/": False, "http://10.0.0.5/": True, "http://10.0.0.5:81/": False,
            "http://10.0.0.9/": False, "http://user:pw@example.com/": False, "ftp://example.com/": False})
        self.assertIn("never reachable", policy.check_address(pol, "example.com", "127.0.0.1", policy.ALWAYS_BLOCKED))
        self.assertIsNone(policy.check_address(pol, "example.com", "93.184.215.14", policy.ALWAYS_BLOCKED))

    def test_dns_args(self):
        pol = policy.effective("- example.com\n- *.example.io:443\n- !x.example.io\n- https://shop.example.com/api/", "")
        args = core._dns_args(pol, 20001)
        self.assertIn("--server=/example.com/127.0.0.11", args)
        self.assertIn("--address=/*.example.com/", args)       # subdomains of an exact host: NXDOMAIN
        self.assertIn("--server=/*.example.io/127.0.0.11", args)
        self.assertIn("--nftset=/example.io/4#inet#rvkit#e20001_h1", args)
        self.assertIn("--address=/x.example.io/", args)          # exclusion
        self.assertIn("--address=/shop.example.com/", args)      # request tool only
        self.assertNotIn("--server=/shop.example.com/127.0.0.11", args)

    def test_parse_rules(self):
        r, err = policy.parse_rules("- Allowed tiers: passive, intrusive\n- Max rate: 20/s\n- Network: offline\n"
                                    "- Worker: private\n- Window: 22:00-06:00 UTC\n- Dates: 2026-11-10 to 2026-11-20\n"
                                    "- Days: mon-fri\n- Max requests: 500\n- Execution: controlled\n"
                                    "- Stop condition: errors rise\n- Note: anything")
        self.assertEqual(err, [])
        self.assertEqual((r["tiers"], r["max_rate"], r["network"], r["worker"], r["window"], r["timezone"]),
                         (["passive", "intrusive"], 20, "offline", "private", [22, 0, 6, 0], "UTC"))
        self.assertEqual((r["dates"], r["days"], r["max_requests"], r["execution"], r["stop_conditions"]),
                         (["2026-11-10", "2026-11-20"], ["mon", "tue", "wed", "thu", "fri"], 500, "controlled",
                          ["errors rise"]))
        for bad in ("- Allowed tiers: everything", "- Speed: fast", "- Do not touch prod", "- Timezone: Mars/Base",
                    "- Dates: 2026-11-20 to 2026-11-10", "- Window: 25:00-26:00", "- Max rate: lots"):
            self.assertTrue(policy.parse_rules(bad)[1], bad)
        self.assertEqual(policy.parse_rules("")[0]["tiers"], ["passive", "active"])
        self.assertEqual(policy.parse_rules("- Window (UTC): 08:00-18:00")[0]["timezone"], "UTC")

    def test_time(self):
        import datetime as dt
        r = policy.parse_rules("- Timezone: Europe/Berlin\n- Window: 08:00-18:00\n- Days: mon-fri\n"
                               "- Dates: 2026-11-02 to 2026-11-30")[0]
        at = lambda *a: dt.datetime(*a, tzinfo=dt.timezone.utc)
        self.assertIsNone(policy.time_refusal(r, at(2026, 11, 9, 10, 0)))          # Monday 11:00 Berlin
        self.assertIn("window", policy.time_refusal(r, at(2026, 11, 9, 6, 30)))    # 07:30 Berlin
        self.assertIn("mon, tue", policy.time_refusal(r, at(2026, 11, 8, 10, 0)))  # Sunday
        self.assertIn("ended", policy.time_refusal(r, at(2026, 12, 1, 10, 0)))
        self.assertIn("starts", policy.time_refusal(r, at(2026, 11, 1, 10, 0)))

    def test_precheck(self):
        pol = policy.effective("- example.com\n- 10.0.0.0/24\n- !10.0.0.66\n- https://shop.example.com/api/", "")
        info = {"infra_domains": ["searxng"]}
        self.assertEqual(core.precheck("nmap 10.0.0.7 example.com", info, pol), [])
        self.assertEqual(core.precheck("nmap 10.0.1.7 evil.test", info, pol), ["10.0.1.7", "evil.test"])
        self.assertEqual(core.precheck("nmap 10.0.0.66 www.example.com", info, pol), ["10.0.0.66", "www.example.com"])
        self.assertEqual(core.precheck("curl https://shop.example.com/api/x", info, pol), ["shop.example.com"])
        self.assertEqual(core.precheck("grep evil.test notes.txt", info, pol), [])  # not a network tool
        self.assertEqual(core.precheck("curl http://10.0.0.1/login.php", info, pol), [])

    def test_names(self):
        self.assertTrue(core._name_ok("acme-2026.11_a"))
        for bad in ("", "-x", "../x", "a/b", "x" * 65):
            self.assertFalse(core._name_ok(bad), bad)


class Approvals(unittest.TestCase):
    """RW-005: approvals are bound to the action and the policy revision, and are used exactly once."""
    def setUp(self):
        import json
        self.tmp = tempfile.TemporaryDirectory()
        self.saved = (core.CONTROL, core.WORK, core.AUDIT, core.REGISTRY, core.ACTOR)
        core.CONTROL, core.WORK = os.path.join(self.tmp.name, "control"), os.path.join(self.tmp.name, "work")
        core.AUDIT, core.REGISTRY = os.path.join(core.CONTROL, "audit.log"), os.path.join(core.CONTROL, "reg.json")
        os.makedirs(os.path.join(core.ctl_dir("e1"), "approvals"))
        os.makedirs(os.path.join(core.WORK, "e1"))
        json.dump({"e1": 20001}, open(core.REGISTRY, "w"))
        self.scope("- example.com\n")
        self.rules = policy.parse_rules("")[0]

    def tearDown(self):
        core.CONTROL, core.WORK, core.AUDIT, core.REGISTRY, core.ACTOR = self.saved
        self.tmp.cleanup()

    def scope(self, text):
        with open(os.path.join(core.ctl_dir("e1"), "SCOPE.md"), "w") as f:
            f.write(text)

    def approved(self, action):
        a = core.request_approval("e1", action, "intrusive", "shown")
        core.ACTOR = "console:tester"
        core.decide("e1", a["id"], True)
        return a["id"]

    def test_bound_to_action_and_used_once(self):
        act = {"kind": "http", "method": "POST", "url": "https://example.com/", "headers": {}, "body": "x"}
        aid = self.approved(act)
        self.assertIn("body differ", core.consume_approval("e1", aid, dict(act, body="y"), self.rules))
        self.assertIsNone(core.consume_approval("e1", aid, act, self.rules))
        self.assertIn("is used", core.consume_approval("e1", aid, act, self.rules))
        a = [x for x in core.approvals("e1") if x["id"] == aid][0]
        self.assertEqual(a["decided_by"], "console:tester")

    def test_policy_change_makes_it_stale(self):
        act = {"kind": "run", "command": "sqlmap -u x", "executables": {}, "inputs": {}}
        aid = self.approved(act)
        self.scope("- example.com\n- example.org\n")
        self.assertIn("stale", core.consume_approval("e1", aid, act, self.rules))
        self.assertEqual([x["status"] for x in core.approvals("e1")], ["stale"])
        pending = core.request_approval("e1", act, "intrusive", "shown")
        self.scope("- example.com\n")
        self.assertEqual(core.invalidate_approvals("e1", "changed"), 1)
        with self.assertRaises(ValueError):  # approving a request made under another policy
            core.decide("e1", pending["id"], True)

    def test_race_uses_once(self):
        act = {"kind": "run", "command": "x", "executables": {}, "inputs": {}}
        aid = self.approved(act)
        open(core._approval_path("e1", aid)[:-5] + ".used", "w").close()  # another call got there first
        self.assertIn("is used", core.consume_approval("e1", aid, act, self.rules))

    def test_input_files_bound(self):
        with open(os.path.join(core.WORK, "e1", "probe.sh"), "w") as f:
            f.write("curl x")
        before = core.run_action("e1", "bash probe.sh")["inputs"]
        with open(os.path.join(core.WORK, "e1", "probe.sh"), "w") as f:
            f.write("curl y")
        self.assertNotEqual(before, core.run_action("e1", "bash probe.sh")["inputs"])
        self.assertIn("probe.sh", before)

    def test_budget(self):
        self.assertTrue(core.take_budget("e1", "requests", 2))
        self.assertTrue(core.take_budget("e1", "requests", 2))
        self.assertFalse(core.take_budget("e1", "requests", 2))
        self.assertEqual(core.usage("e1")["requests"], 2)


class Findings(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        db.WORK = self.tmp.name
        os.mkdir(os.path.join(self.tmp.name, "e"))

    def tearDown(self):
        self.tmp.cleanup()

    def add(self, title):
        return db.record("e", title=title, severity="high")["id"]

    def test_duplicates(self):
        a, b, c = self.add("A"), self.add("B"), self.add("C")
        self.assertEqual((a, b, c), ("F-001", "F-002", "F-003"))
        r = db.update("e", b, duplicate_of=a)  # duplicate_of alone implies the status
        self.assertEqual((r["status"], r["duplicate_of"]), ("duplicate", a))
        with self.assertRaises(ValueError):
            db.update("e", c, status="duplicate")  # needs the original
        with self.assertRaises(ValueError):
            db.update("e", c, duplicate_of=c)  # not itself
        with self.assertRaises(ValueError):
            db.update("e", c, duplicate_of=b)  # not a duplicate
        with self.assertRaises(ValueError):
            db.update("e", c, duplicate_of="F-999")
        with self.assertRaises(ValueError):
            db.update("e", c, status="confirmed", duplicate_of=a)
        r = db.update("e", b, status="confirmed")  # leaving the status drops the link
        self.assertEqual((r["status"], r["duplicate_of"]), ("confirmed", None))

    def test_validation(self):
        with self.assertRaises(ValueError):
            db.record("e", title="x", severity="urgent")
        with self.assertRaises(ValueError):
            db.list_("../etc")
        with self.assertRaises(ValueError):
            db.update("e", "F-404", status="confirmed")

    def test_migrates_old_database(self):
        """A findings.db from before schema versions keeps its rows and gains revision and updated_by."""
        import sqlite3
        con = sqlite3.connect(os.path.join(self.tmp.name, "e", "findings.db"))
        con.execute("CREATE TABLE findings (id TEXT PRIMARY KEY, title TEXT NOT NULL, severity TEXT NOT NULL, "
                    "cvss_vector TEXT, cvss_score REAL, cwe TEXT, asset TEXT, description TEXT, impact TEXT, "
                    "reproduction TEXT, remediation TEXT, evidence TEXT DEFAULT '[]', status TEXT NOT NULL "
                    "DEFAULT 'candidate', source TEXT, notes TEXT, created TEXT, updated TEXT)")
        con.execute("INSERT INTO findings (id, title, severity) VALUES ('F-001', 'old', 'low')")
        con.commit(); con.close()
        r = db.get("e", "F-001")
        self.assertEqual((r["title"], r["revision"], r["updated_by"], r["duplicate_of"]), ("old", 1, None, None))
        con = sqlite3.connect(os.path.join(self.tmp.name, "e", "findings.db"))
        self.assertEqual(con.execute("PRAGMA user_version").fetchone()[0], db.SCHEMA_VERSION)
        con.execute(f"PRAGMA user_version={db.SCHEMA_VERSION + 1}"); con.commit(); con.close()
        with self.assertRaises(ValueError):  # from a newer kit: refused, not downgraded
            db.get("e", "F-001")

    def test_revisions_and_conflicts(self):
        a = self.add("A")
        r = db.update("e", a, expected_revision=1, actor="console:alice", status="confirmed")
        self.assertEqual((r["revision"], r["previous_revision"], r["updated_by"]), (2, 1, "console:alice"))
        with self.assertRaises(db.Conflict):  # someone saved revision 2 in between
            db.update("e", a, expected_revision=1, actor="console:bob", severity="low")
        self.assertEqual(db.get("e", a)["severity"], "high")
        with self.assertRaises(ValueError):
            db.update("e", a, actor="root", notes="x")  # actors are <kind>:<name>

    def test_ops(self):
        import ops
        a = self.add("A")
        with self.assertRaises(ops.OpError) as c:
            ops.call("shell.run", {"engagement": "e"})  # only listed operations exist
        self.assertEqual(c.exception.code, 404)
        with self.assertRaises(ops.OpError):  # a change needs an actor
            ops.call("finding.update", {"engagement": "e", "id": a, "fields": {"status": "confirmed"}})
        with self.assertRaises(ops.OpError):  # source isn't editable
            ops.call("finding.update", {"engagement": "e", "actor": "cli:x", "id": a, "fields": {"source": "x"}})
        row, ev = ops.call("finding.update", {"engagement": "e", "actor": "cli:x", "id": a,
                                              "fields": {"status": "confirmed"}, "expected_revision": 1})
        self.assertEqual(ev, {"event": "finding-updated", "actor": "cli:x", "target": a, "before": 1, "after": 2,
                              "fields": ["status"]})
        with self.assertRaises(ops.OpError) as c:
            ops.call("finding.update", {"engagement": "e", "actor": "cli:x", "id": a,
                                        "fields": {"status": "fixed"}, "expected_revision": 1})
        self.assertEqual(c.exception.code, 409)
        got, _ = ops.call("meta.get", {"engagement": "e"})
        res, ev = ops.call("meta.set", {"engagement": "e", "actor": "console:a", "fields": {"client": "Acme\nInc"},
                                        "expected_digest": got["digest"]})
        self.assertEqual((res["meta"]["client"], ev["event"]), ("Acme Inc", "meta-updated"))
        with self.assertRaises(ops.OpError) as c:  # stale digest: the file changed since it was read
            ops.call("meta.set", {"engagement": "e", "actor": "console:a", "fields": {"client": "B"},
                                  "expected_digest": got["digest"]})
        self.assertEqual(c.exception.code, 409)
        with self.assertRaises(ops.OpError):
            ops.call("meta.set", {"engagement": "e", "actor": "console:a", "fields": {"evil": "x"}})
        s, _ = ops.call("summary.get", {"engagement": "e"})
        ops.call("summary.set", {"engagement": "e", "actor": "console:a", "text": "Hi", "expected_digest": s["digest"]})
        self.assertEqual(ops.call("summary.get", {"engagement": "e"})[0]["text"], "Hi")
        with self.assertRaises(ValueError):
            ops.call("summary.get", {"engagement": "../e"})


class WebFetch(unittest.TestCase):
    def test_refusal(self):
        self.assertTrue(webfetch.refusal("http://127.0.0.1/", [], []).startswith("REFUSED"))
        self.assertTrue(webfetch.refusal("https://app.example.com/x", [], ["example.com"]).startswith("REFUSED"))
        self.assertEqual(webfetch.refusal("file:///etc/passwd", [], []), "only http(s) URLs")

    def test_connection_is_pinned(self):
        """The connection goes to the checked address, never to a fresh DNS answer, and an unchecked host
        (a redirect target that skipped the check) can't be reached at all."""
        import http.server, threading
        srv = http.server.HTTPServer(("127.0.0.1", 0), type("H", (http.server.BaseHTTPRequestHandler,), {
            "do_GET": lambda s: (s.send_response(200), s.end_headers(), s.wfile.write(b"pinned")),
            "log_message": lambda *a: None}))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        port = srv.server_address[1]
        try:
            pins = {"never-resolves.invalid": ["127.0.0.1"]}  # .invalid has no DNS: only the pin can reach it
            op = webfetch.opener([], [], pins)
            self.assertEqual(op.open(f"http://never-resolves.invalid:{port}/", timeout=5).read(), b"pinned")
            with self.assertRaises(Exception):
                op.open(f"http://localhost:{port}/", timeout=5)  # not checked, so not pinned
        finally:
            srv.shutdown()


class ColabPrebuilt(unittest.TestCase):
    """colab/serve.py picks the llama.cpp CUDA build for the driver, never the runtime-only cudart package."""
    NAMES = ["cudart-llama-b1-bin-ubuntu-cuda-12.8-x64.tar.gz", "cudart-llama-b1-bin-ubuntu-cuda-13.4-x64.tar.gz",
             "llama-b1-bin-ubuntu-cuda-12.8-x64.tar.gz", "llama-b1-bin-ubuntu-cuda-13.4-x64.tar.gz",
             "llama-b1-bin-ubuntu-cuda-13.4-arm64.tar.gz", "llama-b1-bin-ubuntu-x64.tar.gz"]

    def test_pick(self):
        spec = importlib.util.spec_from_file_location("serve", os.path.join(KIT, "colab", "serve.py"))
        serve = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(serve)
        pick = serve.pick_prebuilt
        self.assertEqual(pick(self.NAMES, "b1", (12, 8)), ("llama-b1-bin-ubuntu-cuda-12.8-x64.tar.gz",
                                                          "cudart-llama-b1-bin-ubuntu-cuda-12.8-x64.tar.gz"))
        self.assertEqual(pick(self.NAMES, "b1", (13, 6))[0], "llama-b1-bin-ubuntu-cuda-13.4-x64.tar.gz")
        self.assertEqual(pick(self.NAMES, "b1", (12, 4)), (None, None))  # driver too old: build from source
        self.assertEqual(pick(self.NAMES, "b1", None)[0], "llama-b1-bin-ubuntu-cuda-12.8-x64.tar.gz")


class Console(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import console
        cls.c = console

    def test_names(self):
        self.assertTrue(self.c.NAME_RX.match("acme-1"))
        self.assertFalse(self.c.NAME_RX.match("../x"))
        self.assertTrue(self.c.FID_RX.match("F-012"))
        self.assertFalse(self.c.FID_RX.match("F-1; rm"))

    def test_eng_path(self):
        with self.assertRaises(Exception):
            self.c.eng_path("../etc", "passwd")


class ModelEvents(unittest.TestCase):
    """litellm/rv_events.py (error classification, the event log) and scripts/model_events.py (its reader)."""
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("rv_events", os.path.join(KIT, "litellm", "rv_events.py"))
        cls.rv = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.rv)

    def test_classify(self):
        class E(Exception):
            def __init__(self, msg, code=None):
                super().__init__(msg)
                self.status_code = code
        c = lambda g, msg, code=None: self.rv.classify(g, E(msg, code))[0]
        self.assertEqual(c("planner", "This request requires more credits", 402), "credits")
        self.assertEqual(c("planner", "ExceededBudget: crossed budget for provider openrouter", 400), "budget")
        self.assertEqual(c("planner", "invalid api key", 401), "auth")
        self.assertEqual(c("planner", "temporarily rate-limited upstream", 429), "rate_limit")
        self.assertEqual(c("colab-qwen", "Connection error"), "worker_down")
        self.assertEqual(c("colab-qwen", "Cloudflare tunnel error", 530), "worker_down")
        self.assertEqual(c("planner", "Connection error"), "error")              # only the worker means "Colab down"
        self.assertEqual(c("planner", "ContextWindowExceededError: too long"), "context")
        self.assertEqual(c("planner", "Request timed out"), "timeout")
        kind, msg = self.rv.classify("planner", E('{"error":{"message":"Provider returned error","raw":"{\\"message\\": \\"Invalid value: x\\"}"}}', 400))
        self.assertEqual(kind, "error")
        self.assertIn("Invalid value: x", msg)                                    # the detailed message, not the wrapper
        for k in ("credits", "budget", "worker_down"):                           # every message says what to do
            self.assertTrue(any(w in self.rv.classify("colab-qwen" if k == "worker_down" else "planner",
                                                      E({"credits": "credits", "budget": "budget exceeded",
                                                         "worker_down": "connect"}[k], 402 if k == "credits" else None))[1]
                                for w in ("./rvkit", "/rv-start", "openrouter.ai")))

    def test_context_passes_through(self):
        """A full context window must reach OpenHands unchanged (it summarises and continues), logged as recovered."""
        import asyncio, model_events as me
        class Ctx(Exception):
            status_code = 400
        with tempfile.TemporaryDirectory() as d:
            self.rv.EVENTS = log = os.path.join(d, "e.jsonl")
            err = Ctx("ContextWindowExceededError: request (81359 tokens) exceeds the available context size (65536 tokens)")
            out = asyncio.run(self.rv.RvEvents().async_post_call_failure_hook({"model": "colab-qwen", "messages": []}, err, None))
            self.assertIsNone(out)                                              # not rewritten
            ev = me.read(path=log)[0]
            self.assertEqual((ev["kind"], ev["problem"]), ("context", False))
            self.assertIn("81K tokens, the window is 64K", ev["message"])

    def test_engagement_of(self):
        e = self.rv.engagement_of
        self.assertEqual(e({"messages": [{"role": "user", "content": "Engagement `lab-juice`: web test"}]}), "lab-juice")
        call = {"role": "assistant", "tool_calls": [{"function": {"arguments": '{"engagement": "acme-2026", "command": "id"}'}}]}
        self.assertEqual(e({"messages": [{"role": "user", "content": [{"type": "text", "text": "Engagement `old`"}]}, call]}),
                         "acme-2026")                                         # the newest tool call wins over the brief
        self.assertIsNone(e({"messages": [{"role": "user", "content": "hello"}]}))
        self.assertIsNone(e({}))

    def test_log_and_reader(self):
        import model_events as me
        with tempfile.TemporaryDirectory() as d:
            self.rv.EVENTS = log = os.path.join(d, "events", "model-events.jsonl")
            self.rv.record("refusal", "planner", "planner refused; answered by planner-fallback", fallback="planner-fallback")
            for _ in range(3):
                self.rv.record("credits", "planner", "balance too low")
            self.assertEqual(me.count(log), 4)
            ev = me.recent(3600, path=log)
            self.assertEqual([(e["kind"], e["count"], e["problem"]) for e in sorted(ev, key=lambda e: e["kind"])],
                             [("credits", 3, True), ("refusal", 1, False)])       # repeats collapsed, refusal recovered
            self.assertEqual([e["kind"] for e in me.recent(3600, problems_only=True, path=log)], ["credits"])
            self.assertEqual(me.recent(3600, path=log, now=__import__("time").time() + 7200), [])
            self.assertEqual(len(me.read(3, path=log)), 1)                       # --from-line, for ./rvkit watch
            self.assertIn("(x3)", me.line(ev[0] if ev[0]["kind"] == "credits" else ev[1]))
            self.rv.record("worker_down", "colab-qwen", "colab-qwen is not reachable", engagement="lab-juice")
            self.assertEqual([x["kind"] for x in me.recent(3600, path=log, engagement="lab-juice")], ["worker_down"])
            self.assertEqual(me.recent(3600, path=log, engagement="lab-juice")[0]["text"], "Is not reachable")


if __name__ == "__main__":
    unittest.main(verbosity=1)
