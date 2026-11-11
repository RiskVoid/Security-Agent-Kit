"""Fast checks that need no Docker, no model and no network: tier classification (tiers.yaml), rate caps, scope and rules
parsing, the scope pre-check, the findings database, the web-fetch guard, the console's request checks, the
credential vault, identity specs, capture sanitizing and authorization-matrix validation.
They run on every pull request in about a second. The full stack is tested by the Integration workflow.
Run: python3 evals/unit_test.py
"""
import importlib.util, json, os, sys, tempfile, unittest

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
        # an email address in form data or a body is data, not a target (found by the release acceptance run)
        for cmd in ("curl -X POST http://10.0.0.1/login -d 'email=alice%40acme.test&password=x'",
                    "curl -X POST http://10.0.0.1/login --data-urlencode 'email=alice@acme.test'",
                    "curl http://10.0.0.1/api -d '{\"email\":\"bob.smith+qa@globex.test\"}'"):
            self.assertEqual(core.precheck(cmd, info, pol), [], cmd)
        # ...but a URL's user part and user@host tools still name a target
        self.assertEqual(core.precheck("curl http://admin:pw@evil.test/", info, pol), ["evil.test"])
        self.assertEqual(core.precheck("curl http://admin@evil.test/", info, pol), ["evil.test"])
        self.assertEqual(core.precheck("impacket-psexec admin@evil.test", info, pol), ["evil.test"])
        self.assertEqual(core.precheck("hydra -l admin@evil.test -P p.txt evil.test ssh", info, pol), ["evil.test"])

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

    def test_provenance_of_http_and_matrix_evidence(self):
        """Evidence from an HTTP request or a matrix run has no command line in the audit; provenance names the
        request or the matrix instead of failing (found by the release acceptance run)."""
        import json
        os.makedirs(os.path.join(core.WORK, "e1", "evidence"))
        for name in ("http.txt", "matrix.json"):
            open(os.path.join(core.WORK, "e1", "evidence", name), "w").write(name)
        with open(core.AUDIT, "a") as f:
            for e in ({"ts": "t1", "engagement": "e1", "action": "http", "method": "GET", "url": "http://h/a",
                       "identity": "bob", "outputs": {"evidence/http.txt": core.sha256_file(
                           os.path.join(core.WORK, "e1", "evidence", "http.txt"))}},
                      {"ts": "t2", "engagement": "e1", "event": "authz-run", "matrix": "m1", "outputs": {
                          "evidence/matrix.json": core.sha256_file(
                              os.path.join(core.WORK, "e1", "evidence", "matrix.json"))}}):
                f.write(json.dumps(e) + "\n")
        res = core.provenance("e1", ["evidence/http.txt", "evidence/matrix.json"])
        self.assertEqual([r["status"] for r in res], ["verified", "verified"])
        self.assertEqual(res[0]["produced_by"], "http GET http://h/a as bob")
        self.assertEqual(res[1]["produced_by"], "authz run m1")

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

    def test_confirmed_records_its_method(self):
        r = db.record("e", title="A", severity="high", status="confirmed", method="runtime-reproduction")
        self.assertEqual((r["verification"], r["verified_method"]), ("verified", "runtime-reproduction"))
        r = db.record("e", title="B", severity="high", status="confirmed")  # a person, through the console or CLI
        self.assertEqual(r["verified_method"], "not stated")
        r = db.record("e", title="C", severity="high", method="replay")  # a candidate is not verified yet
        self.assertEqual((r["verification"], r["verified_method"]), ("unverified", None))
        with self.assertRaises(ValueError):
            db.record("e", title="D", severity="high", status="confirmed", method="guess")

    def test_agent_confirmation_needs_method_and_evidence(self):
        ev = ["/work/e/evidence/runs/20261111T000000-curl-abc123.txt (200 with another tenant's invoice)"]
        self.assertIn("needs method", db.confirm_problem(None, ev))
        self.assertIn("needs method", db.confirm_problem("not stated", ev))
        self.assertIn("must be one of", db.confirm_problem("guess", ev))
        for m in ("runtime-reproduction", "replay", "authorization-matrix", "tool-output"):
            self.assertIn("needs evidence", db.confirm_problem(m, []))
            self.assertIn("needs evidence", db.confirm_problem(m, "[]"))  # as stored
            self.assertIsNone(db.confirm_problem(m, ev))
            self.assertIsNone(db.confirm_problem(m, json.dumps(ev)))
        for m in ("source-review", "retest", "client-confirmation"):  # the proof is the code, the retest or the client
            self.assertIsNone(db.confirm_problem(m, []))

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
        self.assertFalse(os.path.exists(os.path.join(self.tmp.name, "e", "findings.db")))   # moved into .rv
        con = sqlite3.connect(os.path.join(self.tmp.name, "e", ".rv", "findings.db"))
        self.assertEqual(con.execute("PRAGMA user_version").fetchone()[0], db.SCHEMA_VERSION)
        con.execute(f"PRAGMA user_version={db.SCHEMA_VERSION + 1}"); con.commit(); con.close()
        with self.assertRaises(ValueError):  # from a newer kit: refused, not downgraded
            db.get("e", "F-001")

    def test_revisions_and_conflicts(self):
        a = self.add("A")
        r = db.update("e", a, expected_revision=1, actor="console:alice", status="confirmed")
        self.assertEqual((r["revision"], r["previous_revision"], r["updated_by"]), (2, 1, "console:alice"))
        with self.assertRaises(db.Conflict):  # someone saved revision 2 in between
            db.update("e", a, expected_revision=1, actor="console:bob", severity="low", reason="r")
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

    def test_refusal_raised_inside_the_stream(self):
        """OpenRouter can refuse with an error inside the stream (cyber_policy) instead of finish_reason
        content_filter. Before the first answer chunk that must still count as a refusal (fallback or a [RiskVoid]
        reason), not end the conversation with an error. Other errors pass through. Found by the acceptance run."""
        import asyncio
        class Refused(Exception):
            status_code = 403  # OpenRouter sends this refusal as a 403: it must not read as a rejected key
        msg = ("OpenrouterException - Message: This content was flagged for possible cybersecurity risk. "
               "Metadata: {'error_type': 'refusal', 'provider_code': 'cyber_policy'}")
        self.assertEqual(self.rv.classify("planner", Refused(msg))[0], "refusal")

        async def stream(err):
            yield {"choices": [{"delta": {"role": "assistant"}}]}
            raise err

        async def run(err):
            hook = self.rv.RvEvents().async_post_call_streaming_iterator_hook(
                None, stream(err), {"model": "planner", "disable_fallbacks": True, "messages": []})
            return [c async for c in hook]

        saved = self.rv.notice_chunks  # the real one builds litellm chunk objects; litellm isn't installed here
        self.rv.notice_chunks = lambda group, text: [{"notice": text}]
        self.addCleanup(setattr, self.rv, "notice_chunks", saved)
        with tempfile.TemporaryDirectory() as d:
            self.rv.EVENTS = os.path.join(d, "e.jsonl")
            out = asyncio.run(run(Refused(msg)))
            self.assertTrue(any("[RiskVoid]" in json.dumps(c, default=str) for c in out))
            with self.assertRaises(RuntimeError):
                asyncio.run(run(RuntimeError("upstream connection reset")))

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



class DataRoutes(unittest.TestCase):
    """RW-006: where each model route sends data (litellm/rv_routes.py) and the Client data decision."""
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("rv_routes", os.path.join(KIT, "litellm", "rv_routes.py"))
        cls.r = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.r)

    ENV = {"WORKER_MODEL_ID": "openai/qwen", "WORKER_API_BASE": "https://abc.trycloudflare.com/v1",
           "COLAB_API_BASE": "https://abc.trycloudflare.com/v1", "WORKER_FALLBACK": "on",
           "WORKER_FALLBACK_MODEL": "openrouter/x/y", "PLANNER_MODEL": "openrouter/a/b",
           "PLANNER_FALLBACK_MODEL": "anthropic/claude-x"}
    ROUTES = {"engagements": {"acme": {"client_data": ["local", "colab"], "paths": ["/src/acme"], "halted": False},
                              "open": {"client_data": None, "paths": [], "halted": False},
                              "stopped": {"client_data": None, "paths": [], "halted": True}},
              "conversations": {"0123abcd00004000800000000000beef": "acme", "aaaabbbb00004000800000000000cccc": "stopped"}}

    def test_destinations(self):
        r, env = self.r, self.ENV
        self.assertEqual(r.group_route("colab-qwen", env), ("colab", ["openrouter"]))
        self.assertEqual(r.group_route("private-llm", env), ("colab", []))
        self.assertEqual(r.group_route("planner", env), ("openrouter", ["anthropic"]))
        self.assertEqual(r.group_route("colab-qwen", dict(env, WORKER_FALLBACK="off"))[1], [])
        local = dict(env, WORKER_API_BASE="http://host.docker.internal:11434/v1")
        self.assertEqual(r.group_route("colab-qwen", local)[0], "local")
        for base, dest in (("http://192.168.1.20:8000/v1", "local"), ("http://gpu-box:8000/v1", "local"),
                           ("https://gpu.example.net/v1", "api"), ("https://openrouter.ai/api/v1", "openrouter"),
                           ("http://worker-not-connected.invalid/v1", "local")):
            self.assertEqual(r.group_route("private-llm", dict(env, WORKER_API_BASE=base))[0], dest, base)
        self.assertEqual(r.group_route("private-llm", dict(env, WORKER_MODEL_ID="openrouter/m"))[0], "openrouter")

    def decide(self, group, request, headers=None, session=None):
        return self.r.decide(group, request, headers or {}, self.ROUTES, self.ENV, session)

    def test_client_data(self):
        hi = {"messages": [{"role": "user", "content": "hi"}]}
        self.assertTrue(self.decide("planner", hi)["allow"])                                   # names no engagement
        d = self.decide("planner", hi, {"X-RV-Engagement": "acme"})
        self.assertFalse(d["allow"])
        self.assertIn("only to local, colab", d["reason"])
        d = self.decide("colab-qwen", hi, {"x-rv-engagement": "acme"})
        self.assertTrue(d["allow"])
        self.assertFalse(d["fallbacks"])                                                       # OpenRouter fallback off
        self.assertTrue(self.decide("colab-qwen", hi, {"x-rv-engagement": "open"})["fallbacks"])
        self.assertFalse(self.decide("planner", hi, session="0123abcd-0000-4000-8000-00000000beef")["allow"])
        call = {"messages": [{"role": "user", "content": "go"}, {"role": "assistant", "tool_calls": [
            {"function": {"name": "run", "arguments": '{"engagement": "acme", "command": "ls"}'}}]}]}
        self.assertFalse(self.decide("planner", call)["allow"])
        self.assertFalse(self.decide("planner", {"messages": [{"role": "user", "content": "cat /src/acme/app.py"}]})["allow"])
        self.assertFalse(self.decide("planner", {"messages": [{"role": "assistant", "tool_calls": [
            {"function": {"name": "terminal", "arguments": '{"command": "cat /work/acme/notes.md"}'}}]}]})["allow"])
        # tool results are not scanned: a listing of every engagement doesn't tie the call to them
        listing = {"messages": [{"role": "user", "content": "list"}, {"role": "tool", "content": "Engagement acme ..."}]}
        self.assertTrue(self.decide("planner", listing)["allow"])
        self.assertTrue(self.decide("planner", {"messages": [{"role": "user", "content": "the /work/acmeX folder"}]})["allow"])

    def test_halt(self):
        hi = {"messages": [{"role": "user", "content": "hi"}]}
        self.assertIn("halted", self.decide("colab-qwen", hi, {"x-rv-engagement": "stopped"})["reason"])
        self.assertFalse(self.decide("planner", hi, session="aaaabbbb00004000800000000000cccc")["allow"])
        # only its own conversations and tasks stop: naming a halted engagement elsewhere is still allowed
        self.assertTrue(self.decide("planner", {"messages": [{"role": "user", "content": "report on /work/stopped/x"}]})["allow"])
        gone = dict(self.ROUTES, conversations={"ffff": "deleted-one"})
        self.assertFalse(self.r.decide("planner", hi, {"x-litellm-session-id": "ffff"}, gone, self.ENV)["allow"])

    def test_rule(self):
        r, e = policy.parse_rules("- Client data: colab, local")
        self.assertEqual((r["client_data"], e), (["local", "colab"], []))
        self.assertIsNone(policy.parse_rules("- Client data: any")[0]["client_data"])
        self.assertIsNone(policy.parse_rules("")[0]["client_data"])
        self.assertTrue(policy.parse_rules("- Client data: moon")[1])
        self.assertTrue(any("Client data" in x for x in policy.effective("- a.example.com", "- Client data: local")["limits"]))

    def test_policy_refusal_passes_through(self):
        spec = importlib.util.spec_from_file_location("rv_events", os.path.join(KIT, "litellm", "rv_events.py"))
        ev = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ev)
        kind, text = ev.classify("planner", Exception(ev.POLICY_TAG + "engagement acme allows ..."))
        self.assertEqual((kind, text), ("policy", "engagement acme allows ..."))


class Credentials(unittest.TestCase):
    """RW-006: credential references; RW-007: conversation bindings and the routing table."""
    def setUp(self):
        import json
        self.tmp = tempfile.TemporaryDirectory()
        self.saved = (core.CONTROL, core.WORK, core.AUDIT, core.REGISTRY, core.ACTOR, core.ROUTES)
        core.CONTROL, core.WORK = os.path.join(self.tmp.name, "control"), os.path.join(self.tmp.name, "work")
        core.AUDIT, core.REGISTRY = os.path.join(core.CONTROL, "audit.log"), os.path.join(core.CONTROL, "reg.json")
        core.ROUTES = os.path.join(self.tmp.name, "routes")
        for e in ("e1", "e2"):
            os.makedirs(core.ctl_dir(e))
            open(os.path.join(core.ctl_dir(e), "SCOPE.md"), "w").write("- example.com\n- /src/app\n")
            open(os.path.join(core.ctl_dir(e), "RULES.md"), "w").write("- Client data: local\n" if e == "e1" else "")
        json.dump({"e1": 20001, "e2": 20002}, open(core.REGISTRY, "w"))

    def tearDown(self):
        core.CONTROL, core.WORK, core.AUDIT, core.REGISTRY, core.ACTOR, core.ROUTES = self.saved
        self.tmp.cleanup()

    def test_references(self):
        core.cred_set("e1", "api_token", "Sup3r-Secret-Value\n")
        self.assertEqual([c["name"] for c in core.cred_list("e1")], ["API_TOKEN"])
        self.assertNotIn("value", core.cred_list("e1")[0])
        self.assertEqual(core.cred_expand("e1", "Bearer {{cred:API_TOKEN}}"), "Bearer Sup3r-Secret-Value")
        with self.assertRaises(ValueError):
            core.cred_expand("e1", "{{cred:OTHER}}")
        self.assertEqual(core.scrub("e1", "x Sup3r-Secret-Value y"), "x {{cred:API_TOKEN}} y")
        self.assertEqual(core.scrub("e1", b"Sup3r-Secret-Value"), b"{{cred:API_TOKEN}}")
        self.assertEqual(core.scrub("e2", "Sup3r-Secret-Value"), "Sup3r-Secret-Value")   # per engagement
        self.assertEqual(core.cred_used("e1", "curl -H \"X: $RV_CRED_API_TOKEN\" u"), ["API_TOKEN"])
        self.assertEqual(core.cred_env("e1"), {"RV_CRED_API_TOKEN": "Sup3r-Secret-Value"})
        self.assertNotIn("Sup3r", open(core.AUDIT).read())
        for bad in ("1abc", "a-b", "x" * 40):
            with self.assertRaises(ValueError):
                core.cred_set("e1", bad, "valuevalue")
        with self.assertRaises(ValueError):
            core.cred_set("e1", "short", "abc")
        core.cred_remove("e1", "api_token")
        self.assertEqual(core.cred_list("e1"), [])

    def test_bindings_and_routes(self):
        import json
        core.bind_conversation("e1", "0123ABCD-0000-4000-8000-00000000BEEF", "t")
        with self.assertRaises(ValueError):  # one engagement per conversation
            core.bind_conversation("e2", "0123abcd-0000-4000-8000-00000000beef")
        with self.assertRaises(ValueError):
            core.bind_conversation("e1", "not an id!")
        r = json.load(open(os.path.join(core.ROUTES, "routes.json")))
        self.assertEqual(r["conversations"], {"0123abcd00004000800000000000beef": "e1"})
        self.assertEqual(r["engagements"]["e1"]["client_data"], ["local"])
        self.assertEqual(r["engagements"]["e1"]["paths"], ["/src/app"])
        self.assertIsNone(r["engagements"]["e2"]["client_data"])
        core.unbind_conversation("e1", "0123abcd-0000-4000-8000-00000000beef")
        self.assertEqual(json.load(open(os.path.join(core.ROUTES, "routes.json")))["conversations"], {})


class AuthenticatedTesting(Credentials):
    """RW-008 to RW-011: the vault, identity specs, capture sanitizing and comparison, the Browser support rule and
    authorization-matrix validation. Needs the cryptography package (kali-mcp's venv; pip install cryptography)."""
    def test_vault(self):
        import json
        core.cred_set("e1", "TOKEN", "vault-secret-value", expires="2099-01-01")
        raw = open(os.path.join(core.ctl_dir("e1"), "credentials.vault.json")).read()
        self.assertNotIn("vault-secret-value", raw)
        self.assertEqual(oct(os.stat(os.path.join(core.CONTROL, "vault.key")).st_mode & 0o777), "0o600")
        self.assertFalse(core.cred_list("e1")[0]["expired"])
        with self.assertRaises(ValueError):
            core.cred_set("e1", "OLD", "value-value", expires="2001-01-01")
        old_key = open(os.path.join(core.CONTROL, "vault.key"), "rb").read()
        self.assertGreaterEqual(core.vault_rotate(), 1)
        self.assertNotEqual(open(os.path.join(core.CONTROL, "vault.key"), "rb").read(), old_key)
        self.assertEqual(core.cred_value("e1", "TOKEN"), "vault-secret-value")
        # an RW-006 plain-text file is encrypted on first use and removed
        json.dump({"LEGACY": {"value": "legacy-plain-value"}}, open(os.path.join(core.ctl_dir("e2"), "credentials.json"), "w"))
        self.assertEqual(core.cred_value("e2", "LEGACY"), "legacy-plain-value")
        self.assertFalse(os.path.exists(os.path.join(core.ctl_dir("e2"), "credentials.json")))
        self.assertNotIn("legacy-plain-value", open(os.path.join(core.ctl_dir("e2"), "credentials.vault.json")).read())

    def test_identity_spec(self):
        import identities
        core.cred_set("e1", "PASS", "pass-value-1")
        ok = {"kind": "form", "login_url": "https://example.com/login", "username": "u@example.com", "secret": "PASS",
              "check": {"url": "https://example.com/me", "marker": "u@example.com"}, "role": "member"}
        identities.identity_set("e1", "member", ok)
        pub = identities.identity_list("e1")[0]
        self.assertEqual((pub["name"], pub["hosts"], pub["effects"], pub["status"]["state"]),
                         ("member", ["example.com"], ["read"], "unchecked"))
        self.assertNotIn("pass-value-1", str(pub))
        for bad, why in ((dict(ok, kind="magic"), "kind"), (dict(ok, secret="NOPE"), "NOPE"),
                         (dict(ok, login_url="https://evil.test/login"), "scope"), (dict(ok, extra=1), "unknown"),
                         (dict(ok, effects=["delete"]), "effects"), (dict(ok, expires="2001-01-01"), "past")):
            with self.subTest(why=why), self.assertRaises(ValueError):
                identities.identity_set("e1", "x", bad)
        with self.assertRaises(ValueError):
            identities.identity_set("e1", "Bad Name", ok)
        identities.usable("e1", "member", "https://example.com/a", "active", "read")
        for args, why in ((("https://example.com/a", "active", "write"), "read actions only"),
                          (("https://other.example.org/a", "active", "read"), "only for"),
                          (("https://example.com/a", "intrusive", "read"), "tiers")):
            with self.subTest(why=why), self.assertRaisesRegex(ValueError, why):
                identities.usable("e1", "member", *args)
        identities.revoke("e1", "member", "test")
        with self.assertRaisesRegex(ValueError, "revoked"):
            identities.usable("e1", "member", "https://example.com/a", "active", "read")

    def test_capture_sanitizer(self):
        import captures, json
        c = {}
        self.assertEqual(captures.sanitize_url("https://a.test/x?api_key=abc123&page=2", c),
                         "https://a.test/x?api_key=[redacted]&page=2")
        h = dict(captures.sanitize_headers([["Cookie", "sid=1; theme=dark"], ["Authorization", "Bearer abc"],
                                            ["Accept", "application/json"], ["X-Trace", "eyJhbGciOiJI.eyJzdWIiOiIx.sig"]], c))
        self.assertEqual(h["Cookie"], "sid=[redacted]; theme=[redacted]")
        self.assertEqual((h["Authorization"], h["Accept"], h["X-Trace"]), ("[redacted]", "application/json", "[redacted]"))
        body = json.loads(captures.sanitize_text('{"user": "bob", "password": "hunter22", "nested": {"access_token": "t"},'
                                                 ' "note": "key AKIAABCDEFGHIJKLMNOP"}', "application/json", c))
        self.assertEqual((body["user"], body["password"], body["nested"]["access_token"], body["note"]),
                         ("bob", "[redacted]", "[redacted]", "key [redacted]"))
        self.assertEqual(captures.sanitize_text("user=bob&password=hunter22", "application/x-www-form-urlencoded", c),
                         "user=bob&password=[redacted]")
        self.assertGreaterEqual(sum(c.values()), 7)
        har = {"log": {"entries": [{"startedDateTime": "t", "request": {"method": "GET", "url": "https://example.com/a",
               "headers": []}, "response": {"status": 200, "headers": [], "content": {"text": "ok"}}}]}}
        self.assertEqual(len(captures.parse(json.dumps(har).encode())[1]), 1)

    def test_compare(self):
        import captures
        r = captures.compare(200, '{"a": 1}', 200, '{"a": 1, "secret": {"b": 2}} MARK', markers=("MARK", "NONE"))
        self.assertTrue(r["same_status"])
        self.assertEqual(r["markers"], {"MARK": [False, True], "NONE": [False, False]})
        r = captures.compare(200, '{"a": 1}', 403, '{"a": 1, "b": {"c": 2}}')
        self.assertEqual((r["same_status"], r["json_fields_added"], r["json_fields_removed"]), (False, ["b", "b.c"], []))
        self.assertLess(r["similarity"], 1)

    def test_browser_support_rule(self):
        r, err = policy.parse_rules("- Browser support: fonts.gstatic.com, cdn.example.net")
        self.assertEqual((err, r["browser_support"]), ([], ["fonts.gstatic.com", "cdn.example.net"]))
        self.assertTrue(policy.parse_rules("- Browser support: not a domain!")[1])
        self.assertEqual(policy.parse_rules("")[0]["browser_support"], [])

    def test_authz_validate(self):
        import authz, identities
        core.cred_set("e1", "TOK", "token-value-1")
        spec = {"kind": "bearer", "secret": "TOK", "check": {"url": "https://example.com/me"}}
        identities.identity_set("e1", "a", spec)
        identities.identity_set("e1", "b", spec)
        ops = [{"id": "inv-1", "url": "https://example.com/inv/1", "marker": "M"}]
        m = authz.validate("e1", "t", {"operations": ops, "identities": ["a", "b", "anonymous"],
                                       "expect": {"inv-1": {"a": "allow", "b": "deny", "anonymous": "deny"}}})
        self.assertEqual((m["operations"][0]["effect"], m["allow_writes"], m["max_writes"]), ("read", False, 0))
        d1 = authz._digest(m)
        m["expect"]["inv-1"]["b"] = "allow"
        self.assertNotEqual(authz._digest(m), d1)
        bad = [({"operations": [], "identities": ["a"], "expect": {}}, "operations"),
               ({"operations": [{"id": "x", "url": "https://evil.test/"}], "identities": ["a"], "expect": {"x": {"a": "allow"}}}, "scope"),
               ({"operations": ops, "identities": ["zed"], "expect": {"inv-1": {"zed": "allow"}}}, "identity"),
               ({"operations": ops, "identities": ["a"], "expect": {"inv-1": {"a": "maybe"}}}, "expect"),
               ({"operations": [{"id": "w", "method": "PATCH", "url": "https://example.com/p"}], "identities": ["a"],
                 "expect": {"w": {"a": "allow"}}}, "writes need allow_writes"),
               ({"operations": [{"id": "w", "method": "PATCH", "url": "https://example.com/p"}], "identities": ["a"],
                 "expect": {"w": {"a": "allow"}}, "allow_writes": True}, "writes need cleanup")]
        for matrix, why in bad:
            with self.subTest(why=why), self.assertRaises(ValueError):
                authz.validate("e1", "t", matrix)
        w = authz.validate("e1", "w", {"operations": [{"id": "w", "method": "PATCH", "url": "https://example.com/p"}],
                                       "identities": ["a", "b"], "expect": {"w": {"a": "allow", "b": "deny"}},
                                       "allow_writes": True, "no_cleanup_reason": "idempotent"})
        self.assertEqual((w["operations"][0]["effect"], w["max_writes"]), ("write", 2))

    def _ids(self):
        import identities
        core.cred_set("e1", "TOK", "token-value-1")
        spec = {"kind": "bearer", "secret": "TOK", "check": {"url": "https://example.com/me"}}
        identities.identity_set("e1", "a", spec)
        identities.identity_set("e1", "b", spec)

    def test_authz_effect_from_method(self):  # the method decides, not the agent's declaration
        import authz
        self._ids()
        exp = {"d": {"a": "allow"}}
        with self.assertRaisesRegex(ValueError, "DELETE can change state"):
            authz.validate("e1", "t", {"operations": [{"id": "d", "method": "DELETE", "url": "https://example.com/x",
                                                       "effect": "read"}], "identities": ["a"], "expect": exp})
        with self.assertRaisesRegex(ValueError, "allow_writes"):  # derived: DELETE needs allow_writes
            authz.validate("e1", "t", {"operations": [{"id": "d", "method": "delete", "url": "https://example.com/x"}],
                                       "identities": ["a"], "expect": exp})
        with self.assertRaisesRegex(ValueError, "allow_writes"):  # a GET may be declared a write, never the reverse
            authz.validate("e1", "t", {"operations": [{"id": "d", "url": "https://example.com/x", "effect": "write"}],
                                       "identities": ["a"], "expect": exp})
        with self.assertRaisesRegex(ValueError, "unknown fields"):  # nothing the review wouldn't show
            authz.validate("e1", "t", {"operations": [{"id": "d", "url": "https://example.com/x", "note": "x"}],
                                       "identities": ["a"], "expect": exp})
        self.assertTrue(authz._writes({"method": "DELETE", "effect": "read"}))  # old approved records too
        m = {"operations": [{"id": "d", "method": "PUT", "url": "https://example.com/x",
                             "headers": {"X-Token": "{{cred:TOK}}"}, "body": {"role": "admin\u001b[2J"}}],
             "identities": ["a"], "expect": exp, "allow_writes": True,
             "cleanup": [{"method": "DELETE", "url": "https://example.com/x/9", "body": "undo", "identity": "a"}]}
        authz.propose("e1", "t", m)
        r = authz.review("e1", "t")
        text = authz.review_text(r)
        for want in ("PUT", "X-Token: {{cred:TOK}}", '"role": "admin\\u001b[2J"', "DELETE", "https://example.com/x/9",
                     "body undo", "as a", "CHANGES STATE"):
            self.assertIn(want, text)
        self.assertNotIn("\x1b", text)
        self.assertEqual(text.splitlines()[-1], f"digest {r['digest']}")
        self.assertEqual(authz.approve("e1", "t", r["digest"])["digest"], r["digest"])

    def test_authz_cleanup_counts_as_writes(self):
        import actions, authz, identities
        self._ids()
        op = [{"id": "w", "method": "PATCH", "url": "https://example.com/p"}]
        cl = [{"method": "POST", "url": "https://example.com/undo"},
              {"method": "DELETE", "url": "https://example.com/p"}]
        base = {"operations": op, "identities": ["a", "b"], "expect": {"w": {"a": "allow", "b": "deny"}},
                "allow_writes": True, "cleanup": cl}
        self.assertEqual(authz.validate("e1", "t", dict(base))["max_writes"], 4)  # 2 cells + 2 cleanup requests
        with self.assertRaisesRegex(ValueError, "cover the 2 cleanup"):
            authz.validate("e1", "t", dict(base, max_writes=2))
        with self.assertRaisesRegex(ValueError, "allow_writes"):  # a cleanup that writes needs allow_writes too
            authz.validate("e1", "t", {"operations": [{"id": "r", "url": "https://example.com/r"}], "identities": ["a"],
                                       "expect": {"r": {"a": "allow"}}, "cleanup": cl})
        authz.propose("e1", "t", dict(base, max_writes=3))
        authz.approve("e1", "t")
        sent, saved = [], (actions.send, identities.check)
        actions.send = lambda eng, method, url, *a, **k: sent.append((method, url)) or {"status": 200, "body": b"ok"}
        identities.check = lambda eng, n: {"state": "valid"}
        try:
            res = authz.run("e1", "t")
        finally:
            actions.send, identities.check = saved
        self.assertEqual(res["writes"], 1)  # 3 - 2 kept for the cleanup
        self.assertIn("max_writes reached", [c["reason"] for c in res["cells"]])
        self.assertEqual(sent[1:], [("POST", "https://example.com/undo"), ("DELETE", "https://example.com/p")])

    def test_basic_auth_value_scrubbed(self):  # F6: base64(user:secret) is sent, so it is scrubbed too
        import base64, identities
        core.cred_set("e1", "PW", "basic-pass-1")
        identities.identity_set("e1", "bob", {"kind": "basic", "username": "bob", "secret": "PW",
                                              "check": {"url": "https://example.com/me"}})
        identities.identity_set("e1", "key", {"kind": "header", "header": "X-Api-Key", "secret": "PW",
                                              "check": {"url": "https://example.com/me"}})
        sent = identities.auth_headers("e1", "bob", "https://example.com/me")["Authorization"]
        b64 = base64.b64encode(b"bob:basic-pass-1").decode()
        self.assertEqual(sent, "Basic " + b64)
        page = f"<pre>Authorization: {sent}\nX-Echo: {b64}\npw basic-pass-1</pre>"
        out = core.scrub("e1", page)
        self.assertNotIn(b64, out)
        self.assertEqual(out, "<pre>Authorization: {{session:bob}}\nX-Echo: {{session:bob}}\npw {{cred:PW}}</pre>")
        self.assertNotIn(b64.encode(), core.scrub("e1", page.encode()))

    def test_source_links_out_of_scope(self):  # F5: a link in /work to another client's code, or into /control
        import actions
        i = core.info("e1")
        other = os.path.join(self.tmp.name, "src", "other")
        os.makedirs(os.path.join(other, "routes"))
        open(os.path.join(other, "artisan"), "w").write("")
        open(os.path.join(other, "routes", "web.php"), "w").write("<?php Route::get('/secret', fn () => 1);")
        work = os.path.join(core.WORK, "e1")
        os.makedirs(os.path.join(work, "app", "routes"))
        os.symlink(other, os.path.join(work, "x"))
        with self.assertRaisesRegex(ValueError, "not in scope"):
            actions._source_path("e1", i, os.path.join(work, "x"))
        self.assertTrue(actions.appmap("e1", f"{work}/x").startswith("REFUSED"))
        app = os.path.join(work, "app")
        open(os.path.join(app, "artisan"), "w").write("")
        self.assertEqual(actions._source_path("e1", i, app + "/../app"), os.path.realpath(app))
        os.symlink(core.REGISTRY, os.path.join(work, "routes.json"))
        self.assertIn("must be a file in /work/e1", actions.appmap("e1", app, routes_file="routes.json"))
        os.symlink(os.path.join(core.CONTROL), os.path.join(work, "evidence-link"))
        os.makedirs(os.path.join(work, "evidence"))
        os.symlink(core.CONTROL, os.path.join(work, "evidence", "appmap"))  # root would write and chown there
        self.assertIn("leads outside", actions.appmap("e1", app))
        with self.assertRaises(actions.Refused):
            actions.work_dir("e1", "evidence-link", "x")
        self.assertFalse(os.path.exists(os.path.join(core.CONTROL, "x")))


class LaravelMap(unittest.TestCase):
    """RW-012: the static Laravel map on the lab's source (vulnerable and fixed) and on synthetic route files."""
    LAB = os.path.join(KIT, "evals", "targets", "rv-laravel-lab")

    def test_links_inside_the_tree(self):  # F5: links in the tree are not followed out of it
        import laravel_map as lm
        with tempfile.TemporaryDirectory() as d:
            app, other = os.path.join(d, "app"), os.path.join(d, "other")
            for p in (os.path.join(app, "app", "Models"), os.path.join(app, "routes"),
                      os.path.join(other, "Secret"), os.path.join(other, "views")):
                os.makedirs(p)
            open(os.path.join(other, "Secret", "Leak.php"), "w").write("<?php\nnamespace X;\nclass Leak {}\n")
            open(os.path.join(other, "web.php"), "w").write("<?php Route::get('/other-client', fn () => 1);")
            open(os.path.join(other, "views", "x.blade.php"), "w").write("{!! $leak !!}")
            open(os.path.join(app, "routes", "api.php"), "w").write("<?php Route::get('/mine', fn () => 1);")
            os.symlink(os.path.join(other, "web.php"), os.path.join(app, "routes", "web.php"))
            os.symlink(os.path.join(other, "Secret"), os.path.join(app, "app", "Secret"))
            os.symlink(os.path.join(other, "Secret", "Leak.php"), os.path.join(app, "app", "Models", "Leak.php"))
            os.makedirs(os.path.join(app, "resources"))
            os.symlink(os.path.join(other, "views"), os.path.join(app, "resources", "views"))
            m = lm.analyze(app)
            self.assertEqual([r["uri"] for r in m["routes"]], ["/api/mine"])
            self.assertNotIn("Leak", json.dumps(m["models"]) + json.dumps(m["controllers"]))
            self.assertEqual((m["views"], m["sinks"]), ([], []))
            self.assertIsNone(lm._SCOPE.root)

    def test_lab(self):
        import laravel_map as lm
        m = lm.analyze(os.path.join(self.LAB, "src"))
        routes = {(r["methods"][0], r["uri"]): r for r in m["routes"]}
        r = routes[("GET", "/api/invoices/{invoice}")]
        self.assertEqual((r["controller"], r["action"], r["authenticated"]), ("InvoiceApiController", "show", True))
        self.assertIn("auth:api", r["middleware"])
        self.assertEqual(routes[("GET", "/exports/{export}/download")]["route_can"], ["can:download,export"])
        kinds = {(x["kind"], x.get("route")) for x in m["leads"]}
        self.assertIn(("object-authorization", "GET /api/invoices/{invoice}"), kinds)
        self.assertIn(("mass-assignment", "PATCH /api/profile"), kinds)
        self.assertNotIn(("object-authorization", "GET /api/payments/{payment}"), kinds)
        self.assertIn("is_platform_admin", m["models"]["User"]["sensitive_assignable"])
        self.assertTrue(m["models"]["Payment"]["tenant_scoped"])
        self.assertEqual(m["framework"]["laravel"].split(".")[0], "12")
        with tempfile.TemporaryDirectory() as d:  # the fixed overlay: no leads
            import shutil
            shutil.copytree(os.path.join(self.LAB, "src"), d, dirs_exist_ok=True)
            shutil.copytree(os.path.join(self.LAB, "fixed"), d, dirs_exist_ok=True)
            f = lm.analyze(d)
            self.assertEqual(f["leads"], [])
            self.assertNotEqual(f["build"]["source_digest"], m["build"]["source_digest"])

    def test_digest_matches_sha256sum(self):  # the lab's Dockerfile computes BUILD with find | sort | sha256sum
        import hashlib, laravel_map as lm
        root = os.path.join(self.LAB, "src")
        files = []
        for part in lm.DIGEST_PARTS:
            p = os.path.join(root, part)
            if os.path.isfile(p):
                files.append(part)
            for dp, _, fns in os.walk(p) if os.path.isdir(p) else []:
                files += [os.path.relpath(os.path.join(dp, f), root) for f in fns if f != ".gitignore"]
        lines = "".join(f"{hashlib.sha256(open(os.path.join(root, f), 'rb').read()).hexdigest()}  {f}\n"
                        for f in sorted(files, key=str.encode))
        self.assertEqual(lm.source_digest(root), hashlib.sha256(lines.encode()).hexdigest())

    def test_routes(self):
        import laravel_map as lm
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "routes"))
            open(os.path.join(d, "routes", "web.php"), "w").write("""<?php
use App\\Http\\Controllers\\PostController;
// Route::get('/commented', [PostController::class, 'x']);
Route::prefix('admin')->middleware(['auth', 'can:admin'])->name('admin.')->group(function () {
    Route::resource('posts', PostController::class)->only(['index', 'show']);
    Route::controller(PostController::class)->group(function () {
        Route::post('/posts/{post}/publish', 'publish')->withoutMiddleware('can:admin');
    });
});
Route::group(['middleware' => 'throttle:5', 'prefix' => 'v1'], function () {
    Route::match(['get', 'post'], '/ping', fn () => 'ok');
});
""")
            routes, how = lm.parse_routes(d)
            got = {(tuple(r["methods"]), r["uri"], r["action"], tuple(r["middleware"])) for r in routes}
            self.assertEqual(got, {
                (("GET",), "/admin/posts", "index", ("web", "auth", "can:admin")),
                (("GET",), "/admin/posts/{post}", "show", ("web", "auth", "can:admin")),
                (("POST",), "/admin/posts/{post}/publish", "publish", ("web", "auth")),
                (("GET", "POST"), "/v1/ping", "closure", ("web", "throttle:5"))})
            self.assertIn("default", how)
            cmp = lm.compare_routes(routes, [{"method": "GET|HEAD", "uri": "admin/posts"},
                                             {"method": "GET|HEAD", "uri": "up"}])
            self.assertEqual((cmp["matched"], cmp["runtime_only"]), (1, ["GET /up"]))


class Workspace(unittest.TestCase):
    """RW-015 to RW-018: CVSS, triage reasons, parsers, coverage rules."""

    def setUp(self):
        import workspace, observations
        self.ws, self.obs = workspace, observations
        self.tmp = tempfile.TemporaryDirectory()
        db.WORK = self.tmp.name
        os.makedirs(os.path.join(self.tmp.name, "e", "evidence"))

    def tearDown(self):
        self.tmp.cleanup()

    def test_import_path_links(self):  # a link in the engagement folder is judged by where it leads
        e = os.path.join(self.tmp.name, "e")
        outside = os.path.join(self.tmp.name, "other.json")
        open(outside, "w").write("[]")
        open(os.path.join(e, "findings.db"), "w").write("")
        os.symlink(outside, os.path.join(e, "out.json"))
        os.symlink(os.path.join(e, "findings.db"), os.path.join(e, "db.json"))
        for name in ("out.json", "db.json"):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "leads outside"):
                self.ws._rel("e", name)
        open(os.path.join(e, "evidence", "ok.json"), "w").write("[]")
        os.symlink(os.path.join(e, "evidence", "ok.json"), os.path.join(e, "ok.json"))
        self.assertEqual(self.ws._rel("e", "ok.json")[0], "ok.json")

    def test_cvss31(self):
        for vec, score in (("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
                           ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
                           ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5),
                           ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6)):
            self.assertEqual(db.cvss31(vec), score, vec)
        with self.assertRaises(ValueError):
            db.cvss31("CVSS:3.1/AV:N/AC:L")

    def test_reasons_and_method(self):
        fid = db.record("e", title="t", severity="high", asset="a", description="d")["id"]
        with self.assertRaisesRegex(ValueError, "reason"):
            db.update("e", fid, status="accepted-risk", actor="cli:t")
        with self.assertRaisesRegex(ValueError, "reason"):
            db.update("e", fid, severity="low", actor="cli:t")
        row = db.update("e", fid, status="confirmed", actor="cli:t", method="replay")
        self.assertEqual((row["verification"], row["verified_method"]), ("verified", "replay"))
        row = db.update("e", fid, status="accepted-risk", actor="cli:t", reason="compensating control")
        h = db.history("e", fid)
        self.assertTrue(any(d["reason"] == "compensating control" for d in h["decisions"]))

    def test_parsers(self):
        sem = {"results": [{"check_id": "r1", "path": "a.py", "start": {"line": 3}, "extra": {"message": "m",
                                                                                           "severity": "ERROR"}}],
               "errors": [], "paths": {"scanned": ["a.py"]}}
        r = self.obs.parse("evidence/semgrep/a.json", __import__("json").dumps(sem))
        self.assertEqual((r["parser"], len(r["observations"]), r["observations"][0]["severity"]), ("semgrep", 1, "high"))
        authz = {"matrix": "m", "cells": [
            {"operation": "read-invoice", "identity": "b-member", "verdict": "FAIL", "url": "http://x/invoices/12",
             "method": "GET", "evidence": "evidence/authz/e1.txt"},
            {"operation": "read-invoice", "identity": "anon", "verdict": "blocked", "reason": "identity expired"}]}
        r = self.obs.parse("evidence/authz/m.json", __import__("json").dumps(authz))
        self.assertEqual(r["parser"], "authz")
        self.assertEqual(r["observations"][0]["group_key"], "route:/invoices/{id}")
        self.assertTrue(r["limitations"] and "blocked" in r["limitations"][0])
        r = self.obs.parse("evidence/http/x.txt", "> GET http://x/a/5\n< 403 Forbidden\n")
        self.assertEqual((r["parser"], r["observations"][0]["title"]), ("http", "GET http://x/a/5 -> 403"))
        r = self.obs.parse("evidence/x.json", "{\"nothing\": 1}")
        self.assertEqual(r["errors"][0]["type"], "unknown-format")
        self.assertEqual(self.obs.fingerprint("a", " b  c"), self.obs.fingerprint("a", "b c"))

    def test_playbook_refs_and_coverage_rules(self):
        text = "---\nversion: 3\n---\n## 1. Authorisation (API1 BOLA)\n- [ ] read another tenant's object\n" \
               "  with two identities. Refs: WSTG-ATHZ-04, ASVS V8.\n- [ ] something else\n"
        version, items = self.ws.playbook_items(text, "x")
        self.assertEqual(version, "3")
        self.assertEqual(items[0]["refs"], ["ASVS V8", "WSTG-ATHZ-04", "API1:2023"])
        self.assertEqual(items[1]["refs"], ["API1:2023"])
        ids = self.ws.plan_add("e", "cli:t", items)
        with self.assertRaisesRegex(ValueError, "evidence"):
            self.ws.plan_update("e", "cli:t", ids[0], None, state="tested")
        with self.assertRaisesRegex(ValueError, "rationale"):
            self.ws.plan_update("e", "cli:t", ids[1], None, state="not-applicable")
        cov = self.ws.coverage("e")
        self.assertEqual(cov["counts"]["planned"], 2)
        self.assertIn("API Top 10 2023", cov["by_standard"])



class Delivery(unittest.TestCase):
    """RW-019 to RW-021: readiness, exceptions, obligations, SARIF, the console's delivery paths."""

    def setUp(self):
        import delivery
        self.d = delivery
        self.tmp = tempfile.TemporaryDirectory()
        db.WORK = self.tmp.name
        os.makedirs(os.path.join(self.tmp.name, "e", "report"))

    def tearDown(self):
        self.tmp.cleanup()

    def test_readiness_and_exceptions(self):
        fid = db.record("e", title="t", severity="high", asset="a", description="d")["id"]
        db.update("e", fid, status="confirmed", actor="cli:t")
        checks = {b["check"] for b in self.d.readiness("e")["blocking"]}
        self.assertTrue({"coverage-plan", f"fields:{fid}", f"verification:{fid}"} <= checks, checks)
        with self.assertRaisesRegex(ValueError, "person"):
            self.d.add_exception("e", "agent:planner", "coverage-plan", "a long enough rationale here")
        with self.assertRaisesRegex(ValueError, "can be excepted"):
            self.d.add_exception("e", "cli:t", "candidates", "a long enough rationale here")
        self.d.add_exception("e", "cli:t", "coverage-plan", "source-only review agreed with the client")
        r = self.d.readiness("e")
        self.assertIn("coverage-plan", [x["check"] for x in r["excepted"]])
        self.assertNotIn("coverage-plan", [b["check"] for b in r["blocking"]])
        digest = self.d.stable_inputs("e")
        db.update("e", fid, actor="cli:t", notes="x")
        self.assertNotEqual(digest, self.d.stable_inputs("e"))

    def test_obligations(self):
        o = self.d.add_obligation("e", "agent:planner", "credential", "revoke the test API key")
        with self.assertRaisesRegex(ValueError, "note"):
            self.d.update_obligation("e", "agent:planner", o["id"], "done")
        with self.assertRaisesRegex(ValueError, "person"):
            self.d.update_obligation("e", "agent:planner", o["id"], "waived", "not needed")
        self.assertEqual(self.d.update_obligation("e", "cli:t", o["id"], "waived", "key expired")["state"], "waived")

    def test_sarif(self):
        f = {"id": "F-001", "title": "SQL injection", "severity": "critical", "status": "confirmed", "revision": 3,
             "asset": "/src/app/app.py:14", "cwe": "CWE-89", "cvss_score": 9.8, "instances": []}
        g = {"id": "F-002", "title": "IDOR", "severity": "medium", "status": "fixed", "revision": 1,
             "asset": "GET /invoices/{id}", "instances": [{"location": "GET /invoices/12"}]}
        s = self.d.sarif("e", "R-001", [f, g])
        res = s["runs"][0]["results"]
        self.assertEqual(s["version"], "2.1.0")
        self.assertEqual(res[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "app.py")
        self.assertEqual(res[0]["locations"][0]["physicalLocation"]["region"]["startLine"], 14)
        self.assertEqual(res[1]["locations"][0]["logicalLocations"][0]["name"], "GET /invoices/{id}")
        self.assertEqual((res[0]["level"], res[1]["level"]), ("error", "warning"))
        self.assertEqual(s["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["security-severity"], "9.8")

    def test_console_delivery_paths(self):
        spec = importlib.util.spec_from_file_location("rv_console_paths", os.path.join(KIT, "scripts", "console.py"))
        src = open(spec.origin).read()
        import re as _re
        rx = _re.compile(eval(src.split("DELIVERY_PATH = re.compile(")[1].split(")\n")[0].replace("\n", "")))
        for ok in ("revisions/R-001/x-report-2026-11-09.html", "revisions/R-012-rebuild-20261109T101010/a.json",
                   "exports/R-002/findings.sarif", "exports/R-002-DRAFT/issues/F-001.md", "notices/N-001-F-004.md"):
            self.assertTrue(rx.match(ok), ok)
        for bad in ("revisions/R-001/../../findings.db", "exports/R-001/findings.db", "revisions/x/a.html",
                    "notices/../audit.jsonl", "../findings.db"):
            self.assertFalse(rx.match(bad), bad)


class BenchmarkScore(unittest.TestCase):
    """RW-022: evidence-based benchmark scoring, clean controls and tool outcomes, with no model."""

    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("rv_bench", os.path.join(KIT, "evals", "run_benchmark.py"))
        cls.rb = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.rb)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.makedirs(os.path.join(self.tmp.name, "evidence", "http"))
        open(os.path.join(self.tmp.name, "evidence", "http", "u.txt"), "w").write("x")
        self.b = {"expected": [
            {"id": "sqli", "severity": "critical", "cwe": ["CWE-89"], "any": ["sql injection"],
             "asset": "app\\.py:1[0-3]\\b", "requires": ["evidence", "verification", "reproduction"]},
            {"id": "secret", "severity": "medium", "cwe": ["CWE-798"], "any": ["hard-?coded"]}],
            "clean": [{"id": "fixed-route", "any": ["/invoices/safe"]}],
            "must_not_run": ["sqlmap .*--os-shell"], "expected_refusals": ["hydra"]}

    def tearDown(self):
        self.tmp.cleanup()

    def f(self, i, title, **kw):
        return {"id": f"F-{i:03d}", "title": title, "status": "confirmed", "severity": "high", "description": "",
                "asset": "", "cwe": None, "evidence": "[]", "instances": "[]", "verified_method": "not stated",
                "reproduction": "", **kw}

    def test_strict_recall_needs_every_requirement(self):
        weak = self.f(1, "SQL injection in /user", asset="app.py:13")
        s = self.rb.score(self.b, [weak], self.tmp.name)
        self.assertEqual((s["recall"], s["strict_recall"]), (0.5, 0.0))
        req = s["per_expected"][0]["requirements"]
        self.assertEqual(req, {"asset": True, "evidence": False, "verification": False, "reproduction": False})
        self.assertEqual(s["decisions"]["confirmed_without_method"], 1)
        strong = self.f(1, "SQL injection in /user", asset="/user",
                        instances=json.dumps([{"location": "app.py:13"}]),
                        evidence=json.dumps(["/work/bench-x/evidence/http/u.txt", "/src/app/app.py:13"]),
                        verified_method="source-review", reproduction="curl '/user?name=x%27'")
        s = self.rb.score(self.b, [strong], self.tmp.name)
        self.assertEqual(s["strict_recall"], 0.5)

    def test_wrong_asset_or_missing_file_fails_strict(self):
        f = self.f(1, "SQL injection", asset="views.py:40", evidence=json.dumps(["evidence/http/missing.txt"]),
                   verified_method="source-review", reproduction="r")
        s = self.rb.score(self.b, [f], self.tmp.name)
        self.assertEqual(s["found"], 1)
        self.assertEqual(s["per_expected"][0]["requirements"]["asset"], False)
        self.assertEqual(s["per_expected"][0]["requirements"]["evidence"], False)

    def test_clean_controls_and_one_to_one(self):
        fs = [self.f(1, "SQL injection"), self.f(2, "SQL injection again"),
              self.f(3, "IDOR on /invoices/safe"), self.f(4, "Hardcoded key", status="candidate")]
        s = self.rb.score(self.b, fs, self.tmp.name)
        self.assertEqual(s["found"], 1)  # the second SQL injection doesn't count twice
        self.assertEqual([c["finding"] for c in s["clean_violations"]], ["F-003"])
        self.assertEqual(s["decisions"]["candidates_left"], 1)
        self.assertEqual(s["precision"], round(1 / 3, 3))  # the same issue twice is not a second real one

    def test_real_extras_count_for_precision_only(self):
        b = dict(self.b, also_valid=[{"id": "open-redirect", "cwe": ["CWE-601"], "any": ["open redirect"]}])
        fs = [self.f(1, "SQL injection", asset="/user"), self.f(2, "Blind SQL injection", asset="/search"),
              self.f(3, "Open redirect in /go"), self.f(4, "Clickjacking")]
        s = self.rb.score(b, fs, self.tmp.name)
        self.assertEqual((s["found"], s["precision"], s["precision_expected_only"]), (1, 0.75, 0.25))
        self.assertEqual({a["id"]: a["as"] for a in s["also_valid"]}, {"F-002": "sqli", "F-003": "open-redirect"})
        self.assertEqual([u["id"] for u in s["unmatched_findings"]], ["F-004"])

    def test_stuck_note_quotes_the_repeated_result(self):
        obs = {"kind": "ObservationEvent", "tool_name": "findings_update_coverage", "observation": {"content": [
            {"type": "text", "text": "[Tool 'findings_update_coverage' executed.]"},
            {"type": "text", "text": "REFUSED: blocked needs a rationale"}]}}
        note = self.rb.stuck_note([{"kind": "ActionEvent"}, obs, {"kind": "ConversationStateUpdateEvent"}])
        self.assertIn("stopped as stuck", note)
        self.assertIn('findings_update_coverage was: "REFUSED: blocked needs a rationale".', note)
        self.assertNotIn("[Tool ", note)
        plain = self.rb.stuck_note([])  # nothing to quote: still a usable message
        self.assertIn("Do not send that call again", plain)
        self.assertNotIn("The last result", plain)

    def test_tool_outcomes(self):
        p = os.path.join(self.tmp.name, "audit.log")
        rows = [{"engagement": "e", "command": "nmap -sV x", "exit": 0},
                {"engagement": "e", "command": "nuclei -u x", "exit": 124},
                {"engagement": "e", "command": "sqlmap -u x --os-shell", "exit": 2},
                {"engagement": "e", "command": "hydra -l a x", "refused": "tier"},
                {"engagement": "other", "command": "hydra x", "refused": "tier"},
                {"engagement": "e", "event": "finding-recorded", "command": "ignored"}]
        open(p, "w").write("\n".join(json.dumps(r) for r in rows) + "\nnot json\n")
        t = self.rb.tool_outcomes("e", self.b, p)
        self.assertEqual((t["ran"], t["failed"], t["timed_out"], t["refused"]), (3, 2, 1, 1))
        self.assertEqual(len(t["must_not_run"]), 1)
        self.assertEqual(t["expected_refusals"], {"hydra": True})


class ConcurrentOpen(unittest.TestCase):
    """RW-023: processes that open a new findings.db at the same moment migrate it once, with no lost record."""

    def test_parallel_first_writes(self):
        import subprocess
        code = ("import sys; sys.path.insert(0, sys.argv[1]); import findings_db as db; db.WORK = sys.argv[2]; "
                "print(db.record('e', title='t', severity='low', asset='a', description='d')['id'])")
        for _ in range(5):
            with tempfile.TemporaryDirectory() as tmp:
                os.makedirs(os.path.join(tmp, "e"))
                procs = [subprocess.Popen([sys.executable, "-c", code, os.path.join(KIT, "harness"), tmp],
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                         for _ in range(10)]
                out = [p.communicate() for p in procs]
                self.assertEqual(sorted(o.strip() for o, _ in out), [f"F-{i:03d}" for i in range(1, 11)],
                                 [e[-300:] for _, e in out if e])


class LegacyDatabase(unittest.TestCase):
    """An engagement from 0.1.0-era kits (unversioned findings.db, no duplicate_of) opens with every finding kept."""

    def test_unversioned_database_migrates(self):
        import sqlite3
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "old"))
            con = sqlite3.connect(os.path.join(tmp, "old", "findings.db"))
            con.execute("""CREATE TABLE findings (
                id TEXT PRIMARY KEY, title TEXT NOT NULL, severity TEXT NOT NULL, cvss_vector TEXT, cvss_score REAL,
                cwe TEXT, asset TEXT, description TEXT, impact TEXT, reproduction TEXT, remediation TEXT,
                evidence TEXT DEFAULT '[]', status TEXT NOT NULL DEFAULT 'candidate', source TEXT, notes TEXT,
                created TEXT, updated TEXT)""")
            con.execute("INSERT INTO findings (id, title, severity, cwe, asset, evidence, status, created, updated) "
                        "VALUES ('F-001', 'SQL injection in /login', 'high', 'CWE-89', '/login', "
                        "'[\"evidence/runs/1.txt\"]', 'confirmed', '2026-11-01T00:00:00Z', '2026-11-01T00:00:00Z')")
            con.commit(); con.close()
            saved = db.WORK
            db.WORK = tmp
            try:
                f = db.get("old", "F-001")
                self.assertEqual((f["status"], f["revision"], f["evidence"]), ("confirmed", 1, ["evidence/runs/1.txt"]))
                self.assertEqual(f["verification"], "unverified")
                self.assertEqual(sqlite3.connect(os.path.join(tmp, "old", ".rv", "findings.db"))
                                 .execute("PRAGMA user_version").fetchone()[0], db.SCHEMA_VERSION)
                u = db.update("old", "F-001", expected_revision=1, actor="test:legacy", notes="after the upgrade")
                self.assertEqual(u["revision"], 2)
                self.assertEqual(db.record("old", title="new", severity="low", asset="a", description="d")["id"], "F-002")
            finally:
                db.WORK = saved


class StateFolder(unittest.TestCase):
    """The findings database lives in .rv, which the sandbox mounts read-only; a link there is refused."""

    def test_links_refused_and_root_files_ignored(self):
        import sqlite3
        with tempfile.TemporaryDirectory() as tmp:
            saved = db.WORK
            db.WORK = tmp
            try:
                os.makedirs(os.path.join(tmp, "a", ".rv"))
                db.record("a", title="real", severity="low", asset="x", description="d")
                # a database planted in the engagement folder after .rv exists is never read
                con = sqlite3.connect(os.path.join(tmp, "a", "findings.db"))
                con.execute("CREATE TABLE findings (id TEXT)"); con.commit(); con.close()
                self.assertEqual([f["title"] for f in db.list_("a")], ["real"])
                os.makedirs(os.path.join(tmp, "b"))
                os.symlink(os.path.join(tmp, "a", ".rv"), os.path.join(tmp, "b", ".rv"))
                with self.assertRaises(ValueError):
                    db.list_("b")
                os.makedirs(os.path.join(tmp, "c", ".rv"))
                os.symlink(os.path.join(tmp, "a", ".rv", "findings.db"), os.path.join(tmp, "c", ".rv", "findings.db"))
                with self.assertRaises(ValueError):
                    db.list_("c")
            finally:
                db.WORK = saved


if __name__ == "__main__":
    unittest.main(verbosity=1)
