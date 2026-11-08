"""Fast checks that need no Docker, no model and no network: tier classification (tiers.yaml), rate caps, scope and rules
parsing, the scope pre-check, the findings database, the web-fetch guard and the console's request checks.
They run on every pull request in about a second. The full stack is tested by the Integration workflow.
Run: python3 evals/unit_test.py
"""
import importlib.util, os, sys, tempfile, unittest

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [os.path.join(KIT, "kali-mcp"), os.path.join(KIT, "harness"), os.path.join(KIT, "scripts")]
import core  # noqa: E402
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
        sc = core.parse_scope("""
- https://app.example.com/login   # a URL keeps only the host
- *.example.io
- 203.0.113.0/28
- 10.0.0.5:8080
- /src/repo
- /etc/passwd
- 127.0.0.1
- 169.254.169.254
- ::1
- not a host!
""")
        self.assertEqual(sc["domains"], ["app.example.com", "example.io"])
        self.assertEqual(sc["nets"], ["203.0.113.0/28", "10.0.0.5/32"])
        self.assertEqual(sc["paths"], ["/src/repo"])
        self.assertEqual(len(sc["warnings"]), 5)

    def test_parse_rules(self):
        r = core.parse_rules("- Allowed tiers: passive, intrusive\n- Max rate: 20/s\n- Network: offline\n"
                             "- Worker: private\n- Window: 22:00-06:00 UTC")
        self.assertEqual((r["tiers"], r["max_rate"], r["network"], r["worker"], r["window"]),
                         (["passive", "intrusive"], 20, "offline", "private", [22, 0, 6, 0]))
        self.assertEqual(core.parse_rules("- Allowed tiers: everything")["tiers"], ["passive"])
        self.assertEqual(core.parse_rules("")["tiers"], ["passive", "active"])

    def test_precheck(self):
        info = {"scope": core.parse_scope("- example.com\n- 10.0.0.0/24"), "infra_domains": ["searxng"]}
        self.assertEqual(core.precheck("nmap 10.0.0.7 app.example.com", info), [])
        self.assertEqual(core.precheck("nmap 10.0.1.7 evil.test", info), ["10.0.1.7", "evil.test"])
        self.assertEqual(core.precheck("grep evil.test notes.txt", info), [])  # not a network tool
        self.assertEqual(core.precheck("curl http://10.0.0.1/login.php", info), [])

    def test_names(self):
        self.assertTrue(core._name_ok("acme-2026.11_a"))
        for bad in ("", "-x", "../x", "a/b", "x" * 65):
            self.assertFalse(core._name_ok(bad), bad)


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


class WebFetch(unittest.TestCase):
    def test_refusal(self):
        self.assertTrue(webfetch.refusal("http://127.0.0.1/", [], []).startswith("REFUSED"))
        self.assertTrue(webfetch.refusal("https://app.example.com/x", [], ["example.com"]).startswith("REFUSED"))
        self.assertEqual(webfetch.refusal("file:///etc/passwd", [], []), "only http(s) URLs")


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
