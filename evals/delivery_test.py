"""Delivery and retests (RW-019 to RW-021) against the running stack, with no model: report revisions with frozen
inputs and hashes, readiness checks and attributable exceptions, human approval that refuses a changed record,
supersession, integrity and rebuild, retests that keep the finding's history, cleanup obligations, reviewed
notices, and JSON/SARIF exports tied to the approved finding revisions. Uses a throwaway engagement
(rv-delivery-test) that is deleted afterwards.
Needs the stack up (./rvkit up). Run: python3 evals/delivery_test.py
"""
import json, os, subprocess, sys

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENG = "rv-delivery-test"
CLI, AGENT = "cli:delivery-test", "agent:planner"
results = []


def check(name, ok, detail=""):
    results.append(bool(ok))
    print(("PASS  " if ok else "FAIL  ") + name + ("" if ok else f"\n      {str(detail)[:400]}"))


def sh(*args, stdin=None, timeout=600):
    return subprocess.run(args, cwd=KIT, capture_output=True, text=True, input=stdin, timeout=timeout)


def ops(name, actor=CLI, **req):
    r = sh("docker", "compose", "exec", "-T", "findings-mcp", "python3", "ops.py", name,
           stdin=json.dumps({"engagement": ENG, "actor": actor, **req}))
    try:
        d = json.loads(r.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return None, (r.stdout + r.stderr)[-400:]
    return (None, d["error"]) if "error" in d else (d["result"], None)


def fx(cmd):
    """A shell command in findings-mcp (it owns the report files)."""
    return sh("docker", "compose", "exec", "-T", "findings-mcp", "sh", "-c", cmd)


def put(rel, text):
    return sh("docker", "compose", "exec", "-T", "kali-mcp", "sh", "-c",
              f"mkdir -p \"$(dirname /work/{ENG}/{rel})\" && cat > /work/{ENG}/{rel}", stdin=text)


def tool(expr):
    r = sh("docker", "compose", "exec", "-T", "findings-mcp", "python3", "-c", f"import findings; print({expr})")
    return r.stdout.strip() or r.stderr[-300:]


def cleanup():
    sh("docker", "compose", "exec", "-T", "kali-mcp", "python3", "/opt/kali-mcp/rvctl.py", "delete", ENG, "--force")
    sh("docker", "compose", "exec", "-T", "kali-mcp", "sh", "-c", f"rm -rf /work/_deleted-{ENG}-*")


def main():
    cleanup()
    r = sh("./rvkit", "engagement", ENG, "--tiers", "passive", "198.51.100.40")
    if r.returncode:
        print("FAIL  could not create the engagement\n" + (r.stdout + r.stderr)[-400:]); return 1
    try:
        return run()
    finally:
        cleanup()


FULL = {"asset": "/src/shop/app/Http/Controllers/InvoiceController.php:41", "description": "Invoices are read by id "
        "without checking the tenant.", "impact": "Any customer reads other customers' invoices.",
        "reproduction": "GET /invoices/12 as a member of another tenant.", "remediation": "Scope the query to the "
        "tenant (a global scope or a policy).", "evidence": ["/src/shop/app/Http/Controllers/InvoiceController.php:41"]}


def run():
    put("report/meta.txt", "Client: Delivery Test Ltd\nPrepared by: RiskVoid\nVersion: 1.0\n")
    put("report/executive-summary.md", "One critical authorization flaw lets customers read each other's invoices.\n")
    f1, err = ops("finding.record", fields={"title": "Cross-tenant invoice read", "severity": "critical",
                                            "cwe": "CWE-639", **FULL})
    ops("finding.update", id="F-001", fields={"status": "confirmed", "priority": "P1"}, method="authorization-matrix")
    f2, _ = ops("finding.record", fields={"title": "Debug mode on staging", "severity": "high", "asset": "/_ignition",
                                          "description": "The error page shows the environment.",
                                          "evidence": ["/src/shop/.env.staging:3"]})
    ops("finding.update", id="F-002", fields={"status": "confirmed"}, method="runtime-reproduction")

    print("== readiness and exceptions (RW-019)")
    r1, err = ops("report.build")
    blocking = [b["check"] for b in (r1 or {}).get("readiness", {}).get("blocking", [])]
    check("R-001 generated, not ready: no coverage plan, F-002 missing fields",
          r1 and r1["id"] == "R-001" and r1["state"] == "generated" and "coverage-plan" in blocking
          and "fields:F-002" in blocking, r1 or err)
    check("the document says DRAFT while something blocks delivery", r1 and r1["report"]["status"] == "DRAFT", r1)
    _, err = ops("report.approve", revision="R-001")
    check("a revision that isn't ready can't be approved", err and "only a ready revision" in err, err)
    _, err = ops("report.exception", actor=AGENT, check="coverage-plan", rationale="the agent thinks it's fine")
    check("the agent can't record an exception", err and "person" in err, err)
    _, err = ops("report.exception", check="summary", rationale="we will write it later, honestly")
    check("facts (summary, candidates, evidence, client) can't be excepted", err and "not a check" in err, err)
    _, err = ops("report.exception", check="coverage-plan", rationale="short")
    check("an exception needs its rationale", err and "rationale" in err, err)
    x, err = ops("report.exception", check="coverage-plan",
                 rationale="Source-only review agreed in the kickoff on 3 Nov; no test plan was requested.")
    check("exception recorded with its rationale", x and x["check_key"] == "coverage-plan", x or err)
    ops("finding.update", id="F-002", fields={"impact": "Leaks configuration and secrets to anyone.",
                                              "reproduction": "Request a missing route.", "remediation": "APP_DEBUG=false."})
    r2, err = ops("report.build")
    check("R-002 is ready: nothing blocks, the exception is listed",
          r2 and r2["state"] == "ready" and r2["readiness"]["excepted"][0]["check"] == "coverage-plan"
          and r2["report"]["status"] == "final", r2 or err)
    ls = fx(f"ls /work/{ENG}/report/revisions/R-001 /work/{ENG}/report/revisions/R-002").stdout
    check("earlier revisions keep their files (same day)", ls.count("inputs.json") == 2 and ls.count(".html") == 2, ls)

    print("== approval (RW-019)")
    _, err = ops("report.approve", actor=AGENT, revision="R-002")
    check("the agent can't approve a report", err and "person" in err, err)
    ops("finding.update", id="F-002", fields={"notes": "changed after generation"})
    _, err = ops("report.approve", revision="R-002")
    check("approval refused when the record changed since generation", err and "changed since" in err, err)
    r3, _ = ops("report.build")
    _, err = ops("report.approve", revision="R-002")
    check("only the latest revision can be approved", err and "latest" in err, err)
    a3, err = ops("report.approve", revision="R-003", note="read every finding and the evidence index")
    check("R-003 approved by a person, with the note", a3 and a3["state"] == "approved" and a3["approved_by"] == CLI,
          a3 or err)
    r4, _ = ops("report.build")
    a4, err = ops("report.approve", revision="R-004")
    revs = {r["id"]: r for r in (ops("report.revisions")[0] or {}).get("revisions", [])}
    check("a later approval supersedes the earlier one", revs.get("R-003", {}).get("state") == "superseded"
          and revs["R-003"]["superseded_by"] == "R-004" and revs["R-004"]["state"] == "approved", revs)
    _, err = ops("report.transmitted", revision="R-001", to="client", channel="email")
    check("sending can only be recorded for an approved revision", err and "approved" in err, err)
    t, err = ops("report.transmitted", revision="R-004", to="client security lead", channel="client portal")
    check("sending recorded, separate from approval", t and t["transmissions"][0]["channel"] == "client portal",
          t or err)

    print("== integrity and rebuild")
    v, err = ops("report.verify", revision="R-004")
    check("approved revision's files match their hashes", v and not v["problems"] and v["files"] >= 5, v or err)
    fx(f"for f in /work/{ENG}/report/revisions/R-001/*.html; do chmod u+w \"$f\" && echo x >> \"$f\"; done")
    v, _ = ops("report.verify", revision="R-001")
    check("a modified revision file is detected", v and any("modified" in p for p in v["problems"]), v)
    rb, err = ops("report.rebuild", revision="R-004")
    check("rebuilt from the frozen inputs: identical HTML", rb and rb["html_identical"], rb or err)

    print("== exports and notices (RW-021)")
    ex, err = ops("export.build")
    check("export from the approved revision", ex and ex["revision"] == "R-004" and ex["state"] == "approved"
          and {"findings.json", "findings.sarif", "issues/F-001.md"} <= set(ex["files"]), ex or err)
    js = json.loads(fx(f"cat /work/{ENG}/report/exports/R-004/findings.json").stdout or "{}")
    check("JSON names the report revision and each finding revision",
          js.get("report_revision") == "R-004" and all("revision" in f for f in js.get("findings", [])), js)
    sar = json.loads(fx(f"cat /work/{ENG}/report/exports/R-004/findings.sarif").stdout or "{}")
    res = (sar.get("runs") or [{}])[0].get("results", [])
    loc = res[0]["locations"][0] if res else {}
    check("SARIF 2.1.0 with a source location for code findings",
          sar.get("version") == "2.1.0" and len(res) == 2 and
          loc.get("physicalLocation", {}).get("artifactLocation", {}).get("uri") ==
          "app/Http/Controllers/InvoiceController.php" and loc["physicalLocation"]["region"]["startLine"] == 41, sar)
    check("SARIF levels and revisions", res and res[0]["level"] == "error" and
          res[0]["properties"]["findingRevision"] >= 1, res[:1])
    n, err = ops("notice.prepare", finding_id="F-001")
    check("notice drafted for a material finding, tied to its revision", n and n["state"] == "draft" and
          n["finding_revision"] >= 1, n or err)
    _, err = ops("notice.review", actor=AGENT, id="N-001")
    check("the agent can't review a notice", err and "person" in err, err)
    n2, _ = ops("notice.prepare", finding_id="F-002")
    ops("finding.update", id="F-002", fields={"notes": "edited again"})
    _, err = ops("notice.review", id=n2["id"])
    check("a notice for a finding that changed since can't be reviewed", err and "changed since" in err, err)
    n, err = ops("notice.review", id="N-001")
    check("notice reviewed by a person", n and n["state"] == "reviewed" and n["reviewed_by"] == CLI, n or err)
    _, err = ops("notice.prepare", finding_id="F-999")
    check("no notice for an unknown finding", err, err)

    print("== retests (RW-020)")
    put("evidence/http/retest-1.txt", "> GET http://198.51.100.40/invoices/12\n< 403 Forbidden\n")
    _, err = ops("retest.record", finding_id="F-001", retest_build="b2", outcome="resolved",
                 cases=[{"name": "other tenant reads invoice", "result": "pass"}])
    check("a retest case needs its evidence", err and "evidence" in err, err)
    _, err = ops("retest.record", finding_id="F-001", retest_build="b2", outcome="resolved",
                 cases=[{"name": "a", "result": "pass", "after": ["evidence/http/retest-1.txt"]},
                        {"name": "b", "result": "fail", "after": ["evidence/http/retest-1.txt"]}])
    check("resolved needs every case to pass", err and "every case" in err, err)
    rt, err = ops("retest.record", finding_id="F-001", retest_build="b2", outcome="resolved",
                  cases=[{"name": "other tenant reads invoice", "result": "pass", "after": ["evidence/http/retest-1.txt"]}],
                  reauthorization="retest window agreed by the client on 9 Nov")
    check("resolved retest marks the finding fixed in a new revision", rt and rt["finding"]["status"] == "fixed"
          and rt["outcome"] == "resolved" and rt["cases"][0]["before"], rt or err)
    h, _ = ops("finding.history", id="F-001")
    snaps = [x["snapshot"]["status"] for x in (h or {}).get("revisions", [])]
    check("the original confirmed revision stays in the history", "confirmed" in snaps and snaps[-1] == "fixed"
          and any(d["method"] == "retest" for d in h["decisions"]), snaps)
    rt2, err = ops("retest.record", finding_id="F-001", retest_build="b3", outcome="unresolved",
                   cases=[{"name": "regression", "result": "fail", "after": ["evidence/http/retest-1.txt"]}])
    check("a failed regression reopens it (confirmed), with its own record", rt2 and rt2["finding"]["status"] ==
          "confirmed" and rt2["id"] == "T-002", rt2 or err)
    ops("finding.update", id="F-002", fields={"status": "fixed"})
    rd, _ = ops("report.revisions")
    check("fixed without a resolved retest blocks delivery",
          any(b["check"] == "retest:F-002" for b in rd["readiness"]["blocking"]), rd["readiness"])
    out = tool(f"findings.record_retest('{ENG}', 'F-002', 'b2', 'resolved', [])")
    check("record_retest tool refuses a retest without cases", out.startswith("REFUSED"), out)

    print("== cleanup obligations (RW-020)")
    c, err = ops("cleanup.add", kind="data", what="delete the test invoices created in tenant B")
    check("obligation recorded", c and c["id"] == "C-001" and c["state"] == "open", c or err)
    hv, _ = ops("handover.get")
    check("open obligations are pending decisions in the handover", any(p["kind"] == "cleanup" for p in hv["pending"]),
          hv["pending"])
    _, err = ops("cleanup.update", id="C-001", state="done")
    check("done needs a note", err and "note" in err, err)
    _, err = ops("cleanup.update", actor=AGENT, id="C-001", state="waived", note="not needed")
    check("the agent can't waive an obligation", err and "person" in err, err)
    c, err = ops("cleanup.update", actor=AGENT, id="C-001", state="done", note="deleted invoices 9001-9004")
    check("done with the note", c and c["state"] == "done", c or err)

    print("== audit")
    ev = {"event": "report-approved", "actor": CLI, "target": "R-004", "before": "ready", "after": "approved"}
    r = sh("docker", "compose", "exec", "-T", "kali-mcp", "python3", "/opt/kali-mcp/rvctl.py", "--actor", CLI,
           "record", ENG, stdin=json.dumps(ev))
    check("delivery decisions can be recorded in the audit log", r.returncode == 0 and "report-approved" in r.stdout,
          r.stdout + r.stderr)
    r = sh("./rvkit", "report", ENG, "revisions")
    check("./rvkit report revisions lists them", r.returncode == 0 and "R-004  approved" in r.stdout,
          r.stdout + r.stderr)

    print(f"\npassed {sum(results)}, failed {len(results) - sum(results)}")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
