"""Investigation workspace (RW-015 to RW-018) against the running findings-mcp, with no model: triage decisions
with reasons and history, CVSS 3.1 from the vector, observations from tool outputs (dedupe, parser errors kept,
grouping left to a person), coverage rules and staleness, the handover, and the agent's tools refusing what the
rules refuse. Uses a throwaway engagement (rv-workspace-test) that is deleted afterwards.
Needs the stack up (./rvkit up). Run: python3 evals/workspace_test.py
"""
import json, os, subprocess, sys

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENG = "rv-workspace-test"
ACTOR = "cli:workspace-test"
results = []


def check(name, ok, detail=""):
    results.append(bool(ok))
    print(("PASS  " if ok else "FAIL  ") + name + ("" if ok else f"\n      {str(detail)[:300]}"))


def sh(*args, stdin=None):
    return subprocess.run(args, cwd=KIT, capture_output=True, text=True, input=stdin, timeout=300)


def ops(name, **req):
    """One operation: (result, None) or (None, error)."""
    r = sh("docker", "compose", "exec", "-T", "findings-mcp", "python3", "ops.py", name,
           stdin=json.dumps({"engagement": ENG, "actor": ACTOR, **req}))
    try:
        d = json.loads(r.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return None, r.stderr[-300:]
    return (d.get("result"), d.get("error")) if "error" not in d else (None, d["error"])


def tool(expr):
    """Call one of the agent's findings tools in findings-mcp."""
    r = sh("docker", "compose", "exec", "-T", "findings-mcp", "python3", "-c",
           f"import findings; print({expr})")
    return r.stdout.strip() or r.stderr[-300:]


def put(rel, text):
    """Write a file into the engagement's evidence as the sandbox would."""
    return sh("docker", "compose", "exec", "-T", "kali-mcp", "sh", "-c",
              f"mkdir -p \"$(dirname /work/{ENG}/{rel})\" && cat > /work/{ENG}/{rel}", stdin=text)


def cleanup():
    sh("docker", "compose", "exec", "-T", "kali-mcp", "python3", "/opt/kali-mcp/rvctl.py", "delete", ENG, "--force")
    sh("docker", "compose", "exec", "-T", "kali-mcp", "sh", "-c", f"rm -rf /work/_deleted-{ENG}-*")


SEMGREP = {"version": "1.99.0", "errors": [{"type": "Syntax error", "message": "could not parse", "spans": [
    {"file": "app/Broken.php"}]}], "paths": {"scanned": ["a.php", "b.php"], "skipped": [{"path": "big.min.js"}]},
    "results": [
        {"check_id": "php.lang.security.injection.tainted-sql-string", "path": "app/Http/Controllers/InvoiceController.php",
         "start": {"line": 41}, "end": {"line": 41}, "extra": {"message": "User input in a SQL string", "severity": "ERROR",
                                                               "lines": "DB::select(\"... $q\")", "metadata": {"cwe": ["CWE-89"]}}},
        {"check_id": "php.lang.security.injection.tainted-sql-string", "path": "app/Http/Controllers/InvoiceController.php",
         "start": {"line": 77}, "end": {"line": 77}, "extra": {"message": "User input in a SQL string", "severity": "ERROR",
                                                               "lines": "DB::select(\"... $s\")"}},
        {"check_id": "php.lang.security.cookie-missing-secure", "path": "config/session.php", "start": {"line": 12},
         "end": {"line": 12}, "extra": {"message": "Cookie without Secure", "severity": "WARNING", "lines": "'secure' => false"}}]}


def main():
    cleanup()
    r = sh("./rvkit", "engagement", ENG, "--tiers", "passive", "198.51.100.30")
    if r.returncode:
        print("FAIL  could not create the engagement\n" + r.stdout[-300:] + r.stderr[-300:]); return 1
    try:
        return run()
    finally:
        cleanup()


def run():
    print("== triage decisions (RW-017)")
    f, err = ops("finding.record", fields={"title": "Cross-tenant invoice read", "severity": "high", "asset": "/invoices/{id}",
                                           "description": "A member of tenant A reads tenant B's invoice."})
    check("finding recorded", f and f["id"] == "F-001", err)
    _, err = ops("finding.update", id="F-001", fields={"status": "false-positive"})
    check("false-positive without a reason refused", err and "reason" in err, err)
    _, err = ops("finding.update", id="F-001", fields={"severity": "critical"})
    check("severity change without a reason refused", err and "reason" in err, err)
    _, err = ops("finding.update", id="F-001", fields={"cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                                                       "cvss_score": 9.9})
    check("a CVSS score that doesn't match its vector refused", err and "doesn't match" in err, err)
    f, err = ops("finding.update", id="F-001", fields={"cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"})
    check("CVSS 3.1 score computed from the vector (6.5, medium)", f and f["cvss_score"] == 6.5 and f["cvss_rating"] == "medium",
          f or err)
    _, err = ops("finding.update", id="F-001", fields={"status": "confirmed"}, method="guessed")
    check("unknown verification method refused", err and "method" in err, err)
    f, err = ops("finding.update", id="F-001", fields={"status": "confirmed", "priority": "P1"}, method="authorization-matrix")
    check("confirming records who verified it and how",
          f and f["verification"] == "verified" and f["verified_method"] == "authorization-matrix"
          and f["verified_by"] == ACTOR and f["priority"] == "P1", f or err)
    _, err = ops("finding.update", id="F-001", fields={"priority": "P3"})
    check("changing a set priority without a reason refused", err and "reason" in err, err)
    f, err = ops("finding.update", id="F-001", fields={"priority": "P2"}, reason="only reachable by members of a paid plan")
    check("priority change with a reason accepted (severity unchanged)", f and f["priority"] == "P2" and f["severity"] == "high",
          f or err)
    f2, _ = ops("finding.record", fields={"title": "Debug page", "severity": "low", "asset": "/_debug", "description": "x"})
    f2, err = ops("finding.update", id=f2["id"], fields={"status": "confirmed"})
    check("confirmed without a method says so", f2 and f2["verified_method"] == "not stated", f2 or err)
    _, err = ops("finding.not_reproducible", id="F-002", reason="")
    check("not reproducible needs the reason", err, err)
    f2, err = ops("finding.not_reproducible", id="F-002", reason="retest on build 4f2a: /_debug returns 404")
    check("not reproducible recorded", f2 and f2["verification"] == "not-reproducible", f2 or err)
    h, err = ops("finding.history", id="F-001")
    kinds = [d["kind"] for d in (h or {}).get("decisions", [])]
    check("history keeps every revision and the decisions with reasons",
          h and len(h["revisions"]) >= 4 and "priority" in kinds and
          any(d.get("reason") == "only reachable by members of a paid plan" for d in h["decisions"]), h or err)

    print("== observations (RW-016)")
    put("evidence/semgrep/app.json", json.dumps(SEMGREP))
    imp, err = ops("observation.import", path="evidence/semgrep/app.json")
    check("Semgrep output imported: 3 observations", imp and imp["parser"] == "semgrep" and imp["observations"] == 3
          and imp["new"] == 3, imp or err)
    check("parser errors and skipped paths kept, not dropped",
          imp and imp["errors"] and any("skipped" in l for l in imp["limitations"]), imp)
    imp2, err = ops("observation.import", path="evidence/semgrep/app.json")
    check("re-importing the same output doesn't duplicate", imp2 and imp2["new"] == 0, imp2 or err)
    put("evidence/misc/notes.json", '{"something": "else"}')
    imp3, err = ops("observation.import", path="evidence/misc/notes.json")
    check("an unknown format is an import with an error, not a silent nothing",
          imp3 and imp3["errors"] and imp3["errors"][0]["type"] == "unknown-format", imp3 or err)
    _, err = ops("observation.import", path="../../etc/passwd")
    check("only files of the engagement", err, err)
    put("semgrep.json", json.dumps(SEMGREP))
    imp4, err = ops("observation.import", path="/work/%s/semgrep.json" % ENG)
    check("a tool output at the engagement root imports too (same observations, none new)",
          imp4 and imp4["observations"] == 3 and imp4["new"] == 0, imp4 or err)
    lst, _ = ops("observation.list")
    groups = (lst or {}).get("groups", [])
    sql = [o["id"] for o in lst["observations"] if "sql" in o["rule_id"]]
    check("same rule in the same file suggested as one group", any(sorted(g["observations"]) == sorted(sql) for g in groups),
          groups)
    check("nothing was linked automatically", all(o["status"] == "new" for o in lst["observations"]), lst["observations"])
    f3, _ = ops("finding.record", fields={"title": "SQL injection in invoice search", "severity": "high",
                                          "asset": "InvoiceController", "description": "x"})
    row, err = ops("observation.link", ids=sql, finding_id=f3["id"])
    check("linked observations become the finding's instances and evidence",
          row and len(row["instances"]) == 2 and "evidence/semgrep/app.json" in row["evidence"], row or err)
    other = [o["id"] for o in lst["observations"] if o["id"] not in sql]
    _, err = ops("observation.dismiss", ids=other, reason="")
    check("dismissing needs a reason", err and "reason" in err, err)
    r, err = ops("observation.dismiss", ids=other, reason="cookie flags are set by the TLS terminator")
    lst, _ = ops("observation.list", status=None)
    check("dismissed with the reason kept", any(o["status"] == "dismissed" and o["reason"] for o in lst["observations"]),
          lst)

    print("== coverage (RW-015)")
    pb, err = ops("plan.from_playbook", playbook="laravel")
    check("plan items from the Laravel playbook, with its version", pb and len(pb["ids"]) >= 10 and pb["version"], pb or err)
    pb2, _ = ops("plan.from_playbook", playbook="laravel")
    check("adding the same playbook again adds nothing", pb2 and not pb2["ids"], pb2)
    first = pb["ids"][0]
    put("evidence/authz/x.json", "{}"); put("evidence/http/y.txt", "> GET http://198.51.100.30/\n< 200 OK\n")
    _, err = ops("plan.update", id=first, fields={"state": "tested"})
    check("tested needs evidence", err and "evidence" in err, err)
    _, err = ops("plan.update", id=first, fields={"state": "failed"})
    check("failed needs the finding it produced", err and "finding" in err, err)
    _, err = ops("plan.update", id=first, fields={"state": "blocked"})
    check("blocked needs a rationale", err and "rationale" in err, err)
    it, err = ops("plan.update", id=first, fields={"state": "failed", "finding_id": "F-001", "build": "4f2a",
                                                  "evidence": ["evidence/authz/x.json"]})
    check("failed with the finding and the build", it and it["state"] == "failed", it or err)
    it, err = ops("plan.update", id=pb["ids"][1], fields={"state": "tested", "evidence": ["evidence/http/y.txt"],
                                                         "build": "4f2a"})
    check("tested with evidence", it and it["state"] == "tested", it or err)
    ra, err = ops("coverage.reassess", build="9c1e")
    check("a new build marks earlier results stale", ra and ra["stale"] == 2, ra or err)
    cov, _ = ops("plan.list")
    check("coverage counts per state and per standard", cov and cov["coverage"]["counts"]["failed"] == 1
          and cov["coverage"]["by_standard"], cov and cov["coverage"])

    print("== objective and handover (RW-018)")
    o, err = ops("workspace.objective", text="Can a member of one tenant read or change another tenant's invoices?")
    _, err2 = ops("workspace.objective", text="something else", expected_digest="0" * 16)
    check("objective saved; a stale edit is a conflict", o and err2 and "changed" in err2, err2)
    hv, err = ops("handover.get")
    md = (hv or {}).get("markdown", "")
    check("handover from the records: objective, material findings, stale retests, next",
          "another tenant's invoices" in md and "F-001" in md and "stale" in md.lower() or "retest" in md.lower()
          and "## Next" in md, md[:600] or err)
    check("handover lists the pending decisions it can see",
          any(p["kind"] == "verification-method" for p in hv["pending"]) or any(p["kind"] == "retest" for p in hv["pending"]),
          hv["pending"])
    pv, err = ops("evidence.preview", path="evidence/semgrep/app.json")
    check("evidence preview: text, size and hash", pv and pv["sha256"] and "tainted-sql" in pv["text"], pv or err)
    for bad in ("findings.db", "audit.jsonl", ".home/.bash_history", "report/x.html"):
        _, err = ops("evidence.preview", path=bad)
        check(f"no preview of {bad}", err, err)

    print("== the agent's tools")
    out = tool(f"findings.update_finding('{ENG}', 'F-003', status='false-positive')")
    check("update_finding refuses a false-positive without a reason", out.startswith("REFUSED") and "reason" in out, out)
    out = tool(f"findings.update_finding('{ENG}', 'F-003', status='confirmed')")
    check("update_finding refuses confirmed without a method", out.startswith("REFUSED") and "method" in out, out)
    out = tool(f"findings.update_finding('{ENG}', 'F-003', status='confirmed', method='source-review')")
    check("update_finding records the method", '"verified_method": "source-review"' in out, out)
    rec = f"findings.record_finding('{ENG}', 'Confirmed at once', 'low', 'app.py', 'd', status='confirmed'"
    out = tool(rec + ")")
    check("record_finding refuses confirmed without a method", out.startswith("REFUSED") and "method" in out, out)
    out = tool(rec + ", method='runtime-reproduction')")
    check("record_finding refuses a runtime method without evidence", out.startswith("REFUSED") and "evidence" in out, out)
    out = tool(rec + ", method='source-review')")
    check("record_finding records the method", '"verified_method": "source-review"' in out, out)
    made = json.loads(out)["id"] if out.startswith("{") else ""
    out = tool(f"findings.update_finding('{ENG}', '{made}', status='duplicate', duplicate_of='F-003')")
    check("the extra finding is merged away again", '"status": "duplicate"' in out, out)
    out = tool(f"findings.update_coverage('{ENG}', '{pb['ids'][2]}', 'excluded')")
    check("update_coverage refuses excluded without a rationale", out.startswith("REFUSED"), out)
    out = tool(f"findings.get_handover('{ENG}')")
    check("get_handover returns the handover text", out.startswith(f"# Handover: {ENG}"), out[:200])

    print("== audit")
    ev = {"event": "observations-imported", "actor": ACTOR, "target": "evidence/semgrep/app.json", "parser": "semgrep",
          "new": 3}
    r = sh("docker", "compose", "exec", "-T", "kali-mcp", "python3", "/opt/kali-mcp/rvctl.py", "--actor", ACTOR,
           "record", ENG, stdin=json.dumps(ev))
    check("workspace changes can be recorded in the audit log", r.returncode == 0 and "observations-imported" in r.stdout,
          r.stdout + r.stderr)

    print(f"\npassed {sum(results)}, failed {len(results) - sum(results)}")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
