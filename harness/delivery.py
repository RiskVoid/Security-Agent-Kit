"""Delivery and retest records (RW-019 to RW-021), in the engagement's findings.db.

Report revisions
  generated   a report was built; its inputs are frozen in report/revisions/R-NNN/inputs.json and every artifact's
              SHA-256 is recorded. Earlier revisions (same day or not) are kept as they were.
  ready       nothing blocks delivery: every readiness check passed or has an exception a person recorded with
              its rationale (only the checks the methodology allows to be excepted)
  approved    a person (console or CLI, never the agent) approved it for client delivery, while the records it was
              built from were unchanged; a later approval supersedes it
  superseded  a newer revision was approved
  Transmission (sending the report) is a separate, optional record: approval doesn't send anything.

Retests link a finding to the build it was retested on, the cases (before and after evidence) and the outcome
(resolved, partial, unresolved). A resolved retest marks the finding fixed through a new revision: the original
reproduction and every earlier revision stay in its history.

Cleanup obligations (fixtures, credentials, data, access, retention) stay open until someone records them done
or waived, with a note.

Notices are researcher-reviewed drafts for material findings; exports (JSON, SARIF, issue text) are built from a
revision's frozen findings and name the finding revisions they contain. Nothing here sends anything anywhere.
"""
import datetime, hashlib, json, os, re, shutil

import findings_db as db
import workspace as ws

READY_STATES = ("generated", "ready", "approved", "superseded")
OUTCOMES = ("resolved", "partial", "unresolved")
CASE_RESULTS = ("pass", "fail", "partial")
OBLIGATIONS = ("fixture", "credential", "data", "access", "retention", "other")
OB_STATES = ("open", "done", "waived")
HUMAN_RX = re.compile(r"^(console|cli):")
# Readiness checks a person may except, with the rationale: methodology choices. The others are facts about the
# record (no summary, untriaged candidates, broken evidence, no client name) and have to be fixed.
EXCEPTABLE = ("coverage-plan", "coverage-open", "coverage-stale", "fields", "verification", "retest")
MATERIAL = ("critical", "high")
REQUIRED_FIELDS = ("asset", "description", "impact", "reproduction", "remediation")


def _now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def _sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _jl(v, default=None):
    try:
        return json.loads(v) if v else (default if default is not None else [])
    except ValueError:
        return default if default is not None else []


def _human(actor, what):
    if not isinstance(actor, str) or not HUMAN_RX.match(actor):
        raise ValueError(f"{what} is a person's decision: the console or the CLI, not the agent")
    return actor


def _rdir(eng, *parts):
    return os.path.join(db.engagement_dir(eng), "report", *parts)


# ---------------------------------------------------------------- readiness (RW-019)
def stable_inputs(eng):
    """What a report revision is built from, apart from the live activity counters: finding revisions, the report
    texts and details, coverage outcomes and exceptions. Approval needs these unchanged since generation."""
    with db._db(eng) as con:
        f = [(r["id"], r["revision"], r["status"]) for r in con.execute("SELECT id, revision, status FROM findings")]
        p = [(r["id"], r["revision"], r["state"]) for r in con.execute("SELECT id, revision, state FROM plan_items")]
        x = [(r["id"], r["check_key"], r["revoked_at"]) for r in con.execute("SELECT * FROM report_exceptions")]
    texts = {}
    for n in ("executive-summary.md", "methodology.md", "conclusion.md", "meta.txt"):
        try:
            texts[n] = hashlib.sha256(open(_rdir(eng, n), "rb").read()).hexdigest()
        except OSError:
            texts[n] = None
    blob = json.dumps({"findings": sorted(f), "plan": sorted(p), "exceptions": sorted(x, key=str), "texts": texts},
                      sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()[:32]


def exceptions(eng, active=True):
    with db._db(eng) as con:
        q = "SELECT * FROM report_exceptions" + (" WHERE revoked_at IS NULL" if active else "") + " ORDER BY id"
        return [dict(r) for r in con.execute(q)]


def add_exception(eng, actor, check_key, rationale):
    _human(actor, "an exception to a readiness check")
    base = str(check_key).split(":")[0]
    if base not in EXCEPTABLE:
        raise ValueError(f"{check_key}: not a check that can be excepted (only {', '.join(EXCEPTABLE)}; "
                         "fix the others)")
    if not isinstance(rationale, str) or len(rationale.strip()) < 10:
        raise ValueError("an exception needs its rationale (at least a sentence)")
    with db._db(eng) as con:
        cur = con.execute("INSERT INTO report_exceptions (check_key, rationale, actor, at) VALUES (?,?,?,?)",
                          (check_key, rationale.strip()[:2000], actor, _now()))
        return {"id": cur.lastrowid, "check_key": check_key}


def revoke_exception(eng, actor, exc_id):
    _human(actor, "revoking an exception")
    with db._db(eng) as con:
        if not con.execute("UPDATE report_exceptions SET revoked_at=? WHERE id=? AND revoked_at IS NULL",
                           (_now(), int(exc_id))).rowcount:
            raise ValueError(f"no active exception {exc_id}")
    return {"id": int(exc_id), "revoked": True}


def readiness(eng, inp=None):
    """Checks a report must pass before delivery. inp: report.collect() output (adds the report's own checks:
    summary, client, candidates, evidence integrity). Returns {"blocking", "excepted", "warnings", "ready"}."""
    checks, warnings = [], []
    allf = db.list_(eng) if inp is None else inp["findings"]
    reported = [f for f in allf if f["status"] in ("confirmed", "fixed", "accepted-risk")]
    if inp is not None:
        if not (inp["texts"].get("executive-summary.md") or "").strip():
            checks.append(("summary", "no executive summary (report/executive-summary.md)"))
        if not inp["meta"].get("client"):
            checks.append(("client", "client name not set (report/meta.txt)"))
        for i in inp["evidence_issues"]:
            checks.append(("evidence", i))
    cands = [f["id"] for f in allf if f["status"] == "candidate"]
    if cands:
        checks.append(("candidates", f"{len(cands)} candidate finding(s) not yet triaged: {', '.join(cands)}"))
    plan = ws.plan_list(eng)
    if not plan:
        checks.append(("coverage-plan", "no coverage plan: the report can't say what was tested and what wasn't"))
    open_ = [i["id"] for i in plan if i["state"] == "planned"]
    if open_:
        checks.append(("coverage-open", f"{len(open_)} planned test(s) without an outcome: {', '.join(open_[:15])}"
                       + (" ..." if len(open_) > 15 else "")))
    stale = [i["id"] for i in plan if i["stale"]]
    if stale:
        checks.append(("coverage-stale", f"{len(stale)} outcome(s) recorded on another build or policy: "
                       f"{', '.join(stale[:15])}"))
    for f in reported:
        missing = [k for k in REQUIRED_FIELDS if not (f.get(k) or "").strip()]
        if missing:
            checks.append((f"fields:{f['id']}", f"{f['id']} has no {', '.join(missing)}"))
        if f["status"] == "confirmed" and f.get("verified_method") in (None, "", "not stated"):
            checks.append((f"verification:{f['id']}", f"{f['id']} is confirmed without a verification method"))
    with db._db(eng) as con:
        retested = {r["finding_id"] for r in con.execute("SELECT finding_id FROM retests WHERE outcome='resolved'")}
        open_obs = con.execute("SELECT COUNT(*) FROM observations WHERE status='new'").fetchone()[0]
        open_obl = [r["id"] for r in con.execute("SELECT id FROM obligations WHERE state='open'")]
    for f in reported:
        if f["status"] == "fixed" and f["id"] not in retested:
            checks.append((f"retest:{f['id']}", f"{f['id']} is marked fixed without a resolved retest record"))
        from redact import redact
        if any(redact(f.get(k) or "") != (f.get(k) or "") for k in ("description", "reproduction", "impact", "notes")):
            warnings.append(f"{f['id']}: its text contains what looks like a secret (redacted in the report; "
                            "remove it from the finding)")
    if open_obs:
        warnings.append(f"{open_obs} observation(s) not triaged (not in the report)")
    if open_obl:
        warnings.append(f"{len(open_obl)} cleanup obligation(s) open: {', '.join(open_obl)}")
    exc = {e["check_key"]: e for e in exceptions(eng)}
    blocking = [{"check": k, "issue": msg} for k, msg in checks if k not in exc]
    excepted = [{"check": k, "issue": msg, "rationale": exc[k]["rationale"], "by": exc[k]["actor"], "at": exc[k]["at"]}
                for k, msg in checks if k in exc]
    return {"blocking": blocking, "excepted": excepted, "warnings": warnings, "ready": not blocking}


# ---------------------------------------------------------------- report revisions (RW-019)
def _row(r):
    d = dict(r)
    for k in ("artifacts", "readiness", "transmissions"):
        d[k] = _jl(d.get(k), {} if k != "transmissions" else [])
    d.pop("inputs", None)
    return d


def revisions(eng):
    with db._db(eng) as con:
        return [_row(r) for r in con.execute("SELECT * FROM report_revisions ORDER BY id DESC")]


def revision(eng, rid):
    with db._db(eng) as con:
        r = con.execute("SELECT * FROM report_revisions WHERE id=?", (rid,)).fetchone()
    if not r:
        raise ValueError(f"no report revision {rid}")
    return _row(r)


def generate(eng, actor):
    """Build the report, freeze its inputs and artifacts as a new revision. Returns the revision."""
    import report
    inp = report.collect(eng)
    ready = readiness(eng, inp)
    # the document says DRAFT while anything blocks delivery; excepted checks are listed in the revision
    inp["readiness_issues"] = [b["issue"] for b in ready["blocking"]]
    digest = stable_inputs(eng)
    with db._db(eng) as con:
        con.execute("BEGIN IMMEDIATE")
        n = con.execute("SELECT COUNT(*) FROM report_revisions").fetchone()[0] + 1
        rid = f"R-{n:03d}"
        con.execute("INSERT INTO report_revisions (id, state, created, actor, inputs_digest) VALUES (?,?,?,?,?)",
                    (rid, "building", _now(), actor, digest))
    out = _rdir(eng, "revisions", rid)
    try:
        r = report.build(eng, inp, out_dir=out)
    except Exception:
        with db._db(eng) as con:
            con.execute("DELETE FROM report_revisions WHERE id=?", (rid,))
        shutil.rmtree(out, ignore_errors=True)
        raise
    with open(os.path.join(out, "inputs.json"), "w") as f:
        json.dump(inp, f, default=str)  # key order is content (the tools table is ordered by use)
    arts = {}
    for name in sorted(os.listdir(out)):
        p = os.path.join(out, name)
        if os.path.isfile(p):
            arts[name] = _sha(p)
            shutil.copy2(p, _rdir(eng, name)) if name != "inputs.json" else None  # the latest, at the old place
            os.chmod(p, 0o444)
    state = "ready" if ready["ready"] else "generated"
    with db._db(eng) as con:
        con.execute("UPDATE report_revisions SET state=?, artifacts=?, readiness=?, inputs=? WHERE id=?",
                    (state, json.dumps(arts), json.dumps(ready), json.dumps({"inputs.json": arts["inputs.json"]}),
                     rid))
    return {**revision(eng, rid), "report": {k: r.get(k) for k in ("status", "issues", "findings", "excluded")}}


def approve(eng, actor, rid, note=""):
    _human(actor, "approving a report for client delivery")
    rev = revision(eng, rid)
    if rev["state"] != "ready":
        raise ValueError(f"{rid} is {rev['state']}: only a ready revision (no blocking check left) can be approved")
    latest = revisions(eng)[0]
    if latest["id"] != rid:
        raise ValueError(f"{rid} isn't the latest revision ({latest['id']} is)")
    if stable_inputs(eng) != rev["inputs_digest"]:
        raise ValueError(f"the findings, coverage or report texts changed since {rid} was generated: generate a new "
                         "revision and approve that")
    bad = verify(eng, rid)["problems"]
    if bad:
        raise ValueError(f"{rid}'s files don't match their recorded hashes: " + "; ".join(bad))
    with db._db(eng) as con:
        con.execute("BEGIN IMMEDIATE")
        con.execute("UPDATE report_revisions SET state='superseded', superseded_by=? WHERE state='approved'", (rid,))
        con.execute("UPDATE report_revisions SET state='approved', approved_by=?, approved_at=?, approval_note=? "
                    "WHERE id=?", (actor, _now(), (note or "")[:2000], rid))
    return revision(eng, rid)


def verify(eng, rid):
    """Re-hash a revision's files against what was recorded when it was generated."""
    rev = revision(eng, rid)
    problems = []
    for name, sha in rev["artifacts"].items():
        p = _rdir(eng, "revisions", rid, name)
        if not os.path.isfile(p):
            problems.append(f"{name} is missing")
        elif _sha(p) != sha:
            problems.append(f"{name} was modified")
    return {"revision": rid, "files": len(rev["artifacts"]), "problems": problems}


def rebuild(eng, rid):
    """Render the report again from the revision's frozen inputs, next to it (rebuild-<time>/). The HTML is
    compared byte for byte with the original."""
    import report
    verify_ = verify(eng, rid)
    if verify_["problems"]:
        raise ValueError(f"{rid}'s files don't match their recorded hashes: " + "; ".join(verify_["problems"]))
    inp = json.load(open(_rdir(eng, "revisions", rid, "inputs.json")))
    out = _rdir(eng, "revisions", f"{rid}-rebuild-{datetime.datetime.now().strftime('%Y%m%dT%H%M%S')}")
    r = report.build(eng, inp, out_dir=out)
    html = os.path.basename(str(r["html"]))
    orig = revision(eng, rid)["artifacts"].get(html)
    return {"revision": rid, "folder": os.path.relpath(out, db.engagement_dir(eng)), "html": html,
            "html_identical": orig == _sha(os.path.join(out, html)),
            "note": "the .docx, .pdf and .xlsx embed creation times, so only the HTML is compared byte for byte"}


def record_transmission(eng, actor, rid, to, channel, note=""):
    """That an approved revision was sent (by someone, some way): a record, not a send."""
    _human(actor, "recording a transmission")
    rev = revision(eng, rid)
    if rev["state"] not in ("approved", "superseded") or not rev.get("approved_by"):
        raise ValueError(f"{rid} wasn't approved for delivery")
    if not to or not channel:
        raise ValueError("to (who received it) and channel (how) are required")
    t = rev["transmissions"] + [{"to": str(to)[:200], "channel": str(channel)[:100], "note": str(note)[:500],
                                 "by": actor, "at": _now()}]
    with db._db(eng) as con:
        con.execute("UPDATE report_revisions SET transmissions=? WHERE id=?", (json.dumps(t), rid))
    return revision(eng, rid)


# ---------------------------------------------------------------- retests (RW-020)
def record_retest(eng, actor, finding_id, retest_build, outcome, cases, reauthorization="", note=""):
    f = db.get(eng, finding_id)
    if f["status"] not in ("confirmed", "fixed"):
        raise ValueError(f"{finding_id} is {f['status']}: retests are for confirmed or fixed findings")
    if not retest_build or not isinstance(retest_build, str):
        raise ValueError("retest_build: the build or commit the retest ran on")
    if outcome not in OUTCOMES:
        raise ValueError(f"outcome is one of {OUTCOMES}")
    if not isinstance(cases, list) or not cases:
        raise ValueError("cases: at least one regression case [{name, after: [evidence], result}]")
    clean = []
    for c in cases:
        if not isinstance(c, dict) or not c.get("name") or c.get("result") not in CASE_RESULTS:
            raise ValueError(f"each case needs a name and a result ({', '.join(CASE_RESULTS)})")
        after = c.get("after") or []
        if not after:
            raise ValueError(f"case {c['name']!r}: the evidence of the retest (after) is required")
        for p in after:
            ws._rel(eng, str(p).split(" ")[0])  # exists and belongs to the engagement
        before = c.get("before") or list(f.get("evidence") or [])
        clean.append({"name": str(c["name"])[:200], "before": before[:20], "after": after[:20],
                      "result": c["result"], "detail": str(c.get("detail") or "")[:1000]})
    if outcome == "resolved" and any(c["result"] != "pass" for c in clean):
        raise ValueError("resolved needs every case to pass; use partial or unresolved")
    plan = [i for i in ws.plan_list(eng) if i.get("finding_id") == finding_id and i.get("build")]
    original_build = plan[0]["build"] if plan else None
    reason = f"retest on build {retest_build}: {outcome} ({sum(c['result'] == 'pass' for c in clean)}/" \
             f"{len(clean)} case(s) pass)"
    if outcome == "resolved" and f["status"] != "fixed":
        row = db.update(eng, finding_id, actor=actor, method="retest", reason=reason, status="fixed")
    elif outcome != "resolved" and f["status"] == "fixed":
        row = db.update(eng, finding_id, actor=actor, method="retest", reason=reason, status="confirmed")
    else:
        row = f
        with db._db(eng) as con:
            db._decision(con, finding_id, "retest", f["status"], f["status"], reason, "retest", db._actor(actor),
                         f["revision"])
    with db._db(eng) as con:
        con.execute("BEGIN IMMEDIATE")  # the id is allocated under the write lock
        tid = f"T-{con.execute('SELECT COUNT(*) FROM retests').fetchone()[0] + 1:03d}"
        con.execute("INSERT INTO retests VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (tid, finding_id, f["revision"], original_build, retest_build, outcome, json.dumps(clean),
                     str(reauthorization or "")[:1000], str(note or "")[:2000], row["revision"], actor, _now()))
    return {**retest(eng, tid), "finding": {"id": finding_id, "status": row["status"], "revision": row["revision"]}}


def retest(eng, tid):
    with db._db(eng) as con:
        r = con.execute("SELECT * FROM retests WHERE id=?", (tid,)).fetchone()
    if not r:
        raise ValueError(f"no retest {tid}")
    d = dict(r)
    d["cases"] = _jl(d["cases"])
    return d


def retests(eng, finding_id=None):
    with db._db(eng) as con:
        q, a = "SELECT id FROM retests", []
        if finding_id:
            q += " WHERE finding_id=?"; a.append(finding_id)
        ids = [r["id"] for r in con.execute(q + " ORDER BY id", a)]
    return [retest(eng, i) for i in ids]


# ---------------------------------------------------------------- cleanup obligations (RW-020)
def add_obligation(eng, actor, kind, what, due=None):
    if kind not in OBLIGATIONS:
        raise ValueError(f"kind is one of {OBLIGATIONS}")
    if not what or len(str(what)) > 1000:
        raise ValueError("what: the obligation, up to 1000 characters")
    with db._db(eng) as con:
        con.execute("BEGIN IMMEDIATE")
        n = con.execute("SELECT COUNT(*) FROM obligations").fetchone()[0] + 1
        oid = f"C-{n:03d}"
        con.execute("INSERT INTO obligations (id, kind, what, state, due, actor, created, updated, updated_by) "
                    "VALUES (?,?,?,?,?,?,?,?,?)", (oid, kind, str(what), "open", due, actor, _now(), _now(), actor))
    return obligation(eng, oid)


def update_obligation(eng, actor, oid, state, note=""):
    if state not in OB_STATES:
        raise ValueError(f"state is one of {OB_STATES}")
    if state in ("done", "waived") and len((note or "").strip()) < 5:
        raise ValueError(f"{state} needs a note: what was done, or why it's waived")
    if state == "waived":
        _human(actor, "waiving a cleanup obligation")
    obligation(eng, oid)
    with db._db(eng) as con:
        con.execute("UPDATE obligations SET state=?, note=?, updated=?, updated_by=? WHERE id=?",
                    (state, (note or "")[:2000], _now(), actor, oid))
    return obligation(eng, oid)


def obligation(eng, oid):
    with db._db(eng) as con:
        r = con.execute("SELECT * FROM obligations WHERE id=?", (oid,)).fetchone()
    if not r:
        raise ValueError(f"no obligation {oid}")
    return dict(r)


def obligations(eng):
    with db._db(eng) as con:
        return [dict(r) for r in con.execute("SELECT * FROM obligations ORDER BY id")]


# ---------------------------------------------------------------- notices and exports (RW-021)
def _finding_text(f):
    from redact import redact
    lines = [f"# {f['id']}: {f['title']}", "",
             f"Severity: {f['severity']}" + (f" (CVSS {f['cvss_score']}, {f.get('cvss_vector')})"
                                             if f.get("cvss_score") is not None else ""),
             f"Priority: {f.get('priority') or 'not set'}", f"Status: {f['status']}",
             f"Affected: {f.get('asset') or 'n/a'}" + (f" ({f['cwe']})" if f.get("cwe") else ""),
             f"Finding revision: {f['id']} rev {f['revision']}", ""]
    for k, h in (("description", "Description"), ("impact", "Impact"), ("prerequisites", "Prerequisites"),
                 ("reproduction", "Reproduction"), ("remediation", "Remediation")):
        if (f.get(k) or "").strip():
            lines += [f"## {h}", "", redact(f[k]).strip(), ""]
    inst = _jl(f.get("instances")) if isinstance(f.get("instances"), str) else (f.get("instances") or [])
    if inst:
        lines += ["## Affected instances", ""] + [f"- {i.get('location', i) if isinstance(i, dict) else i}"
                                                  for i in inst] + [""]
    return "\n".join(lines)


def prepare_notice(eng, actor, finding_id):
    f = db.get(eng, finding_id)
    if f["status"] != "confirmed" or f["severity"] not in MATERIAL:
        raise ValueError(f"notices are for confirmed {' or '.join(MATERIAL)} findings ({finding_id} is "
                         f"{f['status']}, {f['severity']})")
    with db._db(eng) as con:
        con.execute("BEGIN IMMEDIATE")
        n = con.execute("SELECT COUNT(*) FROM notices").fetchone()[0] + 1
        nid = f"N-{n:03d}"
        d = _rdir(eng, "notices")
        os.makedirs(d, exist_ok=True)
        path = os.path.join(d, f"{nid}-{finding_id}.md")
        body = (f"DRAFT notice of a material finding, for review before it is shared.\n\n"
                f"Engagement: {eng}\n\n" + _finding_text(f))
        with open(path, "w") as fh:
            fh.write(body)
        con.execute("INSERT INTO notices VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (nid, finding_id, f["revision"], "draft", os.path.relpath(path, db.engagement_dir(eng)),
                     hashlib.sha256(body.encode()).hexdigest(), actor, _now(), None, None))
    return notice(eng, nid)


def review_notice(eng, actor, nid):
    _human(actor, "reviewing a notice")
    n = notice(eng, nid)
    f = db.get(eng, n["finding_id"])
    if f["revision"] != n["finding_revision"]:
        raise ValueError(f"{n['finding_id']} changed since {nid} was prepared (revision {n['finding_revision']} -> "
                         f"{f['revision']}): prepare a new notice")
    p = os.path.join(db.engagement_dir(eng), n["path"])
    if hashlib.sha256(open(p, "rb").read()).hexdigest() != n["sha256"]:
        raise ValueError(f"{n['path']} was edited after it was prepared: prepare a new notice")
    with db._db(eng) as con:
        con.execute("UPDATE notices SET state='reviewed', reviewed_by=?, reviewed_at=? WHERE id=?",
                    (actor, _now(), nid))
    return notice(eng, nid)


def notice(eng, nid):
    with db._db(eng) as con:
        r = con.execute("SELECT * FROM notices WHERE id=?", (nid,)).fetchone()
    if not r:
        raise ValueError(f"no notice {nid}")
    return dict(r)


def notices(eng):
    with db._db(eng) as con:
        return [dict(r) for r in con.execute("SELECT * FROM notices ORDER BY id")]


SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
SEC_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.0"}
LOC_RX = re.compile(r"^(?:/src/[^/]+/)?([^\s:]+\.[A-Za-z0-9]+):(\d+)")


def _locations(f):
    inst = f.get("instances") or []
    if isinstance(inst, str):
        inst = _jl(inst)
    cands = [i.get("location") for i in inst if isinstance(i, dict) and i.get("location")] + [f.get("asset") or ""]
    phys = []
    for c in cands:
        m = LOC_RX.match(c)
        if m:
            phys.append({"physicalLocation": {"artifactLocation": {"uri": m.group(1)},
                                              "region": {"startLine": int(m.group(2))}}})
    if phys:
        return phys
    return [{"logicalLocations": [{"name": (f.get("asset") or f["id"])[:300], "kind": "resource"}]}]


def sarif(eng, rid, findings):
    from redact import redact
    rules, results = [], []
    for f in findings:
        props = {"security-severity": str(f["cvss_score"]) if f.get("cvss_score") is not None
                 else SEC_SEVERITY[f["severity"]], "tags": ["security"] + ([f["cwe"]] if f.get("cwe") else [])}
        rules.append({"id": f["id"], "name": re.sub(r"[^A-Za-z0-9]+", "", f["title"].title())[:100] or f["id"],
                      "shortDescription": {"text": f["title"][:300]},
                      "fullDescription": {"text": redact(f.get("description") or f["title"])[:2000]},
                      "help": {"text": redact(f.get("remediation") or "")[:4000] or "See the report."},
                      "properties": props})
        results.append({"ruleId": f["id"], "level": SARIF_LEVEL[f["severity"]],
                        "message": {"text": f"{f['title']} ({f['severity']}, {f['status']})"},
                        "locations": _locations(f),
                        "partialFingerprints": {"rvkitFinding/v1": f"{eng}:{f['id']}"},
                        "properties": {"findingRevision": f["revision"], "status": f["status"],
                                       "priority": f.get("priority"), "reportRevision": rid}})
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "RiskVoid agent kit", "informationUri":
                                          "https://github.com/RiskVoid/Security-Agent-Kit", "rules": rules}},
                      "results": results, "properties": {"engagement": eng, "reportRevision": rid}}]}


def export(eng, actor, rid=None, draft=False):
    """JSON, SARIF and issue-ready text for the findings of a report revision, from its frozen inputs: the approved
    revision by default; draft=True exports the latest revision, marked DRAFT."""
    revs = revisions(eng)
    if rid:
        rev = revision(eng, rid)
    else:
        appr = [r for r in revs if r["state"] == "approved"]
        rev = appr[0] if appr else (revs[0] if revs and draft else None)
    if not rev:
        raise ValueError("no approved report revision to export (approve one, or export the latest with draft)")
    if rev["state"] != "approved" and not draft:
        raise ValueError(f"{rev['id']} is {rev['state']}, not approved: export it with draft")
    if verify(eng, rev["id"])["problems"]:
        raise ValueError(f"{rev['id']}'s files don't match their recorded hashes")
    inp = json.load(open(_rdir(eng, "revisions", rev["id"], "inputs.json")))
    from redact import redact
    fs = sorted([f for f in inp["findings"] if f["status"] in ("confirmed", "fixed", "accepted-risk")],
                key=lambda f: (db.SEVERITIES.index(f["severity"]), f["id"]))
    label = "" if rev["state"] == "approved" else "-DRAFT"
    out = _rdir(eng, "exports", rev["id"] + label)
    os.makedirs(os.path.join(out, "issues"), exist_ok=True)
    keep = ("id", "revision", "title", "severity", "cvss_vector", "cvss_score", "cwe", "asset", "status", "priority",
            "verification", "verified_method", "prerequisites", "description", "impact", "reproduction",
            "remediation", "evidence", "instances", "root_cause", "updated")
    doc = {"schema": "rvkit-findings/1", "engagement": eng, "report_revision": rev["id"], "state": rev["state"],
           "approved_by": rev.get("approved_by"), "approved_at": rev.get("approved_at"), "exported_at": _now(),
           "findings": [{k: (redact(f[k]) if isinstance(f.get(k), str) else f.get(k)) for k in keep} for f in fs]}
    files = {"findings.json": json.dumps(doc, indent=1, default=str),
             "findings.sarif": json.dumps(sarif(eng, rev["id"], fs), indent=1)}
    for f in fs:
        files[f"issues/{f['id']}.md"] = _finding_text(f) + f"\nFrom report revision {rev['id']} ({rev['state']}).\n"
    hashes = {}
    for name, text in files.items():
        with open(os.path.join(out, name), "w") as fh:
            fh.write(text)
        hashes[name] = hashlib.sha256(text.encode()).hexdigest()
    return {"revision": rev["id"], "state": rev["state"], "folder": os.path.relpath(out, db.engagement_dir(eng)),
            "files": hashes, "findings": [f"{f['id']} rev {f['revision']}" for f in fs]}
