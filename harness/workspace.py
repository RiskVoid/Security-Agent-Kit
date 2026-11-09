"""The investigation workspace (RW-015 to RW-018), on top of findings.db (findings_db.py, schema 3).

  observations  import a tool's output file (parsers in observations.py) or add one by hand; triage each one: link
                it to a finding as an affected instance, mark it a duplicate of another observation, or dismiss it
                with a reason. Re-importing the same output doesn't create copies (fingerprints); grouping by root
                cause is suggested, never applied automatically. Dismissed observations are not false-positive
                findings: false-positive counts come from findings only.
  coverage      plan items: what will be tested, why (hypothesis, standard references), with which operation and
                identity, and the outcome: tested (evidence), failed (a finding), blocked, excluded or
                not-applicable (rationale). When the build or the policy changes, items tested on the old one are
                marked stale for a retest.
  handover      where the investigation stands, computed from the records, plus an editable note.
"""
import datetime, hashlib, json, os, re

import findings_db as db
import observations as obsparse

MAX_IMPORT = 50 * 1024 * 1024
REF_RX = re.compile(r"^(ASVS V\d{1,2}(\.\d{1,2}){0,2}|WSTG-[A-Z]{4}-\d{2}|API\d{1,2}:2023|LLM\d{2}:2025|"
                    r"A\d{2}:2021|CWE-\d{1,4}|MASVS-[A-Z]+(-\d)?|[A-Za-z0-9 ._:-]{1,40})$")


def _now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def _next_id(con, table, prefix):
    n = con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] + 1
    return f"{prefix}-{n:03d}"


DENIED = {"report", "MANIFEST.sha256", "SCOPE.md", "RULES.md"}


def _rel(eng, path):
    base = db.engagement_dir(eng)
    rel = os.path.relpath(os.path.normpath(path if path.startswith("/") else os.path.join(base, path)), base)
    parts = rel.split(os.sep)
    if rel.startswith("..") or any(p.startswith(".") for p in parts) or parts[0] in DENIED \
            or parts[0].startswith(("findings.db", "audit")):
        raise ValueError(f"{path}: not a tool output of this engagement (a file under /work/{eng}/, not the "
                         "findings database, the audit log, the report or a hidden file)")
    full = os.path.join(base, rel)
    if not os.path.isfile(full):
        raise ValueError(f"{rel}: no such file")
    return rel, full


def _jl(v):
    try:
        return json.loads(v or "[]")
    except ValueError:
        return []


def _orow(r):
    d = dict(r)
    d["evidence"] = _jl(d.get("evidence"))
    return d


# ---------------------------------------------------------------- observations (RW-016)
def import_file(eng, path, actor, tool=None):
    rel, full = _rel(eng, path)
    if os.path.getsize(full) > MAX_IMPORT:
        raise ValueError(f"{rel} is larger than {MAX_IMPORT // 1024 // 1024} MB")
    raw = open(full, "rb").read()
    sha = hashlib.sha256(raw).hexdigest()
    res = obsparse.parse(rel, raw.decode("utf-8", "replace"), tool)
    with db._db(eng) as con:
        con.execute("BEGIN IMMEDIATE")
        iid = _next_id(con, "imports", "I")
        new = 0
        for o in res["observations"]:
            ev = [rel] + [e for e in o.pop("evidence", []) if e != rel]
            cur = con.execute("SELECT id, evidence FROM observations WHERE fingerprint=?", (o["fingerprint"],)).fetchone()
            if cur:
                old = _jl(cur["evidence"])
                con.execute("UPDATE observations SET seen=seen+1, evidence=?, updated=? WHERE id=?",
                            (json.dumps(old + [e for e in ev if e not in old]), _now(), cur["id"]))
                continue
            oid = _next_id(con, "observations", "O")
            con.execute("INSERT INTO observations (id, tool, rule_id, title, severity, location, fingerprint, group_key, "
                        "evidence, detail, status, import_id, created, updated, actor) VALUES "
                        "(?,?,?,?,?,?,?,?,?,?,'new',?,?,?,?)",
                        (oid, o["tool"], o["rule_id"], o["title"], o["severity"], o["location"], o["fingerprint"],
                         o["group_key"], json.dumps(ev), o["detail"], iid, _now(), _now(), db._actor(actor)))
            new += 1
        con.execute("INSERT INTO imports VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (iid, res["parser"], rel, sha, res["parser"], obsparse.PARSER_VERSION, _now(), db._actor(actor),
                     len(res["observations"]), new, json.dumps(res["errors"]), json.dumps(res["limitations"])))
    return {"import": iid, "file": rel, "sha256": sha, "parser": res["parser"],
            "parser_version": obsparse.PARSER_VERSION, "observations": len(res["observations"]), "new": new,
            "already_known": len(res["observations"]) - new, "errors": res["errors"],
            "limitations": res["limitations"]}


def add_manual(eng, actor, title, location, detail="", severity="info", evidence=None, tool="manual"):
    """A researcher's own observation, or one from an external tool the researcher ran (tool names it)."""
    if not (title or "").strip() or not (location or "").strip():
        raise ValueError("an observation needs a title and a location (file:line, URL or component)")
    if severity not in db.SEVERITIES:
        raise ValueError(f"severity must be one of {db.SEVERITIES}")
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,39}", tool or ""):
        raise ValueError("tool: a short lower-case name")
    ev = []
    for p in evidence or []:
        ev.append(_rel(eng, p)[0])
    fp = obsparse.fingerprint(tool, "manual", location, title)
    with db._db(eng) as con:
        con.execute("BEGIN IMMEDIATE")
        if con.execute("SELECT 1 FROM observations WHERE fingerprint=?", (fp,)).fetchone():
            raise ValueError("the same observation (title and location) is already recorded")
        oid = _next_id(con, "observations", "O")
        con.execute("INSERT INTO observations (id, tool, rule_id, title, severity, location, fingerprint, group_key, "
                    "evidence, detail, status, created, updated, actor) VALUES (?,?,?,?,?,?,?,?,?,?,'new',?,?,?)",
                    (oid, tool, "manual", title.strip()[:300], severity, location.strip()[:500], fp,
                     f"manual:{obsparse.route_template(location) if '://' in location else location.split(':')[0]}",
                     json.dumps(ev), json.dumps({"detail": (detail or "")[:4000]}), _now(), _now(), db._actor(actor)))
        return _orow(con.execute("SELECT * FROM observations WHERE id=?", (oid,)).fetchone())


def list_observations(eng, status=None, tool=None, group_key=None, limit=500):
    q, a = "SELECT * FROM observations WHERE 1=1", []
    for col, v in (("status", status), ("tool", tool), ("group_key", group_key)):
        if v:
            q += f" AND {col}=?"; a.append(v)
    q += " ORDER BY CASE severity " + " ".join(f"WHEN '{s}' THEN {i}" for i, s in enumerate(db.SEVERITIES)) + \
         " ELSE 9 END, id LIMIT ?"
    a.append(int(limit))
    with db._db(eng) as con:
        return [_orow(r) for r in con.execute(q, a)]


def imports(eng):
    with db._db(eng) as con:
        out = []
        for r in con.execute("SELECT * FROM imports ORDER BY id"):
            d = dict(r)
            d["errors"], d["limitations"] = _jl(d["errors"]), _jl(d["limitations"])
            out.append(d)
        return out


def _obs_rows(con, ids):
    rows = []
    for i in ids:
        r = con.execute("SELECT * FROM observations WHERE id=?", (i,)).fetchone()
        if not r:
            raise ValueError(f"no observation {i}")
        rows.append(r)
    return rows


def link(eng, actor, ids, finding_id):
    """Observations become affected instances of a finding (their evidence is added to it)."""
    if not ids:
        raise ValueError("name the observations to link")
    with db._db(eng) as con:
        rows = _obs_rows(con, ids)
    f = db.get(eng, finding_id)
    if f["status"] == "duplicate":
        raise ValueError(f"{finding_id} is a duplicate of {f['duplicate_of']}: link to that one")
    inst, ev = list(f.get("instances") or []), list(f.get("evidence") or [])
    for r in rows:
        if not any(x.get("observation") == r["id"] for x in inst):
            inst.append({"observation": r["id"], "location": r["location"], "tool": r["tool"], "rule": r["rule_id"]})
        ev += [e for e in _jl(r["evidence"]) if e not in ev]
    row = db.update(eng, finding_id, actor=actor, instances=inst, evidence=ev)
    with db._db(eng) as con:
        for r in rows:
            con.execute("UPDATE observations SET status='linked', finding_id=?, duplicate_of=NULL, reason=NULL, "
                        "updated=?, actor=? WHERE id=?", (finding_id, _now(), db._actor(actor), r["id"]))
        db._decision(con, finding_id, "observations-linked", None, ",".join(ids), None, None, actor, row["revision"])
    return row


def dismiss(eng, actor, ids, reason):
    if not (reason or "").strip():
        raise ValueError("dismissing an observation needs a reason (why it isn't an issue)")
    with db._db(eng) as con:
        _obs_rows(con, ids)
        for i in ids:
            con.execute("UPDATE observations SET status='dismissed', reason=?, finding_id=NULL, updated=?, actor=? "
                        "WHERE id=?", (reason.strip()[:1000], _now(), db._actor(actor), i))
    return {"dismissed": ids}


def duplicate(eng, actor, ids, of):
    """The same issue as another observation (kept, counted once)."""
    with db._db(eng) as con:
        keep = _obs_rows(con, [of])[0]
        if keep["status"] == "duplicate":
            raise ValueError(f"{of} is itself a duplicate of {keep['duplicate_of']}: point to that one")
        _obs_rows(con, ids)
        if of in ids:
            raise ValueError("an observation can't be a duplicate of itself")
        for i in ids:
            con.execute("UPDATE observations SET status='duplicate', duplicate_of=?, finding_id=?, updated=?, actor=? "
                        "WHERE id=?", (of, keep["finding_id"], _now(), db._actor(actor), i))
    return {"duplicates": ids, "of": of}


def reopen(eng, actor, ids):
    with db._db(eng) as con:
        _obs_rows(con, ids)
        for i in ids:
            con.execute("UPDATE observations SET status='new', reason=NULL, duplicate_of=NULL, finding_id=NULL, "
                        "updated=?, actor=? WHERE id=?", (_now(), db._actor(actor), i))
    return {"reopened": ids}


def suggest_groups(eng):
    """Untriaged observations that probably share a root cause, and ones matching an already linked group."""
    with db._db(eng) as con:
        rows = [dict(r) for r in con.execute("SELECT id, group_key, status, finding_id, title, location FROM "
                                             "observations WHERE status IN ('new', 'linked')")]
    groups = {}
    for r in rows:
        groups.setdefault(r["group_key"], []).append(r)
    out = []
    for key, rs in sorted(groups.items()):
        new = [r for r in rs if r["status"] == "new"]
        linked = sorted({r["finding_id"] for r in rs if r["status"] == "linked" and r["finding_id"]})
        if not new or (len(new) < 2 and not linked):
            continue
        out.append({"group_key": key, "observations": [r["id"] for r in new], "titles": sorted({r["title"]
                                                                                              for r in new})[:5],
                    "suggestion": (f"link to {', '.join(linked)} (same group as observations already linked)"
                                   if linked else f"{len(new)} observations may share one root cause: review them "
                                   "together, then link the real ones to one finding")})
    return out


# ---------------------------------------------------------------- coverage (RW-015)
def _prow(r):
    d = dict(r)
    for k in ("refs", "prerequisites", "evidence"):
        d[k] = _jl(d.get(k))
    d["stale"] = bool(d["stale"])
    return d


def _refs(refs):
    refs = [str(x).strip() for x in refs or [] if str(x).strip()]
    bad = [x for x in refs if not REF_RX.match(x)]
    if bad:
        raise ValueError(f"references look like 'ASVS V8.2.1', 'WSTG-ATHZ-04', 'API1:2023', 'LLM01:2025', 'CWE-639': "
                         f"{', '.join(bad)}")
    return refs[:20]


def plan_add(eng, actor, items):
    if not isinstance(items, list) or not items or len(items) > 300:
        raise ValueError("items: 1 to 300 planned tests")
    ids = []
    with db._db(eng) as con:
        con.execute("BEGIN IMMEDIATE")
        for it in items:
            if not isinstance(it, dict) or not str(it.get("title", "")).strip():
                raise ValueError("each item needs a title")
            pid = _next_id(con, "plan_items", "P")
            con.execute("INSERT INTO plan_items (id, title, area, refs, hypothesis, prerequisites, operation, identity, "
                        "playbook, playbook_version, created, updated, updated_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (pid, str(it["title"]).strip()[:300], str(it.get("area") or "")[:100],
                         json.dumps(_refs(it.get("refs"))), str(it.get("hypothesis") or "")[:2000],
                         json.dumps([str(x)[:300] for x in it.get("prerequisites") or []][:20]),
                         str(it.get("operation") or "")[:300], str(it.get("identity") or "")[:64],
                         str(it.get("playbook") or "")[:64], str(it.get("playbook_version") or "")[:64],
                         _now(), _now(), db._actor(actor)))
            ids.append(pid)
    return ids


def plan_update(eng, actor, pid, expected_revision=None, **f):
    allowed = {"state", "rationale", "evidence", "finding_id", "build", "policy_revision", "title", "hypothesis",
               "operation", "identity", "refs", "prerequisites", "area"}
    extra = set(f) - allowed
    if extra:
        raise ValueError(f"unknown fields: {', '.join(sorted(extra))}")
    with db._db(eng) as con:
        con.execute("BEGIN IMMEDIATE")
        cur = con.execute("SELECT * FROM plan_items WHERE id=?", (pid,)).fetchone()
        if not cur:
            raise ValueError(f"no plan item {pid}")
        if expected_revision is not None and int(expected_revision) != cur["revision"]:
            raise db.Conflict(f"{pid} changed since you loaded it (now revision {cur['revision']})")
        new = _prow(cur)
        new.update({k: v for k, v in f.items() if v is not None})
        st = new["state"]
        if st not in db.COVERAGE:
            raise ValueError(f"state must be one of {db.COVERAGE}")
        if "evidence" in f:
            new["evidence"] = [_rel(eng, p)[0] for p in f["evidence"] or []]
        if "refs" in f:
            new["refs"] = _refs(f["refs"])
        if st == "tested" and not new["evidence"]:
            raise ValueError("tested needs evidence (the files that show the test and its result)")
        if st == "failed":
            if not new.get("finding_id"):
                raise ValueError("failed needs the finding it produced (finding_id)")
            db.get(eng, new["finding_id"])
        if st in ("blocked", "excluded", "not-applicable") and not (new.get("rationale") or "").strip():
            raise ValueError(f"{st} needs a rationale (why, and what would unblock or justify it)")
        stale = new["stale"] and not (st != cur["state"] or "build" in f or "policy_revision" in f)
        con.execute("UPDATE plan_items SET title=?, area=?, refs=?, hypothesis=?, prerequisites=?, operation=?, "
                    "identity=?, state=?, rationale=?, evidence=?, finding_id=?, build=?, policy_revision=?, stale=?, "
                    "stale_reason=?, revision=revision+1, updated=?, updated_by=? WHERE id=?",
                    (new["title"], new["area"], json.dumps(new["refs"]), new["hypothesis"],
                     json.dumps(new["prerequisites"]), new["operation"], new["identity"], st, new.get("rationale"),
                     json.dumps(new["evidence"]), new.get("finding_id"), new.get("build"), new.get("policy_revision"),
                     int(stale), new["stale_reason"] if stale else None, _now(), db._actor(actor), pid))
        return _prow(con.execute("SELECT * FROM plan_items WHERE id=?", (pid,)).fetchone())


def plan_list(eng, state=None):
    q, a = "SELECT * FROM plan_items", []
    if state:
        q += " WHERE state=?"; a.append(state)
    with db._db(eng) as con:
        return [_prow(r) for r in con.execute(q + " ORDER BY id", a)]


def playbook_items(text, name):
    """Plan items from a playbook's checklist: one per `- [ ]` line, the section heading as the area, standard
    references found in the text. Returns (version, items)."""
    head = text.split("---")[1] if text.startswith("---") else ""
    meta = dict(l.split(":", 1) for l in head.strip().splitlines() if ":" in l)
    version = (meta.get("version") or "").strip() or "sha-" + hashlib.sha256(text.encode()).hexdigest()[:12]
    items, area, area_refs, cur = [], "", [], None
    for line in text.splitlines():
        if cur is not None and line.startswith((" ", "\t")) and line.strip():
            cur["_text"] += " " + line.strip()  # a checklist item continues on the indented lines below it
            continue
        cur = None
        h = re.match(r"^##\s+(?:\d+\.\s*)?(.+)", line)
        if h:
            area = re.sub(r"\s*\(.*\)\s*$", "", h.group(1)).strip()
            # a section's heading names the categories its items cover: (API1 BOLA, API3 ...), (LLM01)
            area_refs = [f"API{x}:2023" for x in re.findall(r"\bAPI(\d{1,2})\b(?!:)", h.group(1))] + \
                [f"LLM{x}:2025" for x in re.findall(r"\bLLM(\d{2})\b(?!:)", h.group(1))]
            continue
        m = re.match(r"^\s*- \[[ x]\]\s+(.+)", line)
        if not m:
            continue
        title = m.group(1).strip()
        cur = {"title": re.sub(r"`([^`]*)`", r"\1", title)[:300], "area": area[:100], "_text": title, "_area_refs": area_refs,
               "playbook": name, "playbook_version": version}
        items.append(cur)
    for i in items:
        text_ = i.pop("_text")
        refs = [f"ASVS {x}" for x in re.findall(r"\bASVS (V\d{1,2}(?:\.\d+){0,2})\b", text_)] + \
            re.findall(r"\bWSTG-[A-Z]{4}(?:-\d{2})?\b", text_) + re.findall(r"\bAPI\d{1,2}:2023\b", text_) + \
            re.findall(r"\bLLM\d{2}:2025\b", text_) + re.findall(r"\bCWE-\d+\b", text_)
        i["refs"] = list(dict.fromkeys(refs + i.pop("_area_refs")))
    return version, items


def reassess(eng, actor, build=None, policy_revision=None):
    """The build or the policy changed: tested and failed items recorded against another one become stale."""
    if not build and not policy_revision:
        raise ValueError("give the current build (source digest or deployed build) and/or policy revision")
    n = 0
    with db._db(eng) as con:
        con.execute("BEGIN IMMEDIATE")
        for r in con.execute("SELECT * FROM plan_items WHERE state IN ('tested', 'failed')").fetchall():
            why = []
            if build and r["build"] and r["build"] != build:
                why.append(f"build changed ({r['build'][:12]} -> {build[:12]})")
            if policy_revision and r["policy_revision"] and str(r["policy_revision"]) != str(policy_revision):
                why.append(f"policy revision changed ({r['policy_revision']} -> {policy_revision})")
            if why:
                con.execute("UPDATE plan_items SET stale=1, stale_reason=?, updated=?, updated_by=? WHERE id=?",
                            ("; ".join(why) + ": retest", _now(), db._actor(actor), r["id"]))
                n += 1
        for k, v in (("current_build", build), ("current_policy_revision", policy_revision)):
            if v:
                con.execute("INSERT OR REPLACE INTO workspace VALUES (?,?,?,?)", (k, str(v), _now(), actor))
    return {"stale": n}


def coverage(eng):
    items = plan_list(eng)
    by = {s: [i for i in items if i["state"] == s] for s in db.COVERAGE}
    refs = {}
    for i in items:
        for r in i["refs"]:
            std = r.split()[0] if r.startswith("ASVS") else r.split("-")[0] if r.startswith(("WSTG", "CWE")) else \
                f"{r[:3]} Top 10 {r.split(':')[-1]}" if ":" in r else r
            refs.setdefault(std, {s: 0 for s in db.COVERAGE})[i["state"]] += 1
    return {"total": len(items), "counts": {s: len(v) for s, v in by.items()},
            "stale": [{"id": i["id"], "title": i["title"], "why": i["stale_reason"]} for i in items if i["stale"]],
            "blocked": [{"id": i["id"], "title": i["title"], "why": i["rationale"]} for i in by["blocked"]],
            "open": [{"id": i["id"], "title": i["title"], "area": i["area"]} for i in by["planned"]],
            "by_standard": refs,
            "note": "OWASP Top 10 lists are risk categories, not checklists: coverage is measured against the "
                    "planned tests and the ASVS/WSTG requirements they reference."}


# ---------------------------------------------------------------- workspace values and handover (RW-018)
def get_value(eng, key):
    with db._db(eng) as con:
        r = con.execute("SELECT * FROM workspace WHERE key=?", (key,)).fetchone()
        return dict(r) if r else None


def set_value(eng, actor, key, value, expected_digest=None):
    cur = get_value(eng, key)
    cur_v = cur["value"] if cur else ""
    if expected_digest is not None and expected_digest != hashlib.sha256(cur_v.encode()).hexdigest()[:16]:
        raise db.Conflict(f"{key} changed since you loaded it: reload and apply your change again")
    with db._db(eng) as con:
        con.execute("INSERT OR REPLACE INTO workspace VALUES (?,?,?,?)", (key, value, _now(), db._actor(actor)))
    return {"key": key, "digest": hashlib.sha256(value.encode()).hexdigest()[:16]}


def handover(eng):
    """Where the investigation stands, from the authoritative records, plus the editable note."""
    findings = db.list_(eng)
    obs = list_observations(eng, limit=100000)
    cov = coverage(eng)
    imps = imports(eng)
    objective = get_value(eng, "objective")
    note = get_value(eng, "handover")
    st = {s: [f for f in findings if f["status"] == s] for s in db.STATUSES}
    pending = []
    for f in st["candidate"]:
        pending.append({"kind": "verify-candidate", "ref": f["id"], "what": f"verify {f['id']} ({f['severity']}): "
                        f"{f['title']}"})
    for f in st["confirmed"]:
        if f.get("verified_method") in (None, "not stated"):
            pending.append({"kind": "verification-method", "ref": f["id"],
                            "what": f"{f['id']} is confirmed without a recorded verification method"})
        if not f.get("priority"):
            pending.append({"kind": "priority", "ref": f["id"], "what": f"{f['id']} has no remediation priority"})
    new_obs = [o for o in obs if o["status"] == "new"]
    if new_obs:
        pending.append({"kind": "triage-observations", "ref": ",".join(o["id"] for o in new_obs[:20]),
                        "what": f"{len(new_obs)} observation(s) not triaged"})
    for s in cov["stale"]:
        pending.append({"kind": "retest", "ref": s["id"], "what": f"{s['id']} {s['title']}: {s['why']}"})
    parse_problems = [f"{i['id']} {i['path']}: {len(i['errors'])} parser error(s)" for i in imps if i["errors"]]
    nxt = []
    if not objective:
        nxt.append("Set the objective (what this engagement must answer).")
    if not cov["total"]:
        nxt.append("Create the plan: plan items from the playbooks that match the scope.")
    nxt += [p["what"] for p in pending[:8]]
    if cov["open"]:
        nxt.append(f"{len(cov['open'])} planned test(s) not run yet, next: {cov['open'][0]['id']} "
                   f"{cov['open'][0]['title']}")
    return {"objective": objective["value"] if objective else None,
            "findings": {s: len(v) for s, v in st.items()},
            "material": [{"id": f["id"], "title": f["title"], "severity": f["severity"], "status": f["status"]}
                         for f in findings if f["severity"] in ("critical", "high") and f["status"] in
                         ("candidate", "confirmed")],
            "observations": {s: sum(1 for o in obs if o["status"] == s) for s in ("new", "linked", "duplicate",
                                                                                  "dismissed")},
            "coverage": {k: cov[k] for k in ("total", "counts", "stale", "blocked")},
            "imports": len(imps), "parse_problems": parse_problems, "pending": pending, "next": nxt,
            "note": note["value"] if note else "",
            "note_digest": hashlib.sha256((note["value"] if note else "").encode()).hexdigest()[:16],
            "note_updated": note and {"at": note["updated"], "by": note["actor"]}}


def handover_markdown(eng, h=None):
    h = h or handover(eng)
    lines = [f"# Handover: {eng}", "", f"Objective: {h['objective'] or 'not set'}", "",
             "Findings: " + (", ".join(f"{k} {v}" for k, v in h["findings"].items() if v) or "none"),
             "Coverage: " + (", ".join(f"{k} {v}" for k, v in h["coverage"]["counts"].items() if v) or "no plan yet"),
             "Observations: " + (", ".join(f"{k} {v}" for k, v in h["observations"].items() if v) or "none"), ""]
    if h["material"]:
        lines += ["## Material findings"] + [f"- {m['id']} [{m['severity']}, {m['status']}] {m['title']}"
                                            for m in h["material"]] + [""]
    if h["pending"]:
        lines += ["## Pending decisions"] + [f"- {p['what']}" for p in h["pending"][:30]] + [""]
    if h["coverage"]["blocked"]:
        lines += ["## Blocked"] + [f"- {b['id']} {b['title']}: {b['why']}" for b in h["coverage"]["blocked"]] + [""]
    if h["parse_problems"]:
        lines += ["## Import problems"] + [f"- {p}" for p in h["parse_problems"]] + [""]
    lines += ["## Next"] + [f"- {n}" for n in h["next"]] + [""]
    if h["note"]:
        lines += ["## Notes", h["note"], ""]
    return "\n".join(lines)
