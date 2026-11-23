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
import quotecheck

MAX_IMPORT = 50 * 1024 * 1024
REF_RX = re.compile(r"^(ASVS V\d{1,2}(\.\d{1,2}){0,2}|WSTG-[A-Z]{4}-\d{2}|API\d{1,2}:2023|LLM\d{2}:2025|"
                    r"A\d{2}:2021|CWE-\d{1,4}|MASVS-[A-Z]+(-\d)?|[A-Za-z0-9 ._:-]{1,40})$")


def _now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def _next_id(con, table, prefix):
    n = con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] + 1
    return f"{prefix}-{n:03d}"


DENIED = {"report", "MANIFEST.sha256", "SCOPE.md", "RULES.md"}


def _path_only(base, path):
    """An evidence entry as its path: agents write "evidence/runs/x.txt (no WAF seen)", "x.txt: no WAF seen" or
    "x.txt:12". When the text as given isn't a file, the note after the path, the punctuation that ends it and a
    trailing line number are dropped. Refusing such an entry with "no such file" made agents move or re-create
    files that were there all along."""
    p = str(path or "").strip()
    is_file = lambda x: bool(x) and os.path.isfile(x if x.startswith("/") else os.path.join(base, x))  # noqa: E731
    if is_file(p):
        return p
    head = re.split(r"\s", p, maxsplit=1)[0] if p else p
    for cand in (head, head.rstrip(":,;"), re.sub(r":\d+(?:-\d+)?$", "", head.rstrip(":,;"))):
        if is_file(cand):
            return cand
    return head.rstrip(":,;") or head or p


SRC_ENTRY = re.compile(r"(/src/[^\s:`'\"()<>]+?)[:,;]?(?::(\d+)(?:-(\d+))?)?[:,;]?(?=\s|$)")


def _source(path):
    """A source file as evidence of a planned test: "/src/<repo>/<file>", with or without ":<line>" or
    ":<from>-<to>" and a note after it. Returns the entry without the note, or None when it isn't a source path.
    In a source review the code is what shows a test's result ("no auth layer in app.py"); refusing it as "not a
    tool output" sent the planner looking for a tool output to cite instead. The file and the lines must exist
    (unchecked where /src isn't mounted)."""
    m = SRC_ENTRY.match(str(path or "").strip())
    if not m:
        return None
    file, a, b = m.groups()
    entry = file + (f":{a}" + (f"-{b}" if b else "") if a else "")
    root = quotecheck.SRC
    if not os.path.isdir(root):
        return entry
    full = os.path.realpath(os.path.join(root, file[len("/src/"):]))
    if not full.startswith(os.path.realpath(root) + os.sep) or not os.path.isfile(full):
        raise ValueError(f"{file}: no such file")
    if a:
        n = quotecheck._read(full).count("\n") + 1
        if int(a) < 1 or int(b or a) > n:
            raise ValueError(f"{entry}: the file has {n} lines")
    return entry


def _evidence(eng, path):
    """An evidence entry of a plan item or a hand-written observation as it is stored: a tool output of the
    engagement (its path in the engagement folder) or a source file under /src."""
    return _source(path) or _rel(eng, path)[0]


def _rel(eng, path):
    base = db.engagement_dir(eng)
    path = _path_only(base, path)
    rel = os.path.relpath(os.path.normpath(path if path.startswith("/") else os.path.join(base, path)), base)
    parts = rel.split(os.sep)
    if rel.startswith("..") or any(p.startswith(".") for p in parts) or parts[0] in DENIED \
            or parts[0].startswith(("findings.db", "audit")):
        raise ValueError(f"{path}: not a tool output of this engagement (a file under /work/{eng}/ or a source "
                         "file under /src/, not the findings database, the audit log, the report or a hidden file)")
    full = os.path.join(base, rel)
    # the agent can make links in its folder: what the link leads to must pass the same checks
    real = os.path.relpath(os.path.realpath(full), os.path.realpath(base))
    rparts = real.split(os.sep)
    if real.startswith("..") or any(p.startswith(".") for p in rparts) or rparts[0] in DENIED \
            or rparts[0].startswith(("findings.db", "audit")):
        raise ValueError(f"{path}: leads outside the engagement's tool outputs (a link to {real})")
    if "/evidence/tasks/" in str(path) or rel.startswith("evidence/tasks" + os.sep) or "evidence/tasks/" in rel:
        # worker step files are records of the run, not evidence (the worker result's run_evidence names the
        # evidence/runs/ and evidence/source/ files its commands produced); a planner cited a transcript twice
        raise ValueError(f"{path}: worker step files under evidence/tasks/ are transcripts, not evidence: cite "
                         "the evidence/runs/ or evidence/source/ file the task's command produced (the task "
                         "result's run_evidence names them)")
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
        ev.append(_evidence(eng, p))
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


def _map_refs(eng, refs):
    """Map entry ids (E-xxxxxx) in a plan item's refs must be entries of the recon map (reconmap.py, #46)."""
    import reconmap
    bad = reconmap.check_refs(eng, refs)
    if bad:
        raise ValueError(f"not entries of the recon map: {', '.join(bad)} (get_map lists them; recon_map builds it)")


def plan_add(eng, actor, items):
    if not isinstance(items, list) or not items or len(items) > 300:
        raise ValueError("items: 1 to 300 planned tests")
    _map_refs(eng, [r for it in items if isinstance(it, dict) for r in it.get("refs") or []])
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
            new["evidence"] = [_evidence(eng, p) for p in f["evidence"] or []]
        if "refs" in f:
            new["refs"] = _refs(f["refs"])
            _map_refs(eng, new["refs"])
        if st == "tested" and not new["evidence"]:
            raise ValueError("tested needs evidence (the files that show the test and its result)")
        if st == "tested":
            # #72: an item without map references covers no coverage-matrix cell, so marking it tested would
            # hide the gap. Only when a recon map exists — a source review has no entries to reference — and
            # only for an item that names a vulnerability class (its area, refs or title): orientation and
            # checklist items legitimately have no refs, and refusing them made runs burn calls on items that
            # were never meant to cover a cell (#174).
            import reconmap
            if reconmap.has_map(eng) and not any(reconmap.ENTRY_RX.match(r) for r in new["refs"]) \
                    and reconmap._class_of(new):
                raise ValueError(f"{pid} tests {', '.join(reconmap._class_of(new))} and references no recon map "
                                 "entry, so it covers no coverage-matrix cell: add refs (E-xxxxxx from get_map) "
                                 "when planning it, or mark it not-applicable with a rationale for why the class "
                                 "can't apply")
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
    with db._db(eng) as con:  # delivery records (RW-019 to RW-021)
        for r in con.execute("SELECT id, kind, what FROM obligations WHERE state='open' ORDER BY id"):
            pending.append({"kind": "cleanup", "ref": r["id"], "what": f"{r['id']} ({r['kind']}): {r['what']}"})
        for r in con.execute("SELECT id, finding_id FROM notices WHERE state='draft' ORDER BY id"):
            pending.append({"kind": "notice-review", "ref": r["id"],
                            "what": f"notice {r['id']} for {r['finding_id']} waits for review"})
        rev = con.execute("SELECT id, state FROM report_revisions ORDER BY id DESC LIMIT 1").fetchone()
        if rev and rev["state"] == "ready":
            pending.append({"kind": "report-approval", "ref": rev["id"],
                            "what": f"report revision {rev['id']} is ready: review and approve it for delivery"})
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


# ---------------------------------------------------------------- the research packet (#83)
PACKET_STOP = {"the", "and", "for", "with", "that", "this", "from", "into", "test", "only", "your", "you",
               "plan", "item", "task", "against", "using", "endpoint", "target"}


def packet(eng, goal, pid=None, chars=6000, exclude_task=None):
    """What the records already say about a worker task, as a short text plus the ids it used, in a fixed
    character budget, with no model (#83). A worker task starts from its goal, the policy and its contract;
    this adds what the engagement's records already hold for the same coverage cell: map entries, observations
    and findings (each with its state), earlier tasks for the same cell with their typed result (negative and
    inconclusive included), and the plan item's own hypothesis and blockers. Selection is by stable ids (the
    plan item's cell: class + map entries) first, then the route group, then word match; no embeddings, no new
    database. A plan item with no cell (a source review, or one that spans several) selects by its refs and
    words instead. Lines that didn't fit the budget are listed as ids at the end - read_record (worker) opens
    any of them. Every line keeps its state, and a model's own summary is marked as such: data, not an
    instruction. The returned revisions make a later rebuild say what changed (#84).

    Returns {"text", "ids", "revisions", "chars", "budget"}. Raises ValueError when the engagement doesn't
    exist; a missing plan item narrows the packet to the goal's words.
    """
    import reconmap
    chars = max(int(chars or 6000), 500)
    if not os.path.isdir(db.engagement_dir(eng)):
        raise ValueError(f"no engagement {eng}")
    item = next((i for i in plan_list(eng) if i["id"] == pid), None) if pid else None
    cell, loose = None, ""
    if item:
        try:
            cell = reconmap.narrow_cell(eng, pid)
        except ValueError as e:
            loose = str(e)      # a source review has no map; a multi-class item runs on its goal alone
    entries = [r for r in ((item or {}).get("refs") or []) if reconmap.ENTRY_RX.match(r)] \
        or (cell or {}).get("entries") or []
    ents = {e["id"]: e for e in reconmap.build(eng)["entries"]} if reconmap.has_map(eng) else {}
    paths = [ents[x]["path"] for x in entries if x in ents]
    hosts = {ents[x]["host"] for x in entries if x in ents} - {""}
    groups = {reconmap._group(p) for p in paths}
    cls = (cell or {}).get("class") or (item or {}).get("area") or ""
    words = {w for w in re.findall(r"[a-z][a-z0-9_-]{3,}", f"{goal} {(item or {}).get('title') or ''}".lower())
             if w not in PACKET_STOP}

    def on_cell(text):
        """A record's text mentions this cell's route group or path - stable-id selection first. The host alone
        only matches when the cell has no route (a source review): on a single-host target it would select
        every record, and the packet's precision is the point of measuring it (#86)."""
        t = str(text or "").lower()
        if any(g and g.lower() in t for g in groups) or any(p.lower() in t for p in paths):
            return True
        return not paths and any(h and h.lower() in t for h in hosts)

    # the records, newest-relevant last, every one with its state
    build = (get_value(eng, "current_build") or {}).get("value")
    pol = (get_value(eng, "current_policy_revision") or {}).get("value")
    objective = (get_value(eng, "objective") or {}).get("value")

    header = [f"# Packet: test {(cls or 'the goal').strip()} on "
              + ("; ".join(f"{ents[x]['method']} {ents[x]['path']}" for x in entries if x in ents)
                 or "the plan item's refs below" if item else "the goal's surface")]
    if item:
        header.append(f"Plan item {item['id']} ({item.get('state')}" + (", stale" if item.get("stale") else "")
                       + f"): {item['title']}")
    if objective:
        header.append(f"Objective: {objective[:300]}")
    if build or pol:
        header.append("Build " + (str(build)[:16] or "n/a") + f", policy revision {pol or 'n/a'}"
                      " - a record marked (stale) was recorded against another one")

    open_ = []
    if item:   # one row per item, so the id is always in the packet whatever else the item carries
        bits = [f"hypothesis: {item['hypothesis']}" if item.get("hypothesis") else "",
                "prerequisites: " + ", ".join(str(x) for x in item.get("prerequisites") or []) if
                item.get("prerequisites") else "",
                f"rationale: {item['rationale']}" if item.get("rationale") else ""]
        open_.append((item["id"], f"{item['id']} {item['state']}" + (" (stale)" if item.get("stale") else "")
                      + f" - {item['title'][:110]}" + (" - " + "; ".join(b for b in bits if b) if any(bits) else "")))
    tried, known_f, known_o = [], [], []
    for t in _packet_tasks(eng):
        if exclude_task and t.get("id") == exclude_task:
            continue                      # a task never starts from what itself did (#84)
        tcell = (t.get("contract") or {}).get("cell") or {}
        same = entries and set(tcell.get("entries") or []) & set(entries)
        if not same and not (cls and cls in (tcell.get("class") or "")):
            if not (words & {w for w in re.findall(r"[a-z][a-z0-9_-]{3,}", (t.get("goal") or "").lower())}):
                continue                      # neither the same cell nor the same subject
        status = t.get("result", {}).get("status") or t.get("status") or "run"
        summ = (t.get("result") or {}).get("summary") or t.get("last_text") or ""
        ev = ", ".join(str(p).split("/work/" + eng + "/")[-1] for p in (t.get("run_evidence") or [])[:3])
        identity = (tcell.get("identity") or t.get("identity") or "")
        notes = "; ".join(n["fact"][:110] for n in (t.get("notes") or [])[:3])
        line = (f"task {t['id']} {status}" + (f" as {identity}" if identity else "")
                + f" - {(t.get('goal') or '')[:110]} - worker summary (not a verified fact): {summ[:200]}"
                + (f" - agent notes (the worker's own, not verified facts): {notes[:240]}" if notes else "")
                + (f" - evidence: {ev}" if ev else ""))
        tried.append((t["id"], line))
    for f in db.list_(eng):
        title = f.get("title") or ""
        hit = on_cell(f.get("asset")) or on_cell(title) or \
            (not entries and words & {w for w in re.findall(r"[a-z][a-z0-9_-]{3,}",
                                                            f"{title} {f.get('asset')}".lower())})
        if not hit:
            continue
        state = f["status"] + (f", {f['verification']}" if f.get("verification") not in (None, "unverified") else "")
        known_f.append((f["id"], f"{f['id']} {state} ({f['severity']}) - {title[:120]}"
                        + (f" - asset {f['asset']}" if f.get("asset") else "")
                        + (" - worker summary, not a verified fact" if str(f.get("source", "")).startswith
                           ("worker:") else "")))
    for o in list_observations(eng, limit=2000):
        if (on_cell(o.get("location")) or on_cell(o.get("title")) or (not entries and words & {w for w in
                re.findall(r"[a-z][a-z0-9_-]{3,}", f"{o.get('title')} {o.get('location')}".lower())})):
            known_o.append((o["id"], f"{o['id']} {o['status']} ({o.get('severity')}) - {o['title'][:110]}"
                            + (f" - {o.get('location')}" if o.get("location") else "")
                            + (f" - dismissed: {o.get('reason')}" if o.get("reason") else "")))

    rows = ([("open", i, l) for i, l in open_] + [("tried", i, l) for i, l in tried]
            + [("findings", i, l) for i, l in known_f] + [("observations", i, l) for i, l in known_o])
    for x in entries:
        e = ents.get(x)
        if e:
            auth = e.get("auth") + (f" ({e['auth_basis']})" if e.get("auth_basis") else "")
            rows.insert(len(open_), ("entries", x, f"{x} {e['method']} {e['host']}{e['path']} - auth: {auth}"
                                       + (f"; params: {', '.join(sorted(e.get('params') or {}))}" if e.get("params")
                                          else "")
                                       + (f"; seen as: {', '.join(e['seen_by'])}" if e.get("seen_by") else "")))
    used = sum(len(h) for h in header) + sum(len(l) + 1 for _, _, l in rows)
    cut = []
    while used > chars and rows:
        kind, rid, line = rows.pop()
        cut.append(rid)
        used -= len(line) + 1
    text = "\n".join(header) + ("" if not rows else "\n\nWhat the records say (every line keeps its state):\n"
                                 + "\n".join(l for _, _, l in rows))
    if cut:
        text += f"\nNot included (budget): {', '.join(cut[:12])}" + (" ..." if len(cut) > 12 else "")
    ids = {k: [r for kk, r, _ in rows if kk == k] for k in ("entries", "open", "tried", "findings", "observations")}
    frev = {f["id"]: f["revision"] for f in db.list_(eng)}
    tstat = {t.get("id"): t.get("status") for t in _packet_tasks(eng)}
    return {"text": text, "ids": ids, "cut": cut, "chars": len(text), "budget": chars, "objective": bool(objective),
            "cell": {"class": cls, "entries": entries, "endpoints": paths,
                     "note": loose[:120]} if (cls or entries) else None,
            "revisions": {"plan_item": (item or {}).get("revision"),
                          "findings": {r: frev.get(r) for kk, r, _ in rows if kk == "findings"},
                          "tasks": {r: tstat.get(r) for kk, r, _ in rows if kk == "tried"},
                          "build": build, "policy_revision": pol}}


def _packet_tasks(eng):
    """Earlier worker tasks of the engagement, oldest first - their records, from evidence/tasks/."""
    out, d = [], os.path.join(db.engagement_dir(eng), "evidence", "tasks")
    for t in sorted(os.listdir(d)) if os.path.isdir(d) else []:
        try:
            out.append(json.load(open(os.path.join(d, t, "task.json"), errors="replace")))
        except (OSError, ValueError):
            pass
    return sorted(out, key=lambda x: x.get("started") or 0)


# ---------------------------------------------------------------- one search across the records (#116)
def recall(eng, query, kind="", state="", limit=20):
    """What this engagement knows that matches a query: observations, findings, plan items, map entries,
    earlier task results and ledger entries - one line per hit with its state and age, ids first (the query is
    an id), then the route group or path it names, then words. Same engagement only; the text is bounded, and
    target-controlled text arrives quoted through the records' own truncated lines. read_record (the worker)
    or the ops layer opens any hit in full."""
    import reconmap
    from ledger import entries as ledger_entries, norm as _norm
    q = str(query or "").strip()
    if not q:
        return "REFUSED: a query needs words or a record id"
    limit = max(1, min(int(limit or 20), 50))
    kinds = {k.strip().lower() for k in str(kind or "").split(",") if k.strip()} or None
    want_state = str(state or "").strip().lower()
    words = {w for w in re.findall(r"[a-z][a-z0-9_-]{3,}", q.lower()) if w not in PACKET_STOP}
    hits = []

    def take(k, rid, line, st):
        if kinds and k not in kinds:
            return
        if want_state and want_state not in str(st or "").lower():
            return
        hits.append(f"{rid} [{k}] {st or '-'} - {line}")

    rid = q if re.fullmatch(r"(?:[OFPE]-[0-9a-zA-Z]+|\d{8}-\d{6}-[0-9a-f]{4})", q) else ""
    for o in list_observations(eng, limit=5000):
        text = f"{o['title']} {o.get('location') or ''}"
        if (o["id"] == rid or (not rid and (words & {w for w in re.findall(r"[a-z][a-z0-9_-]{3,}", text.lower())} or
                                              q.lower() in text.lower()))):
            take("observation", o["id"], f"{o['title'][:90]}" + (f" at {o.get('location')}" if o.get("location")
                                                                 else ""), o["status"])
    for f in db.list_(eng):
        text = f"{f['title']} {f.get('asset') or ''}"
        st = f["status"] + (f", {f['verification']}" if f.get("verification") not in (None, "unverified") else "")
        if (f["id"] == rid or (not rid and (words & {w for w in re.findall(r"[a-z][a-z0-9_-]{3,}", text.lower())} or
                                             q.lower() in text.lower()))):
            take("finding", f["id"], f"{f['title'][:90]}" + (f" on {f['asset']}" if f.get("asset") else ""), st)
    for it in plan_list(eng):
        text = f"{it['title']} {' '.join(it.get('refs') or [])}"
        if (it["id"] == rid or (not rid and (words & {w for w in re.findall(r"[a-z][a-z0-9_-]{3,}", text.lower())} or
                                             q.lower() in text.lower()))):
            st = it["state"] + (" (stale)" if it.get("stale") else "")
            take("plan", it["id"], f"{it['title'][:90]}", st)
    if reconmap.has_map(eng):
        for e in reconmap.build(eng)["entries"]:
            text = f"{e['method']} {e['host']}{e['path']} {e.get('example') or ''}"
            if (e["id"] == rid or (not rid and (q.lower() in text.lower() or
                                                words & {w for w in re.findall(r"[a-z][a-z0-9_-]{3,}", text.lower())}))):
                take("map", e["id"], f"{e['method']} {e['host']}{e['path']}", e.get("auth"))
    for t in _packet_tasks(eng):
        text = f"{t.get('goal')} {(t.get('result') or {}).get('summary') or ''}"
        notes = " ".join(n.get("fact") or "" for n in t.get("notes") or [])
        if not rid and (words & {w for w in re.findall(r"[a-z][a-z0-9_-]{3,}", (text + " " + notes).lower())}
                        or q.lower() in text.lower()):
            st = (t.get("result") or {}).get("status") or t.get("status")
            line = f"task {(t.get('goal') or '')[:80]}"
            if t.get("notes"):
                line += " - agent notes: " + "; ".join(n["fact"][:90] for n in t["notes"][:3])
            take("task", t["id"], line, st)
    for e in ledger_entries(eng):
        if q.lower() in str(e.get("key") or "").lower():
            take("ledger", str(e.get("who") or "?"), f"{e['tool']} {str(e.get('key'))[:90]}"
                + (f" - {e['digest']}" if e.get("digest") else ""),
                "stale" if e.get("build") else ("reusable" if e.get("exit") in (0, "0", None) else str(e.get("exit"))))
    if not hits:
        return (f"nothing in {eng} matches {q!r}" + (f" of kind {sorted(kinds)}" if kinds else "")
                + ". The records are scoped to this engagement; read_record-style ids are O-..., F-..., P-..., "
                "E-...... or a task id.")
    return f"{len(hits[:limit])} match(es) in {eng} (read_record opens any by id):\n" + "\n".join(hits[:limit]) \
        + (f"\n... and {len(hits) - limit} more" if len(hits) > limit else "")
