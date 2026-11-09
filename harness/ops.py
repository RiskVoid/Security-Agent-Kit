"""Validated operations on an engagement's records, shared by the console, ./rvkit and the findings MCP server.

Each interface is an adapter over the same functions, so a finding, the report cover details or the executive
summary are checked the same way whoever changes them. Only the operations in OPS exist: callers name one and pass
JSON; nothing here runs code a caller supplies.

Every change names its actor (console:<user>, cli:<user>, agent:<name>) and can carry the revision the caller read
(expected_revision for a finding, expected_digest for a file). If the record changed since, the operation fails with
a conflict instead of overwriting the other change. A change returns an "event" (what changed, who, revisions
before and after): the console and ./rvkit record it in the engagement's audit log (rvctl record).

Command line (inside the findings-mcp container):
  python3 ops.py <operation>      request JSON on stdin: {"engagement": ..., "actor": ..., ...}
  prints {"result": ..., "event": {...} | null} or {"error": "...", "code": 400 | 404 | 409}; exit 0, 1 or 3
"""
import hashlib, json, os, sys

import findings_db as db
import workspace as ws

OPS = {}
META_KEYS = {"client": "Client", "prepared by": "Prepared by", "version": "Version", "classification": "Classification"}
FINDING_EDITABLE = tuple(f for f in db.FIELDS if f != "source")  # source records who created it
SUMMARY_MAX = 200_000


class OpError(ValueError):
    def __init__(self, msg, code=400):
        super().__init__(msg)
        self.code = code


def op(name, mutates=True):
    def deco(fn):
        OPS[name] = (fn, mutates)
        return fn
    return deco


def digest(text):
    return hashlib.sha256((text or "").encode()).hexdigest()[:16]


def _path(eng, *parts):
    return os.path.join(db.engagement_dir(eng), *parts)


def _read(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def _write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)


def _check_digest(current, expected, what):
    if expected is not None and expected != digest(current):
        raise OpError(f"{what}: changed by someone else since you loaded it. Reload and apply your change again", 409)


def _event(name, actor, target, before, after, **extra):
    return {"event": name, "actor": actor, "target": target, "before": before, "after": after, **extra}


# ---------------------------------------------------------------- findings
@op("finding.list", mutates=False)
def finding_list(engagement, actor=None, status=None, severity=None):
    return db.list_(engagement, status, severity), None


@op("finding.record")
def finding_record(engagement, actor, fields):
    if not isinstance(fields, dict):
        raise OpError("fields must be an object")
    unknown = set(fields) - set(db.FIELDS)
    if unknown:
        raise OpError(f"unknown fields: {', '.join(sorted(unknown))}")
    row = db.record(engagement, actor=actor, **_limit(fields))
    return row, _event("finding-recorded", actor, row["id"], None, row["revision"])


def _limit(fields):
    return {k: (v[:20_000] if isinstance(v, str) else v) for k, v in fields.items()}


@op("finding.update")
def finding_update(engagement, actor, id, fields, expected_revision=None, reason=None, method=None):
    if not isinstance(fields, dict):
        raise OpError("fields must be an object")
    unknown = set(fields) - set(FINDING_EDITABLE)
    if unknown:
        raise OpError(f"these fields can't be changed here: {', '.join(sorted(unknown))}")
    fields = _limit(fields)
    if fields.get("duplicate_of") == "":
        fields.pop("duplicate_of")
    if fields.get("title") is not None and not str(fields["title"]).strip():
        raise OpError("title can't be empty")
    if expected_revision is not None and not isinstance(expected_revision, int):
        raise OpError("expected_revision must be a number")
    if reason is not None and not isinstance(reason, str):
        raise OpError("reason must be text")
    try:
        row = db.update(engagement, id, expected_revision=expected_revision, actor=actor,
                        reason=(reason or "")[:2000] or None, method=method, **fields)
    except db.Conflict as e:
        raise OpError(str(e), 409)
    before = row.pop("previous_revision")
    return row, _event("finding-updated", actor, id, before, row["revision"], fields=sorted(fields),
                       **({"reason": reason[:300]} if reason else {}), **({"method": method} if method else {}))


@op("finding.history", mutates=False)
def finding_history(engagement, actor=None, id=None):
    return db.history(engagement, id or ""), None


@op("finding.not_reproducible")
def finding_not_reproducible(engagement, actor, id, reason):
    row = db.mark_not_reproducible(engagement, id, actor, reason)
    return row, _event("finding-not-reproducible", actor, id, None, row["revision"], reason=reason[:300])


# ---------------------------------------------------------------- observations (RW-016)
def _ids(ids):
    if not isinstance(ids, list) or not ids or not all(isinstance(i, str) and i.startswith("O-") for i in ids):
        raise OpError("ids: a list of observation ids (O-001...)")
    return ids[:500]


@op("observation.import")
def observation_import(engagement, actor, path, tool=None):
    r = ws.import_file(engagement, path, actor, tool or None)
    return r, _event("observations-imported", actor, r["file"], None, r["import"], parser=r["parser"],
                     observations=r["observations"], new=r["new"], errors=len(r["errors"]))


@op("observation.add")
def observation_add(engagement, actor, title, location, detail="", severity="info", evidence=None, tool="manual"):
    r = ws.add_manual(engagement, actor, title, location, detail, severity, evidence, tool)
    return r, _event("observation-added", actor, r["id"], None, None, tool=tool)


@op("observation.list", mutates=False)
def observation_list(engagement, actor=None, status=None, tool=None, group_key=None):
    return {"observations": ws.list_observations(engagement, status, tool, group_key),
            "imports": ws.imports(engagement), "groups": ws.suggest_groups(engagement)}, None


@op("observation.link")
def observation_link(engagement, actor, ids, finding_id):
    row = ws.link(engagement, actor, _ids(ids), finding_id)
    return row, _event("observations-linked", actor, finding_id, None, row["revision"], observations=ids)


@op("observation.dismiss")
def observation_dismiss(engagement, actor, ids, reason):
    return ws.dismiss(engagement, actor, _ids(ids), reason), _event("observations-dismissed", actor, ",".join(ids),
                                                                    None, None, reason=str(reason)[:300])


@op("observation.duplicate")
def observation_duplicate(engagement, actor, ids, of):
    return ws.duplicate(engagement, actor, _ids(ids), of), _event("observations-duplicate", actor, ",".join(ids),
                                                                  None, of)


@op("observation.reopen")
def observation_reopen(engagement, actor, ids):
    return ws.reopen(engagement, actor, _ids(ids)), _event("observations-reopened", actor, ",".join(ids), None, None)


# ---------------------------------------------------------------- coverage (RW-015)
@op("plan.add")
def plan_add(engagement, actor, items):
    ids = ws.plan_add(engagement, actor, items)
    return {"ids": ids}, _event("plan-items-added", actor, ",".join(ids[:20]), None, None, count=len(ids))


@op("plan.from_playbook")
def plan_from_playbook(engagement, actor, playbook):
    name = os.path.basename(str(playbook)).removesuffix(".md")
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "playbooks", name + ".md")
    if not os.path.isfile(path):
        raise OpError(f"unknown playbook {name!r}")
    version, items = ws.playbook_items(_read(path), name)
    have = {(i["playbook"], i["title"]) for i in ws.plan_list(engagement)}
    items = [i for i in items if (i["playbook"], i["title"]) not in have]
    ids = ws.plan_add(engagement, actor, items) if items else []
    return ({"playbook": name, "version": version, "ids": ids, "already_planned": len(have)},
            _event("plan-items-added", actor, name, None, version, count=len(ids)))


@op("plan.update")
def plan_update(engagement, actor, id, fields, expected_revision=None):
    if not isinstance(fields, dict):
        raise OpError("fields must be an object")
    try:
        r = ws.plan_update(engagement, actor, id, expected_revision, **fields)
    except db.Conflict as e:
        raise OpError(str(e), 409)
    return r, _event("coverage-updated", actor, id, None, r["revision"], state=r["state"])


@op("plan.list", mutates=False)
def plan_list(engagement, actor=None, state=None):
    return {"items": ws.plan_list(engagement, state), "coverage": ws.coverage(engagement)}, None


@op("coverage.reassess")
def coverage_reassess(engagement, actor, build=None, policy_revision=None):
    r = ws.reassess(engagement, actor, build, policy_revision)
    return r, _event("coverage-reassessed", actor, "coverage", None, None, stale=r["stale"],
                     build=build, policy_revision=policy_revision)


# ---------------------------------------------------------------- objective and handover (RW-018)
@op("workspace.objective")
def workspace_objective(engagement, actor, text, expected_digest=None):
    if not isinstance(text, str) or len(text) > 4000:
        raise OpError("the objective is text, up to 4000 characters")
    try:
        r = ws.set_value(engagement, actor, "objective", text.strip(), expected_digest)
    except db.Conflict as e:
        raise OpError(str(e), 409)
    return r, _event("objective-set", actor, "objective", None, r["digest"])


@op("handover.get", mutates=False)
def handover_get(engagement, actor=None):
    h = ws.handover(engagement)
    return {**h, "markdown": ws.handover_markdown(engagement, h)}, None


@op("investigation.get", mutates=False)
def investigation_get(engagement, actor=None):
    """Everything the console's Investigation view shows, in one call."""
    h = ws.handover(engagement)
    return {"handover": {**h, "markdown": ws.handover_markdown(engagement, h)},
            "objective": h["objective"] or "", "objective_digest": digest(h["objective"] or ""),
            "plan": ws.plan_list(engagement), "coverage": ws.coverage(engagement),
            "observations": ws.list_observations(engagement), "imports": ws.imports(engagement),
            "groups": ws.suggest_groups(engagement)}, None


@op("handover.save")
def handover_save(engagement, actor, text, expected_digest=None):
    if not isinstance(text, str) or len(text) > SUMMARY_MAX:
        raise OpError(f"the handover note is text, up to {SUMMARY_MAX} characters")
    try:
        r = ws.set_value(engagement, actor, "handover", text, expected_digest)
    except db.Conflict as e:
        raise OpError(str(e), 409)
    return r, _event("handover-saved", actor, "handover", None, r["digest"])


# ---------------------------------------------------------------- evidence preview (sanitized)
PREVIEW_MAX = 256 * 1024


@op("evidence.preview", mutates=False)
def evidence_preview(engagement, actor=None, path=""):
    """The start of an evidence file as text, with secrets redacted (the file itself is unchanged)."""
    from redact import redact
    base = db.engagement_dir(engagement)
    try:
        rel, _ = ws._rel(engagement, str(path).split(" ")[0])  # an evidence entry may carry a note after a space
    except ValueError as e:
        raise OpError(str(e), 404)
    raw = open(os.path.join(base, rel), "rb").read(PREVIEW_MAX + 1)
    binary = b"\0" in raw[:4096]
    text = "" if binary else redact(raw[:PREVIEW_MAX].decode("utf-8", "replace"))
    return {"path": rel, "binary": binary, "truncated": len(raw) > PREVIEW_MAX, "text": text,
            "size": os.path.getsize(os.path.join(base, rel)),
            "sha256": hashlib.sha256(open(os.path.join(base, rel), "rb").read()).hexdigest()}, None


# ---------------------------------------------------------------- report cover details and executive summary
def _meta(text):
    out = {}
    for line in text.splitlines():
        if ":" in line and not line.lstrip().startswith("#"):
            k, v = line.split(":", 1)
            out[k.strip().lower()] = v.strip()
    return out


@op("meta.get", mutates=False)
def meta_get(engagement, actor=None):
    text = _read(_path(engagement, "report", "meta.txt"))
    return {"meta": _meta(text), "digest": digest(text)}, None


@op("meta.set")
def meta_set(engagement, actor, fields, expected_digest=None):
    if not isinstance(fields, dict) or set(fields) - set(META_KEYS):
        raise OpError(f"cover details are: {', '.join(META_KEYS)}")
    p = _path(engagement, "report", "meta.txt")
    cur = _read(p)
    _check_digest(cur, expected_digest, "The cover details")
    vals = {k: str(v).replace("\r", " ").replace("\n", " ").strip()[:200] for k, v in fields.items()}
    out, seen = [], set()
    for line in cur.splitlines():
        k = line.split(":", 1)[0].strip().lower() if ":" in line and not line.lstrip().startswith("#") else None
        if k in vals:
            out.append(f"{META_KEYS[k]}: {vals[k]}"); seen.add(k)
        else:
            out.append(line)
    out += [f"{META_KEYS[k]}: {v}" for k, v in vals.items() if k not in seen]
    new = "\n".join(out) + "\n"
    _write(p, new)
    return ({"meta": _meta(new), "digest": digest(new)},
            _event("meta-updated", actor, "report/meta.txt", digest(cur), digest(new), fields=sorted(vals)))


@op("summary.get", mutates=False)
def summary_get(engagement, actor=None):
    text = _read(_path(engagement, "report", "executive-summary.md"))
    return {"text": text, "digest": digest(text)}, None


@op("summary.set")
def summary_set(engagement, actor, text, expected_digest=None):
    if not isinstance(text, str):
        raise OpError("text must be a string")
    if len(text) > SUMMARY_MAX:
        raise OpError(f"the executive summary is limited to {SUMMARY_MAX} characters")
    p = _path(engagement, "report", "executive-summary.md")
    cur = _read(p)
    _check_digest(cur, expected_digest, "The executive summary")
    _write(p, text)
    return ({"digest": digest(text)},
            _event("summary-updated", actor, "report/executive-summary.md", digest(cur), digest(text)))


# ---------------------------------------------------------------- report and evidence (report.py, this image only)
@op("report.build")
def report_build(engagement, actor):
    import report
    try:
        r = report.build(engagement)
    except ValueError as e:
        raise OpError(str(e))
    files = [os.path.basename(str(r[k])) for k in ("html", "docx", "pdf", "xlsx") if os.path.isfile(str(r.get(k)))]
    return r, _event("report-generated", actor, "report", None, r.get("status"), files=files,
                     findings=r.get("findings"))


@op("evidence.index", mutates=False)
def evidence_index(engagement, actor=None):
    import report
    f = [x for x in db.list_(engagement) if x["status"] not in ("false-positive", "duplicate")]
    items, issues = report.evidence_index(engagement, f)
    return {"items": items, "issues": issues}, None


# ---------------------------------------------------------------- dispatch
def call(name, req):
    """Run one operation. req: {"engagement", "actor", ...operation arguments}. Returns (result, event)."""
    if name not in OPS:
        raise OpError(f"unknown operation {name!r}", 404)
    if not isinstance(req, dict):
        raise OpError("the request must be a JSON object")
    fn, mutates = OPS[name]
    req = dict(req)
    eng, actor = req.pop("engagement", None), req.pop("actor", None)
    if mutates and not (isinstance(actor, str) and db.ACTOR_RX.match(actor)):
        raise OpError("changes need an actor: <console|cli|agent>:<name>")
    db.engagement_dir(eng or "")  # validates the name and that it exists
    try:
        return fn(eng, actor, **req)
    except TypeError as e:  # missing or unexpected arguments
        raise OpError(f"{name}: {e}")


def main(argv):
    if len(argv) != 1:
        print(__doc__); return 1
    try:
        req = json.load(sys.stdin)
        result, event = call(argv[0], req)
        print(json.dumps({"result": result, "event": event}, default=str)); return 0
    except OpError as e:
        print(json.dumps({"error": str(e), "code": e.code})); return 3 if e.code == 409 else 1
    except ValueError as e:  # findings_db validation, unknown engagement, bad JSON
        print(json.dumps({"error": str(e), "code": 400})); return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
