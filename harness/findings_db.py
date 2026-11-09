"""Findings store shared by the findings MCP (planner-facing) and the worker (candidates only).

One SQLite database per engagement: /work/<engagement>/findings.db

Schema versions (PRAGMA user_version), applied in order when a database is opened:
  1  findings table with duplicate_of (databases from before versioning get it added)
  2  revision (starts at 1, +1 on every change) and updated_by (the actor that made the last change)
  3  the investigation workspace (RW-015 to RW-018):
       findings gain verification (separate from status and severity), verified_by/method/at, remediation
       priority, reproduction prerequisites, affected instances and a root-cause key; CVSS 3.1 vectors are
       validated and the score computed from them
       finding_revisions  a snapshot of every revision of a finding (nothing is overwritten)
       decisions          who decided what about a finding and why (reasons are required for rejecting, accepting
                          a risk and changing severity or priority)
       observations       normalized tool and manual observations (observations.py), linked to findings as
                          instances; imports records each imported file with its parser errors and limitations
       plan_items         planned tests and their coverage outcome (tested, failed, blocked, excluded,
                          not-applicable), with evidence or rationale, the build and policy revision they ran on
       workspace          small key/value records: the current objective, the handover note
A database from a newer kit version is refused rather than written with an older schema.
Updates can carry expected_revision: when the finding changed in the meantime, Conflict is raised instead of
overwriting someone else's change.
"""
import datetime, json, os, re, sqlite3

WORK = "/work"
SEVERITIES = ("critical", "high", "medium", "low", "info")
STATUSES = ("candidate", "confirmed", "false-positive", "duplicate", "fixed", "accepted-risk")
VERIFICATION = ("unverified", "verified", "not-reproducible")
METHODS = ("runtime-reproduction", "replay", "authorization-matrix", "source-review", "tool-output", "retest",
           "client-confirmation", "not stated")
PRIORITIES = ("P1", "P2", "P3", "P4")   # remediation priority: the client's order of work, not the severity
NEEDS_REASON = ("false-positive", "accepted-risk")
COVERAGE = ("planned", "tested", "failed", "blocked", "excluded", "not-applicable")
SCHEMA_VERSION = 3
ACTOR_RX = re.compile(r"^(console|cli|agent|test):[A-Za-z0-9._@-]{1,64}$")
FIELDS = ("title", "severity", "cvss_vector", "cvss_score", "cwe", "asset", "description", "impact",
          "reproduction", "remediation", "evidence", "status", "source", "notes", "duplicate_of", "priority",
          "prerequisites", "instances", "root_cause")
JSON_FIELDS = ("evidence", "instances")


def engagement_dir(engagement: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9._-]+", engagement or "") or engagement.startswith("."):
        raise ValueError(f"invalid engagement name: {engagement!r}")
    path = os.path.join(WORK, engagement)
    if not os.path.isdir(path):
        raise ValueError(f"unknown engagement '{engagement}' (create it with ./rvkit engagement)")
    return path


class Conflict(ValueError):
    """The record changed since the caller read it."""


def _migrate(con: sqlite3.Connection) -> None:
    v = con.execute("PRAGMA user_version").fetchone()[0]
    if v > SCHEMA_VERSION:
        raise ValueError(f"findings.db has schema version {v}; this kit knows up to {SCHEMA_VERSION}: update the kit")
    if v == SCHEMA_VERSION:
        return
    cols = lambda: {r[1] for r in con.execute("PRAGMA table_info(findings)")}  # noqa: E731
    if v < 1:
        con.execute("""CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY, title TEXT NOT NULL, severity TEXT NOT NULL, cvss_vector TEXT, cvss_score REAL,
            cwe TEXT, asset TEXT, description TEXT, impact TEXT, reproduction TEXT, remediation TEXT,
            evidence TEXT DEFAULT '[]', status TEXT NOT NULL DEFAULT 'candidate', source TEXT, notes TEXT,
            created TEXT, updated TEXT)""")
        if "duplicate_of" not in cols():  # databases before v0.2
            con.execute("ALTER TABLE findings ADD COLUMN duplicate_of TEXT")
    if v < 2:
        if "revision" not in cols():
            con.execute("ALTER TABLE findings ADD COLUMN revision INTEGER NOT NULL DEFAULT 1")
        if "updated_by" not in cols():
            con.execute("ALTER TABLE findings ADD COLUMN updated_by TEXT")
    if v < 3:
        for col, decl in (("verification", "TEXT NOT NULL DEFAULT 'unverified'"), ("verified_by", "TEXT"),
                          ("verified_method", "TEXT"), ("verified_at", "TEXT"), ("priority", "TEXT"),
                          ("prerequisites", "TEXT"), ("instances", "TEXT DEFAULT '[]'"), ("root_cause", "TEXT")):
            if col not in cols():
                con.execute(f"ALTER TABLE findings ADD COLUMN {col} {decl}")
        con.executescript("""
            CREATE TABLE IF NOT EXISTS finding_revisions (finding_id TEXT NOT NULL, revision INTEGER NOT NULL,
                snapshot TEXT NOT NULL, actor TEXT, at TEXT, PRIMARY KEY (finding_id, revision));
            CREATE TABLE IF NOT EXISTS decisions (id INTEGER PRIMARY KEY AUTOINCREMENT, finding_id TEXT NOT NULL,
                kind TEXT NOT NULL, from_value TEXT, to_value TEXT, reason TEXT, method TEXT, actor TEXT, at TEXT,
                revision INTEGER);
            CREATE TABLE IF NOT EXISTS imports (id TEXT PRIMARY KEY, tool TEXT, path TEXT, sha256 TEXT, parser TEXT,
                parser_version INTEGER, at TEXT, actor TEXT, observations INTEGER, new INTEGER, errors TEXT,
                limitations TEXT);
            CREATE TABLE IF NOT EXISTS observations (id TEXT PRIMARY KEY, tool TEXT NOT NULL, rule_id TEXT,
                title TEXT NOT NULL, severity TEXT, location TEXT, fingerprint TEXT UNIQUE, group_key TEXT,
                evidence TEXT DEFAULT '[]', detail TEXT, status TEXT NOT NULL DEFAULT 'new', finding_id TEXT,
                duplicate_of TEXT, reason TEXT, seen INTEGER NOT NULL DEFAULT 1, import_id TEXT, created TEXT,
                updated TEXT, actor TEXT);
            CREATE TABLE IF NOT EXISTS plan_items (id TEXT PRIMARY KEY, title TEXT NOT NULL, area TEXT,
                refs TEXT DEFAULT '[]', hypothesis TEXT, prerequisites TEXT DEFAULT '[]', operation TEXT,
                identity TEXT, playbook TEXT, playbook_version TEXT, state TEXT NOT NULL DEFAULT 'planned',
                rationale TEXT, evidence TEXT DEFAULT '[]', finding_id TEXT, build TEXT, policy_revision TEXT,
                stale INTEGER NOT NULL DEFAULT 0, stale_reason TEXT, revision INTEGER NOT NULL DEFAULT 1,
                created TEXT, updated TEXT, updated_by TEXT);
            CREATE TABLE IF NOT EXISTS workspace (key TEXT PRIMARY KEY, value TEXT, updated TEXT, actor TEXT);
        """)
        for r in con.execute("SELECT * FROM findings").fetchall():  # history starts with what exists now
            con.execute("INSERT OR IGNORE INTO finding_revisions VALUES (?,?,?,?,?)",
                        (r["id"], r["revision"], json.dumps(dict(r)), r["updated_by"], r["updated"]))
    con.execute(f"PRAGMA user_version={SCHEMA_VERSION}")


def _db(engagement: str) -> sqlite3.Connection:
    con = sqlite3.connect(os.path.join(engagement_dir(engagement), "findings.db"), timeout=30)
    con.row_factory = sqlite3.Row
    with con:
        _migrate(con)
    return con


def _actor(actor):
    if actor is None:
        return None
    if not ACTOR_RX.match(str(actor)):
        raise ValueError(f"invalid actor {actor!r}: <console|cli|agent>:<name>")
    return actor


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------- CVSS 3.1 (base score, FIRST specification)
CVSS_W = {"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}, "AC": {"L": 0.77, "H": 0.44},
          "UI": {"N": 0.85, "R": 0.62}, "C": {"H": 0.56, "L": 0.22, "N": 0}, "I": {"H": 0.56, "L": 0.22, "N": 0},
          "A": {"H": 0.56, "L": 0.22, "N": 0}, "S": {"U": None, "C": None}, "PR": {"N": None, "L": None, "H": None}}
CVSS_OTHER = {"E": "XUPFH", "RL": "XOTWU", "RC": "XURC", "CR": "XLMH", "IR": "XLMH", "AR": "XLMH",
              "MAV": "XNALP", "MAC": "XLH", "MPR": "XNLH", "MUI": "XNR", "MS": "XUC", "MC": "XNLH", "MI": "XNLH",
              "MA": "XNLH"}


def _roundup(x):
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (i // 10000 + 1) / 10.0


def cvss31(vector: str) -> float:
    """The CVSS 3.1 base score of a vector; ValueError for a malformed vector."""
    v = (vector or "").strip()
    if not re.fullmatch(r"CVSS:3\.[01](/[A-Z]{1,3}:[A-Z])+", v):
        raise ValueError("cvss_vector must look like CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    m = {}
    for part in v.split("/")[1:]:
        k, val = part.split(":")
        if k in m:
            raise ValueError(f"cvss_vector: {k} given twice")
        if not ((k in CVSS_W and val in CVSS_W[k]) or (k in CVSS_OTHER and val in CVSS_OTHER[k])):
            raise ValueError(f"cvss_vector: {k}:{val} is not a CVSS 3.1 metric value")
        m[k] = val
    missing = [k for k in ("AV", "AC", "PR", "UI", "S", "C", "I", "A") if k not in m]
    if missing:
        raise ValueError(f"cvss_vector is missing {', '.join(missing)}")
    changed = m["S"] == "C"
    pr = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[m["PR"]]
    iss = 1 - (1 - CVSS_W["C"][m["C"]]) * (1 - CVSS_W["I"][m["I"]]) * (1 - CVSS_W["A"][m["A"]])
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    expl = 8.22 * CVSS_W["AV"][m["AV"]] * CVSS_W["AC"][m["AC"]] * pr * CVSS_W["UI"][m["UI"]]
    if impact <= 0:
        return 0.0
    return _roundup(min(1.08 * (impact + expl), 10)) if changed else _roundup(min(impact + expl, 10))


def cvss_rating(score):
    if score is None:
        return None
    return "none" if score == 0 else "low" if score < 4 else "medium" if score < 7 else "high" if score < 9 \
        else "critical"


def _clean(fields: dict) -> dict:
    out = {k: v for k, v in fields.items() if k in FIELDS and v is not None}
    if "severity" in out:
        out["severity"] = str(out["severity"]).lower()
        if out["severity"] not in SEVERITIES:
            raise ValueError(f"severity must be one of {SEVERITIES}")
    if "status" in out and out["status"] not in STATUSES:
        raise ValueError(f"status must be one of {STATUSES}")
    if out.get("priority") == "":
        out["priority"] = None
    if out.get("priority") is not None and out["priority"] not in PRIORITIES:
        raise ValueError(f"priority must be one of {PRIORITIES} (remediation order, separate from severity)")
    if out.get("cvss_vector") and str(out["cvss_vector"]).startswith("CVSS:4.0/"):
        # CVSS 4.0: the score comes from the FIRST calculator (not computed here); the vector's shape is checked
        if not re.fullmatch(r"CVSS:4\.0(/[A-Z]{1,3}:[A-Z])+", out["cvss_vector"].strip()):
            raise ValueError("cvss_vector: not a CVSS 4.0 vector")
        if out.get("cvss_score") not in (None, "") and not 0 <= float(out["cvss_score"]) <= 10:
            raise ValueError("cvss_score is 0.0 to 10.0")
    elif out.get("cvss_vector"):
        score = cvss31(out["cvss_vector"])
        given = out.get("cvss_score")
        if given not in (None, "") and abs(float(given) - score) > 0.05:
            raise ValueError(f"cvss_score {given} doesn't match the vector (CVSS 3.1 base score {score})")
        out["cvss_score"] = score
    elif out.get("cvss_score") not in (None, ""):
        s = float(out["cvss_score"])
        if not 0 <= s <= 10:
            raise ValueError("cvss_score is 0.0 to 10.0")
    for k in JSON_FIELDS:
        if k in out and not isinstance(out[k], str):
            out[k] = json.dumps(list(out[k]))
    return out


def _row(r: sqlite3.Row) -> dict:
    d = dict(r)
    for k in JSON_FIELDS:
        try:
            d[k] = json.loads(d.get(k) or "[]")
        except ValueError:
            pass
    if "cvss_score" in d:
        d["cvss_rating"] = cvss_rating(d["cvss_score"])
    return d


def _snapshot(con, finding_id, actor):
    r = con.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
    con.execute("INSERT OR REPLACE INTO finding_revisions VALUES (?,?,?,?,?)",
                (finding_id, r["revision"], json.dumps(dict(r)), actor, _now()))


def _decision(con, finding_id, kind, before, after, reason, method, actor, revision):
    con.execute("INSERT INTO decisions (finding_id, kind, from_value, to_value, reason, method, actor, at, revision) "
                "VALUES (?,?,?,?,?,?,?,?,?)", (finding_id, kind, before, after, reason, method, actor, _now(),
                                                revision))


def record(engagement: str, actor: str | None = None, **fields) -> dict:
    f = _clean(fields)
    if not f.get("title") or not f.get("severity"):
        raise ValueError("title and severity are required")
    with _db(engagement) as con:
        con.execute("BEGIN IMMEDIATE")  # ids are allocated under the write lock: concurrent writers don't collide
        n = con.execute("SELECT COUNT(*) FROM findings").fetchone()[0] + 1
        f.update(id=f"F-{n:03d}", created=_now(), updated=_now(), revision=1, updated_by=_actor(actor))
        f.setdefault("status", "candidate")
        con.execute(f"INSERT INTO findings ({','.join(f)}) VALUES ({','.join('?' * len(f))})", list(f.values()))
        _snapshot(con, f["id"], actor)
        _decision(con, f["id"], "recorded", None, f["status"], None, None, actor, 1)
        if f["status"] == "confirmed":
            _verify(con, f["id"], "not stated", actor)
        return _row(con.execute("SELECT * FROM findings WHERE id=?", (f["id"],)).fetchone())


def _verify(con, finding_id, method, actor):
    con.execute("UPDATE findings SET verification='verified', verified_by=?, verified_method=?, verified_at=? "
                "WHERE id=?", (actor, method, _now(), finding_id))


def update(engagement: str, finding_id: str, expected_revision: int | None = None, actor: str | None = None,
           reason: str | None = None, method: str | None = None, **fields) -> dict:
    """Change a finding. The result has the new row; result["previous_revision"] is the revision it replaced.

    reason: required to mark a finding false-positive or accepted-risk and to change its severity or priority.
    method: how a finding was verified (METHODS); recorded with the actor when it becomes confirmed."""
    f = _clean(fields)
    if not f:
        raise ValueError("nothing to update")
    reason = (reason or "").strip() or None
    if method is not None and method not in METHODS:
        raise ValueError(f"method must be one of {METHODS}")
    f["updated"] = _now()
    f["updated_by"] = _actor(actor)
    with _db(engagement) as con:
        con.execute("BEGIN IMMEDIATE")
        cur_row = con.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
        if not cur_row:
            raise ValueError(f"no finding {finding_id}")
        before = cur_row["revision"]
        changes = []  # (kind, from, to)
        if f.get("status") and f["status"] != cur_row["status"]:
            changes.append(("status", cur_row["status"], f["status"]))
            if f["status"] in NEEDS_REASON and not reason:
                raise ValueError(f"marking {finding_id} {f['status']} needs a reason")
        if f.get("severity") and f["severity"] != cur_row["severity"]:
            changes.append(("severity", cur_row["severity"], f["severity"]))
            if not reason:
                raise ValueError(f"changing the severity of {finding_id} needs a reason")
        if "priority" in f and f["priority"] != cur_row["priority"]:
            changes.append(("priority", cur_row["priority"], f["priority"]))
            if not reason and cur_row["priority"]:
                raise ValueError(f"changing the remediation priority of {finding_id} needs a reason")
        if expected_revision is not None and int(expected_revision) != before:
            raise Conflict(f"{finding_id} was changed by someone else since you opened it (now revision {before}, "
                           f"you had {expected_revision}): reload and apply your change again")
        if f.get("status") == "duplicate" or f.get("duplicate_of"):
            orig = f.get("duplicate_of") or ""
            if f.get("status", "duplicate") != "duplicate":
                raise ValueError("duplicate_of goes with status=duplicate")
            if not orig or orig == finding_id:
                raise ValueError("status=duplicate needs duplicate_of: the id of the finding to keep")
            row = con.execute("SELECT status, duplicate_of FROM findings WHERE id=?", (orig,)).fetchone()
            if not row:
                raise ValueError(f"duplicate_of: no finding {orig}")
            if row["status"] == "duplicate":
                raise ValueError(f"{orig} is itself a duplicate of {row['duplicate_of']}: point to that one")
            f["status"] = "duplicate"
        elif "status" in f:
            f["duplicate_of"] = None  # leaving the duplicate status drops the link
        cur = con.execute(f"UPDATE findings SET {','.join(k + '=?' for k in f)}, revision=revision+1 "
                          "WHERE id=? AND revision=?", [*f.values(), finding_id, before])
        if not cur.rowcount:  # changed between the read and the write (another process)
            raise Conflict(f"{finding_id} changed while saving: reload and apply your change again")
        for kind, a, b in changes:
            _decision(con, finding_id, kind, a, b, reason, method if b == "confirmed" else None, actor, before + 1)
        if f.get("status") == "confirmed" and (cur_row["verification"] != "verified" or method):
            _verify(con, finding_id, method or "not stated", actor)
        elif method and not changes:  # verified again by another method (e.g. a retest)
            _verify(con, finding_id, method, actor)
            _decision(con, finding_id, "verification", cur_row["verified_method"], method, reason, method, actor,
                      before + 1)
        _snapshot(con, finding_id, actor)
        return {**_row(con.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()),
                "previous_revision": before}


def mark_not_reproducible(engagement, finding_id, actor, reason):
    """A verification attempt that failed: kept as a decision, the status doesn't change by itself."""
    if not (reason or "").strip():
        raise ValueError("say why it couldn't be reproduced")
    with _db(engagement) as con:
        con.execute("BEGIN IMMEDIATE")
        r = con.execute("SELECT revision, verification FROM findings WHERE id=?", (finding_id,)).fetchone()
        if not r:
            raise ValueError(f"no finding {finding_id}")
        con.execute("UPDATE findings SET verification='not-reproducible', revision=revision+1, updated=?, "
                    "updated_by=? WHERE id=?", (_now(), _actor(actor), finding_id))
        _decision(con, finding_id, "verification", r["verification"], "not-reproducible", reason, None, actor,
                  r["revision"] + 1)
        _snapshot(con, finding_id, actor)
        return _row(con.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone())


def history(engagement: str, finding_id: str) -> dict:
    """Every revision (snapshot) and decision of a finding, oldest first."""
    with _db(engagement) as con:
        if not con.execute("SELECT 1 FROM findings WHERE id=?", (finding_id,)).fetchone():
            raise ValueError(f"no finding {finding_id}")
        revs = [{"revision": r["revision"], "actor": r["actor"], "at": r["at"], "snapshot": json.loads(r["snapshot"])}
                for r in con.execute("SELECT * FROM finding_revisions WHERE finding_id=? ORDER BY revision",
                                     (finding_id,))]
        dec = [dict(r) for r in con.execute("SELECT * FROM decisions WHERE finding_id=? ORDER BY id", (finding_id,))]
        return {"revisions": revs, "decisions": dec}


def get(engagement: str, finding_id: str) -> dict:
    with _db(engagement) as con:
        r = con.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
        if not r:
            raise ValueError(f"no finding {finding_id}")
        return _row(r)


def list_(engagement: str, status: str | None = None, severity: str | None = None) -> list[dict]:
    q, args = "SELECT * FROM findings WHERE 1=1", []
    if status:
        q += " AND status=?"; args.append(status)
    if severity:
        q += " AND severity=?"; args.append(severity.lower())
    q += " ORDER BY CASE severity " + " ".join(f"WHEN '{s}' THEN {i}" for i, s in enumerate(SEVERITIES)) + " END, id"
    with _db(engagement) as con:
        return [_row(r) for r in con.execute(q, args)]
