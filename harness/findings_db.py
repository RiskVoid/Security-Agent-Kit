"""Findings store shared by the findings MCP (planner-facing) and the worker (candidates only).

One SQLite database per engagement: /work/<engagement>/findings.db

Schema versions (PRAGMA user_version), applied in order when a database is opened:
  1  findings table with duplicate_of (databases from before versioning get it added)
  2  revision (starts at 1, +1 on every change) and updated_by (the actor that made the last change)
A database from a newer kit version is refused rather than written with an older schema.
Updates can carry expected_revision: when the finding changed in the meantime, Conflict is raised instead of
overwriting someone else's change.
"""
import datetime, json, os, re, sqlite3

WORK = "/work"
SEVERITIES = ("critical", "high", "medium", "low", "info")
STATUSES = ("candidate", "confirmed", "false-positive", "duplicate", "fixed", "accepted-risk")
SCHEMA_VERSION = 2
ACTOR_RX = re.compile(r"^(console|cli|agent|test):[A-Za-z0-9._@-]{1,64}$")
FIELDS = ("title", "severity", "cvss_vector", "cvss_score", "cwe", "asset", "description", "impact",
          "reproduction", "remediation", "evidence", "status", "source", "notes", "duplicate_of")


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
    con.execute(f"PRAGMA user_version={SCHEMA_VERSION}")


def _db(engagement: str) -> sqlite3.Connection:
    con = sqlite3.connect(os.path.join(engagement_dir(engagement), "findings.db"))
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


def _clean(fields: dict) -> dict:
    out = {k: v for k, v in fields.items() if k in FIELDS and v is not None}
    if "severity" in out:
        out["severity"] = str(out["severity"]).lower()
        if out["severity"] not in SEVERITIES:
            raise ValueError(f"severity must be one of {SEVERITIES}")
    if "status" in out and out["status"] not in STATUSES:
        raise ValueError(f"status must be one of {STATUSES}")
    if "evidence" in out and not isinstance(out["evidence"], str):
        out["evidence"] = json.dumps(list(out["evidence"]))
    return out


def _row(r: sqlite3.Row) -> dict:
    d = dict(r)
    try:
        d["evidence"] = json.loads(d.get("evidence") or "[]")
    except ValueError:
        pass
    return d


def record(engagement: str, actor: str | None = None, **fields) -> dict:
    f = _clean(fields)
    if not f.get("title") or not f.get("severity"):
        raise ValueError("title and severity are required")
    with _db(engagement) as con:
        n = con.execute("SELECT COUNT(*) FROM findings").fetchone()[0] + 1
        f.update(id=f"F-{n:03d}", created=_now(), updated=_now(), revision=1, updated_by=_actor(actor))
        f.setdefault("status", "candidate")
        con.execute(f"INSERT INTO findings ({','.join(f)}) VALUES ({','.join('?' * len(f))})", list(f.values()))
        return _row(con.execute("SELECT * FROM findings WHERE id=?", (f["id"],)).fetchone())


def update(engagement: str, finding_id: str, expected_revision: int | None = None, actor: str | None = None,
           **fields) -> dict:
    """Change a finding. The result has the new row; result["previous_revision"] is the revision it replaced."""
    f = _clean(fields)
    if not f:
        raise ValueError("nothing to update")
    f["updated"] = _now()
    f["updated_by"] = _actor(actor)
    with _db(engagement) as con:
        cur_row = con.execute("SELECT revision FROM findings WHERE id=?", (finding_id,)).fetchone()
        if not cur_row:
            raise ValueError(f"no finding {finding_id}")
        before = cur_row["revision"]
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
        return {**_row(con.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()),
                "previous_revision": before}


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
