"""Evidence pins: what a confirmed finding cites, by content.

When the planner confirms a finding, each evidence file it cites is recorded with its SHA-256 and size. If such a
file is later moved or renamed inside the engagement folder, the finding's evidence entry is pointed at the file
with the same content, and the change is a decision in the finding's history. A file that is gone, or whose
content changed, is left as it is: the report's evidence checks name it.

Why: in the benchmark run code-node-20261115T202407Z the planner confirmed eight findings citing one file, then
moved that file into evidence/ and never updated the findings. Every one of them lost its proof.
"""
import datetime, hashlib, json, os, re

import findings_db as db
import quotecheck

ACTOR = "agent:harness"
SKIP_DIRS = ("report", "audit")
MAX_SIZE = 50_000_000


def _ensure(con):
    con.execute("""CREATE TABLE IF NOT EXISTS evidence_pins (finding_id TEXT NOT NULL, path TEXT NOT NULL,
        sha256 TEXT NOT NULL, size INTEGER NOT NULL, at TEXT, PRIMARY KEY (finding_id, path))""")


def _sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def _evidence(finding):
    ev = finding.get("evidence") or []
    if isinstance(ev, str):
        try:
            ev = json.loads(ev)
        except ValueError:
            ev = [ev]
    return [str(e) for e in ev if str(e).strip()]


def _base(engagement):
    return os.path.realpath(os.path.join(quotecheck.WORK, engagement))


def _target(engagement, entry):
    """Where an evidence entry points (whether or not the file is there), and what follows the path in it."""
    text = str(entry).strip()
    head = re.split(r"\s", text, maxsplit=1)[0]
    path = head.split(":")[0]
    tail = head[len(path):] + text[len(head):]
    if path.startswith("/work/"):
        path = os.path.join(quotecheck.WORK, path[len("/work/"):])
    return os.path.realpath(path if os.path.isabs(path) else os.path.join(_base(engagement), path)), tail


def pin(engagement, finding):
    """Record the files a confirmed finding cites. Returns how many were pinned."""
    if not isinstance(finding, dict) or finding.get("status") != "confirmed":
        return 0
    base, rows = _base(engagement), []
    for e in _evidence(finding):
        p = quotecheck.evidence_path(engagement, e)
        try:
            if p and os.path.getsize(p) <= MAX_SIZE:
                rows.append((finding["id"], os.path.relpath(p, base), _sha(p), os.path.getsize(p),
                             datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")))
        except OSError:
            continue
    if rows:
        with db._db(engagement) as con:
            _ensure(con)
            con.executemany("INSERT OR REPLACE INTO evidence_pins (finding_id, path, sha256, size, at) "
                            "VALUES (?,?,?,?,?)", rows)
    return len(rows)


def _find(base, sha, size):
    """A file under the engagement folder with this content, as a path relative to it (None: there is none)."""
    for root, dirs, files in os.walk(base):
        dirs[:] = [d for d in dirs if not d.startswith(".") and not (root == base and d in SKIP_DIRS)]
        for name in sorted(files):
            full = os.path.join(root, name)
            try:
                if name.startswith((".", "findings.db")) or os.path.islink(full) or os.path.getsize(full) != size:
                    continue
                if _sha(full) == sha:
                    return os.path.relpath(full, base)
            except OSError:
                continue
    return None


def repair(engagement):
    """Point findings at evidence that was moved after they were confirmed. Returns the changes made, as
    [{"finding", "from", "to"}]. Cheap when nothing moved: one existence check per pinned file."""
    base = _base(engagement)
    try:
        with db._db(engagement) as con:
            _ensure(con)
            pins = [dict(r) for r in con.execute("SELECT * FROM evidence_pins")]
    except (OSError, ValueError):
        return []
    gone = [p for p in pins if not os.path.isfile(os.path.join(base, p["path"]))]
    if not gone:
        return []
    moved, done = {}, []
    for p in gone:
        key = (p["sha256"], p["size"])
        if key not in moved:
            moved[key] = _find(base, *key)
        to = moved[key]
        if not to:
            continue
        try:
            f = db.get(engagement, p["finding_id"])
        except ValueError:
            continue
        old_full = os.path.realpath(os.path.join(base, p["path"]))
        new, changed = [], False
        for e in _evidence(f):
            full, tail = _target(engagement, e)
            if full == old_full:
                new.append(f"/work/{engagement}/{to}{tail}")   # a line number or a note after the path is kept
                changed = True
            else:
                new.append(e)
        if changed:
            row = db.update(engagement, f["id"], actor=ACTOR, evidence=new)
            with db._db(engagement) as con:   # an evidence change is not a decision by itself: say why it happened
                db._decision(con, f["id"], "evidence", p["path"], to, f"the cited evidence file {p['path']} was "
                             f"moved; the same content is at {to}", None, ACTOR, row["revision"])
            done.append({"finding": f["id"], "from": p["path"], "to": to})
        with db._db(engagement) as con:
            con.execute("DELETE FROM evidence_pins WHERE finding_id=? AND path=?", (p["finding_id"], p["path"]))
            con.execute("INSERT OR REPLACE INTO evidence_pins (finding_id, path, sha256, size, at) VALUES (?,?,?,?,?)",
                        (p["finding_id"], to, p["sha256"], p["size"], p["at"]))
    return done
