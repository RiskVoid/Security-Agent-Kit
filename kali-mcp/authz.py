"""Authorization comparisons (RW-011): operation x identity matrices with researcher-approved expectations.

The agent proposes a matrix (propose_authz_matrix): the operations (method, URL, optional body), the identities
to try (plus "anonymous"), what each identity is expected to get (allow or deny), the fixture marker that shows
whose data a response holds, and for operations that change state the limits and cleanup. Only the researcher
approves it, on the host (./rvkit authz <eng> approve <name>, or the console); the approval is bound to the
matrix's digest and the policy revision, so a changed matrix or a changed scope needs a new approval.

A run first checks every identity (the valid-session control). A cell whose identity isn't valid is blocked,
never "denied". Each request goes through the execution broker (policy, identity hosts, budget, rate, evidence).
Outcomes compare actual data, not the status alone:

  allowed   2xx and the operation's marker is in the response (or it matches the owner's response)
  denied    401/403/404, a redirect to the login page, or a 2xx without the marker that differs from the owner's
  blocked   the session isn't valid, or a CAPTCHA/WAF/rate-limit page, or a 5xx: the cell wasn't tested
  verdict   pass (as expected), FAIL (allowed where deny was expected: a finding to verify), unexpected-deny,
            blocked

The effect follows the method: anything but GET, HEAD or OPTIONS is a write whatever the agent declares (a GET
may also be declared a write: it is not assumed harmless). Writes run only when the approved matrix says
allow_writes, at most max_writes requests counting the cleanup requests, followed by the cleanup it lists.
"""
import hashlib, json, os, re

import core
import policy as rvpolicy

NAME_RX = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")
ANON = "anonymous"
SAFE = ("GET", "HEAD", "OPTIONS")
METHODS = SAFE + ("POST", "PUT", "PATCH", "DELETE")
OP_KEYS = {"id", "method", "url", "headers", "body", "marker", "effect"}   # all of it is shown at review
CLEANUP_KEYS = {"method", "url", "headers", "body", "identity"}


def _dir(eng, approved=False):
    d = os.path.join(core.ctl_dir(eng), "authz") if approved else os.path.join(core.WORK, eng, "authz")
    if approved:
        os.makedirs(d, exist_ok=True)
        return d
    import actions  # the sandbox can write /work: the folder must not lead elsewhere through a link
    return actions.work_dir(eng, "authz")


def _writes(op, default="GET"):
    """A request changes state when its method isn't safe or it was declared a write (approved records made before
    the effect was derived from the method are judged by the method too)."""
    return str(op.get("method") or default).upper() not in SAFE or op.get("effect") == "write"


def _request_fields(where, r, keys):
    extra = set(r) - keys
    if extra:
        raise ValueError(f"{where}: unknown fields {', '.join(sorted(map(str, extra)))} "
                         f"(allowed: {', '.join(sorted(keys))})")
    h = r.get("headers") or {}
    if not isinstance(h, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in h.items()):
        raise ValueError(f"{where}: headers are an object of strings")
    if not isinstance(r.get("body"), (type(None), str, dict, list)):
        raise ValueError(f"{where}: body is text or JSON")


def _digest(m):
    keep = {k: m[k] for k in ("operations", "identities", "expect", "allow_writes", "max_writes", "cleanup")}
    return hashlib.sha256(json.dumps(keep, sort_keys=True).encode()).hexdigest()[:32]


def validate(eng, name, matrix):
    if not NAME_RX.match(name or ""):
        raise ValueError("matrix names are lower-case letters, digits, - and _ (up to 48)")
    import identities
    known = {i["name"] for i in identities.identity_list(eng)}
    ops = matrix.get("operations") or []
    if not ops or len(ops) > 50:
        raise ValueError("1 to 50 operations")
    pol = core.policy_of(eng)
    ids = set()
    for op in ops:
        if not isinstance(op, dict) or not NAME_RX.match(str(op.get("id", ""))) or op["id"] in ids:
            raise ValueError("each operation needs a unique id (lower-case letters, digits, - and _)")
        ids.add(op["id"])
        _request_fields(f"operation {op['id']}", op, OP_KEYS)
        method = str(op.get("method", "GET")).upper()
        if method not in METHODS:
            raise ValueError(f"operation {op['id']}: bad method")
        why = rvpolicy.check_url(pol, op.get("url", ""))
        if why:
            raise ValueError(f"operation {op['id']}: {why}")
        # the method decides: a DELETE declared "read" would skip allow_writes, max_writes and the cleanup
        effect = op.get("effect") or ("read" if method in SAFE else "write")
        if effect not in ("read", "write"):
            raise ValueError(f"operation {op['id']}: effect is read or write")
        if effect == "read" and method not in SAFE:
            raise ValueError(f"operation {op['id']}: {method} can change state, so its effect is write, not read")
        op["effect"] = effect
    who = matrix.get("identities") or []
    for n in who:
        if n != ANON and n not in known:
            raise ValueError(f"no identity {n} (define it on the host: ./rvkit identity)")
    expect = matrix.get("expect") or {}
    for op in ops:
        for n in who:
            e = (expect.get(op["id"]) or {}).get(n)
            if e not in ("allow", "deny"):
                raise ValueError(f"expect[{op['id']}][{n}] must be allow or deny")
    expect = {op["id"]: {n: expect[op["id"]][n] for n in who} for op in ops}  # only what runs is approved
    cleanup = matrix.get("cleanup") or []
    for c in cleanup:
        if not isinstance(c, dict):
            raise ValueError("each cleanup request is an object (method, url, headers, body, identity)")
        _request_fields(f"cleanup {c.get('url')}", c, CLEANUP_KEYS)
        if str(c.get("method", "POST")).upper() not in METHODS:
            raise ValueError(f"cleanup {c.get('url')}: bad method")
        why = rvpolicy.check_url(pol, c.get("url", ""))
        if why:
            raise ValueError(f"cleanup {c.get('url')}: {why}")
        if c.get("identity") and c["identity"] not in known:
            raise ValueError(f"cleanup identity {c['identity']} is not defined")
    writes = [op for op in ops if op["effect"] == "write"]
    cleanup_writes = sum(1 for c in cleanup if _writes(c, "POST"))
    if (writes or cleanup_writes) and not matrix.get("allow_writes"):
        raise ValueError("operations that change state (and cleanup requests) need allow_writes: true, max_writes "
                         "and cleanup")
    if writes and not cleanup and not matrix.get("no_cleanup_reason"):
        raise ValueError("operations that change state need cleanup operations (or no_cleanup_reason)")
    # cleanup requests are writes too: max_writes covers them, and they are kept out of the operations' share
    max_writes = int(matrix.get("max_writes") or (len(writes) * len(who) + cleanup_writes if writes else 0))
    if writes and max_writes < cleanup_writes + 1:
        raise ValueError(f"max_writes {max_writes} must cover the {cleanup_writes} cleanup request(s) and at least "
                         "one operation")
    return {"operations": ops, "identities": who, "expect": expect, "allow_writes": bool(matrix.get("allow_writes")),
            "max_writes": max_writes, "cleanup": cleanup, "no_cleanup_reason": matrix.get("no_cleanup_reason"),
            "purpose": str(matrix.get("purpose") or "")[:500]}


def propose(eng, name, matrix):
    """The agent's proposal: saved in the engagement folder, not usable until the researcher approves it."""
    core.require(eng)
    m = validate(eng, name, matrix)
    m.update(name=name, digest=_digest(m), proposed_by=core.ACTOR, proposed_at=core._now_iso())
    core._write_json(os.path.join(_dir(eng), f"{name}.json"), m)
    core._audit({"engagement": eng, "event": "authz-proposed", "matrix": name, "digest": m["digest"],
                 "operations": len(m["operations"]), "identities": m["identities"],
                 "writes": sum(1 for o in m["operations"] if _writes(o))})
    return m


def proposal(eng, name):
    if not NAME_RX.match(name or ""):
        raise ValueError("bad matrix name")
    try:
        return json.load(open(os.path.join(_dir(eng), f"{name}.json")))
    except OSError:
        raise ValueError(f"no matrix {name} proposed in {eng}")


def review(eng, name):
    """The proposal as the researcher reviews it: validated (effects derived from the methods) and with the digest
    an approval of it will have. Everything the digest covers is in it."""
    m = proposal(eng, name)
    v = validate(eng, name, m)
    return {**v, "name": name, "digest": _digest(v), "proposed_by": m.get("proposed_by"),
            "proposed_at": m.get("proposed_at")}


def _show(v):
    """Agent-written text for a terminal: one line, control characters escaped."""
    return json.dumps(v)[1:-1] if isinstance(v, str) else json.dumps(v, sort_keys=True)


def review_text(m):
    """Every field the digest covers, as text for the terminal (./rvkit authz <eng> approve). The last line is the
    digest, which no agent-written value can produce (values are one line each, indented)."""
    lines = [f"Matrix {m['name']}: {_show(m.get('purpose') or 'no purpose given')}",
             f"  identities: {', '.join(m['identities'])}"]
    for o in m["operations"]:
        lines.append(f"  {o['id']:<18} {_show(o.get('method', 'GET')):<7} {_show(o['url'])}  effect {o['effect']}"
                     + (f"  marker {_show(o['marker'])}" if o.get("marker") else ""))
        for k, v in (o.get("headers") or {}).items():
            lines.append(f"      header {_show(k)}: {_show(v)}")
        if o.get("body") not in (None, ""):
            lines.append(f"      body {_show(o['body'])}")
        lines.append("      expect " + ", ".join(f"{i}: {m['expect'][o['id']][i]}" for i in m["identities"]))
    if m.get("allow_writes"):
        lines.append(f"  CHANGES STATE: at most {m['max_writes']} write(s), cleanup included")
    else:
        lines.append("  read-only")
    if m["cleanup"]:
        lines.append(f"  cleanup ({len(m['cleanup'])} request(s), run after the writes):")
    elif m.get("no_cleanup_reason"):
        lines.append(f"  no cleanup: {_show(m['no_cleanup_reason'])}")
    for c in m["cleanup"]:
        lines.append(f"    {_show(c.get('method', 'POST')):<7} {_show(c['url'])}  as "
                     f"{_show(c.get('identity') or 'no identity')}")
        for k, v in (c.get("headers") or {}).items():
            lines.append(f"      header {_show(k)}: {_show(v)}")
        if c.get("body") not in (None, ""):
            lines.append(f"      body {_show(c['body'])}")
    lines.append("Header values are as proposed: {{cred:NAME}} references are filled in only when sent.")
    lines.append(f"digest {m['digest']}")
    return "\n".join(lines)


def approve(eng, name, digest=None):
    """Host only: approve the proposal as it is now (optionally only if it still has the digest that was reviewed)."""
    m = proposal(eng, name)
    m = {**validate(eng, name, m), "name": name}
    d = _digest(m)
    if digest and digest != d:
        raise ValueError(f"the matrix changed since it was reviewed (digest {d}, reviewed {digest})")
    rec = {**m, "digest": d, "approved_by": core.ACTOR, "approved_at": core._now_iso(),
           "policy_revision": core.policy_version(eng)}
    core._write_json(os.path.join(_dir(eng, True), f"{name}.json"), rec)
    core._audit({"engagement": eng, "event": "authz-approved", "matrix": name, "digest": d,
                 "policy_revision": rec["policy_revision"]})
    return rec


def approved(eng, name):
    try:
        return json.load(open(os.path.join(_dir(eng, True), f"{name}.json")))
    except OSError:
        raise ValueError(f"matrix {name} is not approved (the researcher approves it: ./rvkit authz {eng} approve {name})")


def listing(eng):
    core.require(eng)
    out = []
    for fn in sorted(os.listdir(_dir(eng))):
        if not fn.endswith(".json"):
            continue
        try:
            m = json.load(open(os.path.join(_dir(eng), fn)))
        except (OSError, ValueError):
            continue
        try:
            a = approved(eng, m["name"])
            state = "approved" if a["digest"] == _digest(m) else "changed since approval"
        except ValueError:
            state = "proposed"
        out.append({"name": m["name"], "state": state, "digest": m.get("digest"), "operations": len(m["operations"]),
                    "identities": m["identities"], "purpose": m.get("purpose")})
    return out


def _outcome(eng, ident, op, r, owner_body):
    import captures, identities
    if r.get("refused"):
        return "blocked", r["refused"]
    status, body = r.get("status"), r.get("body") or b""
    if status is None:
        return "blocked", r.get("error") or "no response"
    text = body.decode("utf-8", "replace") if isinstance(body, bytes) else str(body)
    if identities.CHALLENGE.search(text) or status == 429:
        return "blocked", f"HTTP {status}: a CAPTCHA, WAF or rate-limit page answered"
    if status >= 500:
        return "blocked", f"HTTP {status}: server error, not an authorization answer"
    if ident != ANON and identities.looks_expired(eng, ident, status, r.get("headers") or [], body):
        return "blocked", f"HTTP {status}: the session of {ident} ended during the run"
    if status in (401, 403, 404, 419) or (300 <= status < 400):
        return "denied", f"HTTP {status}"
    marker = op.get("marker")
    if 200 <= status < 300:
        if marker:
            return ("allowed", f"HTTP {status}, marker {marker!r} present") if marker in text else \
                ("denied", f"HTTP {status} without the marker {marker!r}")
        if owner_body is not None:
            sim = captures.compare(200, owner_body, status, text)["similarity"]
            return ("allowed", f"HTTP {status}, {sim} similar to the owner's response") if sim >= 0.9 else \
                ("denied", f"HTTP {status}, only {sim} similar to the owner's response")
        return "allowed", f"HTTP {status} (no marker given: status only)"
    return "denied", f"HTTP {status}"


def run(eng, name, task=None):
    import actions, identities
    m = approved(eng, name)
    try:
        current = proposal(eng, name)
        if _digest(current) != m["digest"]:
            return {"text": f"REFUSED: matrix {name} changed since it was approved; the researcher must approve it again"}
    except ValueError:
        pass
    if m["policy_revision"] != core.policy_version(eng):
        return {"text": f"REFUSED: the scope or rules changed since matrix {name} was approved "
                        f"(revision {m['policy_revision']} -> {core.policy_version(eng)}); approve it again"}
    by = {"kind": "authz-matrix", "name": name, "digest": m["digest"], "approved_by": m["approved_by"]}
    session = {}
    for n in m["identities"]:
        session[n] = {"state": "valid", "reason": "no session"} if n == ANON else identities.check(eng, n)
    cells, writes = [], 0
    op_writes = m["max_writes"] - sum(1 for c in m["cleanup"] if _writes(c, "POST"))  # the cleanup's share is kept
    for op in m["operations"]:
        owner = next((n for n in m["identities"] if m["expect"][op["id"]][n] == "allow" and
                      session[n]["state"] == "valid" and n != ANON), None)
        owner_body = None
        order = ([owner] if owner else []) + [n for n in m["identities"] if n != owner]
        for n in order:
            exp = m["expect"][op["id"]][n]
            cell = {"operation": op["id"], "method": op.get("method", "GET"), "url": op["url"], "identity": n,
                    "expected": exp}
            if session[n]["state"] != "valid":
                cell.update(outcome="blocked", reason=f"session {session[n]['state']}: {session[n].get('reason')}",
                            verdict="blocked")
                cells.append(cell)
                continue
            if _writes(op):
                if writes >= op_writes:
                    cell.update(outcome="blocked", reason="max_writes reached", verdict="blocked")
                    cells.append(cell)
                    continue
                writes += 1
            data = json.dumps(op["body"]).encode() if isinstance(op.get("body"), (dict, list)) else \
                str(op.get("body") or "").encode()
            hdrs = dict(op.get("headers") or {})
            if isinstance(op.get("body"), (dict, list)):
                hdrs.setdefault("Content-Type", "application/json")
            hdrs.setdefault("Accept", "application/json, text/html")
            r = actions.send(eng, op.get("method", "GET"), op["url"], hdrs, data, task=task,
                             identity=None if n == ANON else n, authorized_by=by, evidence_kind="authz")
            out, why = _outcome(eng, n, op, r, owner_body)
            if n == owner and out == "allowed":
                owner_body = r.get("body")
            verdict = "blocked" if out == "blocked" else "pass" if (out == "allowed") == (exp == "allow") else \
                "FAIL" if out == "allowed" else "unexpected-deny"
            cell.update(outcome=out, reason=why, verdict=verdict, status=r.get("status"), evidence=r.get("evidence"))
            cells.append(cell)
    cleanup = []
    if writes:
        for c in m["cleanup"]:
            r = actions.send(eng, c.get("method", "POST"), c["url"], dict(c.get("headers") or {}),
                             json.dumps(c["body"]).encode() if isinstance(c.get("body"), (dict, list)) else
                             str(c.get("body") or "").encode(), task=task, identity=c.get("identity"),
                             authorized_by={**by, "cleanup": True}, evidence_kind="authz")
            cleanup.append({"url": c["url"], "status": r.get("status"), "refused": r.get("refused"),
                            "evidence": r.get("evidence")})
    res = {"matrix": name, "digest": m["digest"], "at": core._now_iso(), "sessions": session, "cells": cells,
           "writes": writes, "cleanup": cleanup,
           "summary": {v: sum(1 for c in cells if c["verdict"] == v) for v in ("pass", "FAIL", "unexpected-deny",
                                                                           "blocked")}}
    rel = os.path.join("evidence", "authz", f"{name}-{core._now_iso().replace(':', '')}.json")
    actions.work_dir(eng, "evidence", "authz")
    core._write_json(os.path.join(core.WORK, eng, rel), res)
    core._audit({"engagement": eng, "event": "authz-run", "matrix": name, "digest": m["digest"],
                 "summary": res["summary"], "outputs": {rel: core.sha256_file(os.path.join(core.WORK, eng, rel))}})
    lines = [f"authorization matrix {name}: " + ", ".join(f"{k} {v}" for k, v in res["summary"].items())]
    for c in cells:
        lines.append(f"  {c['operation']:<20} {c['identity']:<14} expected {c['expected']:<5} -> {c['outcome']:<8} "
                     f"{c['verdict']:<15} {c['reason']}")
    if cleanup:
        lines.append("cleanup: " + "; ".join(f"{c['url']} -> {c['status'] or c['refused']}" for c in cleanup))
    lines.append(f"[results saved as evidence: /work/{eng}/{rel}]")
    return {"text": core.scrub(eng, "\n".join(lines)), **res, "evidence": rel}
