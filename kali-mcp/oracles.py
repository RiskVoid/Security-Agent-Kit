"""Verification oracles (epic #52, issues #42 and #44): deterministic checks that decide whether a finding holds.

A model proposes a finding; an oracle decides it. Each oracle sends its requests through the execution broker
(actions.send: scope, tiers, approvals, identities, budget, evidence, audit), checks the responses for a marker
and runs a negative control. The result is pass only when the oracle holds AND the control stays clean:

  marker              the request carries a fresh canary ({{marker}} in the URL, a header or the body) and the
                      canary (or `expect` with it) comes back. Control: the same request with a different harmless
                      token: the probe's canary must not come back (it isn't on the page anyway).
                      With an explicit marker (no {{marker}}), give the control request yourself.
  identity_difference the same request as two identities: the attacker gets the owner's marker (another tenant's
                      fixture record). Controls: the owner gets it too (the request reaches the record), and the
                      request without an identity doesn't (the record isn't public).
  read_back           a proof request writes or reads something, and a separate check request finds the marker.
                      Control: the check request before the proof doesn't find it (it wasn't there already).

Every run writes a verification record (evidence/verify/<ts>-<oracle>-<id>.json) with the oracle, the result, the
reason and each request's evidence file and status, and the record is audited and hashed like any evidence.
results: pass (holds, control clean), fail (doesn't hold), inconclusive (the control or a precondition failed:
no conclusion either way), or the broker's refusal or approval request.
"""
import datetime, json, os, re

import core
import actions

ORACLES = ("marker", "identity_difference", "read_back")
PLACEHOLDER = "{{marker}}"
MARKER_RX = re.compile(r"^[A-Za-z0-9_.:@-]{6,128}$")


def canary():
    return "rv" + os.urandom(6).hex()


def _fill(req, value):
    """A request spec with {{marker}} replaced in the URL, the headers and the body."""
    return {"method": (req.get("method") or "GET").upper(), "url": str(req.get("url") or "").replace(PLACEHOLDER, value),
            "headers": {k: str(v).replace(PLACEHOLDER, value) for k, v in (req.get("headers") or {}).items()},
            "body": str(req.get("body") or "").replace(PLACEHOLDER, value), "identity": req.get("identity") or None}


def _has_placeholder(req):
    return PLACEHOLDER in json.dumps(req or {})


def _response_text(r):
    body = r.get("body") or b""
    text = body.decode("utf-8", "replace") if isinstance(body, bytes) else str(body)
    return "\n".join(f"{k}: {v}" for k, v in r.get("headers") or []) + "\n\n" + text


class Stopped(Exception):
    """The broker didn't send a request (refused, or it needs an approval)."""
    def __init__(self, result):
        super().__init__(result.get("text"))
        self.result = result


def _send(eng, req, role, approval_id=None, max_tier=None, task=None, identity=None, send=None):
    send = send or actions.send
    r = send(eng, req["method"], req["url"], req["headers"], req["body"].encode(), approval_id=approval_id,
             max_tier=max_tier, task=task, identity=(req.get("identity") if identity is None else identity) or None,
             evidence_kind="verify")
    if r.get("refused") or r.get("approval"):
        raise Stopped({**r, "role": role})
    return {"role": role, "status": r.get("status"), "evidence": f"/work/{eng}/{r['evidence']}" if r.get("evidence")
            else None, "error": r.get("error"), "_text": _response_text(r)}


def _seen(step, marker):
    return marker in step["_text"]


def marker_oracle(eng, request, marker="", expect="", control=None, send_kw=None):
    kw = send_kw or {}
    if _has_placeholder(request):
        mark = marker or canary()
        want = (expect or PLACEHOLDER).replace(PLACEHOLDER, mark)
        probe = _send(eng, _fill(request, mark), "probe", **kw)
        other = canary()
        ctl = _send(eng, _fill(control or request, other), "control", **{k: v for k, v in kw.items()
                                                                          if k != "approval_id"})
    else:
        if not marker:
            raise ValueError("marker: put {{marker}} in the request (a fresh canary is used), or give marker")
        if not control:
            raise ValueError("marker: with an explicit marker, give the control request (the same request without "
                             "the payload, or as an identity that must not see the marker)")
        mark, want = marker, (expect or marker)
        probe = _send(eng, _fill(request, mark), "probe", **kw)
        ctl = _send(eng, _fill(control, mark), "control", **{k: v for k, v in kw.items() if k != "approval_id"})
    steps = [probe, ctl]
    if probe.get("error"):
        return "inconclusive", f"the probe request failed: {probe['error']}", mark, steps
    if not _seen(probe, want):
        return "fail", f"{want!r} is not in the probe's response", mark, steps
    if _seen(ctl, want):
        return "inconclusive", (f"the control's response contains {want!r} too: the marker doesn't come from the "
                                "probe's input"), mark, steps
    return "pass", f"{want!r} came back in the probe's response and not in the control's", mark, steps


def identity_difference(eng, request, identities, marker, send_kw=None):
    kw = send_kw or {}
    if not isinstance(identities, list) or len(identities) != 2 or not all(identities):
        raise ValueError("identity_difference needs identities: [attacker, owner]")
    if not marker or not MARKER_RX.match(marker):
        raise ValueError("identity_difference needs the owner's marker (a fixture marker only that record contains)")
    attacker, owner = identities
    req = _fill(request, marker)
    probe = _send(eng, req, f"probe as {attacker}", identity=attacker, **kw)
    pos = _send(eng, req, f"control as {owner} (owner)", identity=owner, **kw)
    anon = _send(eng, req, "control without an identity", identity="", **kw)
    steps = [probe, pos, anon]
    if not _seen(pos, marker):
        return "inconclusive", f"the owner {owner} doesn't get {marker!r}: the request doesn't reach the record", \
            marker, steps
    if _seen(anon, marker):
        return "inconclusive", (f"the request without an identity gets {marker!r} too: the record is public, which "
                                "is not an access-control difference"), marker, steps
    if not _seen(probe, marker) or (probe.get("status") or 0) >= 400:
        return "fail", f"{attacker} doesn't get {owner}'s record (status {probe.get('status')})", marker, steps
    return "pass", f"{attacker} gets {owner}'s marker {marker!r}; without an identity the request doesn't", \
        marker, steps


def read_back(eng, request, check, marker="", send_kw=None):
    kw = send_kw or {}
    if not check or not check.get("url"):
        raise ValueError("read_back needs check: the separate request that reads the result back")
    mark = marker or canary()
    if not _has_placeholder(request) and not marker:
        raise ValueError("read_back: put {{marker}} in the proof request (or give the marker it writes)")
    ckw = {k: v for k, v in kw.items() if k != "approval_id"}
    before = _send(eng, _fill(check, mark), "control: check before the proof", **ckw)
    if _seen(before, mark):
        return "inconclusive", f"{mark!r} is there before the proof ran", mark, [before]
    proof = _send(eng, _fill(request, mark), "proof", **kw)
    after = _send(eng, _fill(check, mark), "check after the proof", **ckw)
    steps = [before, proof, after]
    if proof.get("error"):
        return "inconclusive", f"the proof request failed: {proof['error']}", mark, steps
    if not _seen(after, mark):
        return "fail", f"{mark!r} is not in the check's response after the proof", mark, steps
    return "pass", f"{mark!r} was absent before the proof and present after it", mark, steps


def verify(eng, oracle, request, marker="", expect="", identities=None, check=None, control=None, approval_id=None,
           max_tier=None, task=None, finding="", send=None):
    """Run one oracle and record it. Returns {"result", "reason", "record", "text", ...}."""
    if oracle not in ORACLES:
        raise ValueError(f"oracle must be one of {', '.join(ORACLES)}")
    if not isinstance(request, dict) or not request.get("url"):
        raise ValueError("request must be {method, url, headers?, body?, identity?}")
    if marker and not MARKER_RX.match(marker):
        raise ValueError("a marker is 6-128 letters, digits and _ . : @ -")
    kw = {"approval_id": approval_id or None, "max_tier": max_tier, "task": task, "send": send}
    if not marker and _has_placeholder(request) and oracle in ("marker", "read_back"):
        marker = canary()   # chosen here so a request that needs an approval can be sent again with the same one
    try:
        if oracle == "marker":
            result, reason, mark, steps = marker_oracle(eng, request, marker, expect, control, kw)
        elif oracle == "identity_difference":
            result, reason, mark, steps = identity_difference(eng, request, identities, marker, kw)
        else:
            result, reason, mark, steps = read_back(eng, request, check, marker, kw)
    except Stopped as s:
        r = s.result
        again = (f" Call verify again with the same arguments, marker='{marker}' and the approval_id once it is "
                 "approved: the approval covers this exact request.") if r.get("approval") and marker else ""
        return {"result": "approval" if r.get("approval") else "refused", "approval": r.get("approval"),
                "marker": marker or None,
                "text": f"verify {oracle}: the {r.get('role')} request was not sent. {r.get('text')}{again}"}
    ts = datetime.datetime.now(datetime.timezone.utc)
    rec = {"oracle": oracle, "result": result, "reason": reason, "marker": mark, "finding": finding or None,
           "at": ts.isoformat(timespec="seconds"), "control_clean": result == "pass",
           "steps": [{k: v for k, v in s.items() if not k.startswith("_")} for s in steps]}
    rel = os.path.join("evidence", "verify", f"{ts.strftime('%Y%m%dT%H%M%S')}-{oracle}-{os.urandom(3).hex()}.json")
    actions.work_dir(eng, "evidence", "verify")
    full = os.path.join(core.WORK, eng, rel)
    with open(full, "w") as f:
        json.dump(rec, f, indent=1)
    core._audit({"engagement": eng, "action": "verify", "oracle": oracle, "result": result,
                 **({"task": task} if task else {}), **({"finding": finding} if finding else {}),
                 "outputs": {rel: core.sha256_file(full)}})
    lines = [f"verify {oracle}: {result.upper()}: {reason}"]
    lines += [f"  {s['role']}: status {s.get('status')}  {s.get('evidence') or s.get('error')}" for s in steps]
    lines.append(f"[verification saved as verified evidence: /work/{eng}/{rel}]")
    return {**rec, "record": f"/work/{eng}/{rel}", "text": core.scrub(eng, "\n".join(lines))}

