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
  browser_xss         the page opens in the sandboxed browser (read-only); pass when script with the canary RAN
                      (rvMarker('{{marker}}') or alert('{{marker}}')), not when it was only reflected. Control: the
                      same URL with another token must not run the probe's canary.
  timing              N samples of the probe and N of the control, interleaved; pass when every probe is slower
                      than every control and the difference of the means is above min_delay and three times the
                      spread. The caller gives both requests.
  out_of_band         {{callback}} becomes a unique URL at the engagement's self-hosted catcher. Pass only if a
                      structured event for that token arrives after the probe, absent before and after the
                      control request with another token. HTTP reflection never proves a callback.

Every run writes a verification record (evidence/verify/<ts>-<oracle>-<id>.json) with the oracle, the result, the
reason and each request's evidence file and status, and the record is audited and hashed like any evidence.
results: pass (holds, control clean), fail (doesn't hold), inconclusive (the control or a precondition failed:
no conclusion either way), or the broker's refusal or approval request.
"""
import datetime, hashlib, json, math, os, re, time

import core
import actions

ORACLES = ("marker", "identity_difference", "read_back", "browser_xss", "timing", "out_of_band")
BROWSER_EVIDENCE = re.compile(r"\[browser evidence: /work/[^/]+/(\S+?)/ ")
MAX_SAMPLES = 10
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
    hops = r.get("hops") or []
    return {"role": role, "status": r.get("status"), "evidence": f"/work/{eng}/{r['evidence']}" if r.get("evidence")
            else None, "error": r.get("error"), "seconds": hops[-1].get("seconds") if hops else None,
            "_redirected": len(hops) > 1, "_text": _response_text(r)}


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


def _browse(eng, url, role, identity=None, max_tier=None, task=None, browse=None):
    """Open url in the sandboxed browser (actions.browse: same policy checks) and read what ran on the page."""
    out = (browse or actions.browse)(eng, url, identity=identity or None, max_tier=max_tier, task=task)
    m = BROWSER_EVIDENCE.search(out or "")
    if not m:
        raise Stopped({"refused": True, "text": out, "role": role})
    try:
        with open(os.path.join(core.WORK, eng, m.group(1), "summary.json")) as f:
            summ = json.load(f)
    except (OSError, ValueError):
        summ = {}
    first = (summ.get("steps") or [{}])[0]
    return {"role": role, "status": first.get("status"), "evidence": f"/work/{eng}/{m.group(1)}/",
            "error": None if first.get("ok", True) else first.get("error"), "executed": summ.get("executed") or [],
            "_text": ""}


def browser_xss(eng, request, marker, send_kw=None):
    kw = send_kw or {}
    if (request.get("method") or "GET").upper() != "GET" or PLACEHOLDER not in str(request.get("url")):
        raise ValueError("browser_xss: a GET URL with {{marker}} in the input, passed to rvMarker('{{marker}}') "
                         "(alert('{{marker}}') is recorded too); the page is opened read-only")
    bkw = {"max_tier": kw.get("max_tier"), "task": kw.get("task"), "browse": kw.get("browse")}
    probe = _browse(eng, _fill(request, marker)["url"], "probe", request.get("identity"), **bkw)
    ctl = _browse(eng, _fill(request, canary())["url"], "control", request.get("identity"), **bkw)
    steps = [probe, ctl]

    def ran(st):
        return any(x.split(":", 1)[-1] == marker for x in st["executed"])
    if probe.get("error"):
        return "inconclusive", f"the page didn't load: {probe['error']}", marker, steps
    if ran(ctl):
        return "inconclusive", f"{marker!r} ran in the control too: it doesn't come from the probe's input", \
            marker, steps
    if not ran(probe):
        return "fail", f"nothing ran with {marker!r} (the page may only reflect it)", marker, steps
    return "pass", f"script with {marker!r} ran in the browser; not in the control", marker, steps


def _stats(xs):
    m = sum(xs) / len(xs)
    return m, (sum((x - m) ** 2 for x in xs) / max(1, len(xs) - 1)) ** 0.5


def timing(eng, request, control, samples=5, min_delay=1.0, send_kw=None):
    """The probe is slower than its control by more than the noise: every probe sample is slower than every
    control sample, and the difference of the means is above min_delay and three times the spread."""
    kw = send_kw or {}
    if not control or not control.get("url"):
        raise ValueError("timing needs control: the same request without the part that should take time")
    n = max(3, min(int(samples or 5), MAX_SAMPLES))
    ckw = {k: v for k, v in kw.items() if k != "approval_id"}
    steps, pt, ct = [], [], []
    for i in range(n):   # interleaved, so a slow patch of the network affects both
        c = _send(eng, _fill(control, ""), f"control {i + 1}", **ckw)
        p = _send(eng, _fill(request, ""), f"probe {i + 1}", **kw)
        steps += [c, p]
        if c.get("seconds") is None or p.get("seconds") is None:
            return "inconclusive", f"sample {i + 1} has no timing ({p.get('error') or c.get('error')})", "", steps
        ct.append(c["seconds"]); pt.append(p["seconds"])
    (pm, ps), (cm, cs) = _stats(pt), _stats(ct)
    diff = pm - cm
    detail = (f"probe {pm:.2f}s ±{ps:.2f}, control {cm:.2f}s ±{cs:.2f}, difference {diff:.2f}s over {n} samples "
              f"each")
    if min(pt) > max(ct) and diff >= max(float(min_delay or 0), 3 * (ps + cs)):
        return "pass", detail, "", steps
    return "fail", detail, "", steps


def out_of_band(eng, request, marker, control=None, wait_seconds=3, finding="", send_kw=None,
                control_approval_id=None):
    """Only a structured event from the operator's catcher proves a callback; reflection proves nothing."""
    if "{{callback}}" not in json.dumps(request):
        raise ValueError("out_of_band needs {{callback}} in the request: the engagement's self-hosted callback URL")
    delay = float(wait_seconds)
    if not math.isfinite(delay) or not 0 <= delay <= 30:
        raise ValueError("wait_seconds must be between 0 and 30")
    base = actions.callback_catcher(eng)
    # Namespace by engagement and finding, including when retrying an approved request with the same marker.
    token = "rv" + hashlib.sha256(f"{eng}\0{finding}\0{marker}".encode()).hexdigest()[:32]
    kw = send_kw or {}
    ckw = {k: v for k, v in kw.items() if k != "approval_id"}
    steps = []

    def payload(req, value):
        req = _fill(req, value)
        url = base + "/callback/" + value
        req["url"] = req["url"].replace("{{callback}}", url)
        req["body"] = req["body"].replace("{{callback}}", url)
        req["headers"] = {k: v.replace("{{callback}}", url) for k, v in req["headers"].items()}
        return req

    def poll(role):
        step = _send(eng, _fill({"url": base + "/events/" + token}, ""), role, **ckw)
        steps.append(step)
        try:
            # Parse the body only, never headers, an echoed URL, or a substring in arbitrary target output.
            event = json.loads(step["_text"].split("\n\n", 1)[1])
            count = event["count"]
            if (step.get("error") or step.get("_redirected") or step["status"] != 200 or event["token"] != token
                    or type(count) is not int or count < 0):
                raise ValueError("invalid catcher event")
        except (ValueError, KeyError, TypeError, IndexError):
            return None
        step.update(token=token, callbacks=count)
        return count

    def finish(result, reason):
        return result, reason, marker, steps

    other = "rv" + hashlib.sha256(f"{eng}\0{finding}\0{marker}\0control".encode()).hexdigest()[:32]
    probe_req, control_req = payload(request, token), payload(control or request, other)
    # Obtain both write approvals before consuming either. The broker never sends an unsafe method without one.
    for req, role, opts in ((probe_req, "probe", kw),
                            (control_req, "control: another token", {**ckw, "approval_id": control_approval_id})):
        if req["method"] not in actions.SAFE_METHODS and not opts.get("approval_id"):
            _send(eng, req, role, **opts)  # raises Stopped with this exact request's approval id
            return finish("inconclusive", "the broker did not stop an unapproved write")

    before = poll("control: catcher before requests")
    if before is None:
        return finish("inconclusive", "the self-hosted catcher is unavailable or returned an invalid event")
    if before:
        return finish("inconclusive", "this token already has a callback; use a fresh marker")
    ctl = _send(eng, control_req, "control: another token",
                approval_id=control_approval_id, **ckw)
    steps.append(ctl)
    if ctl.get("error") or not ctl.get("status") or ctl["status"] >= 400:
        return finish("inconclusive", "the control request failed")
    clean = poll("control: probe token after control")
    if clean is None or clean:
        return finish("inconclusive", "the catcher control is unavailable or the probe token arrived before the probe")
    steps.append(_send(eng, probe_req, "probe", **kw))
    if steps[-1].get("error"):
        return finish("inconclusive", "the probe request failed")
    deadline = time.monotonic() + delay
    while True:
        count = poll("check: callback after probe")
        if count is None:
            return finish("inconclusive", "the self-hosted catcher became unavailable or returned an invalid event")
        if count:
            return finish("pass", f"callback with {token!r} arrived only after the probe; another token stayed distinct")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return finish("fail", f"no callback with {token!r} arrived within {delay:g}s")
        time.sleep(min(0.25, remaining))


def verify(eng, oracle, request, marker="", expect="", identities=None, check=None, control=None, approval_id=None,
           max_tier=None, task=None, finding="", send=None, samples=5, min_delay=1.0, browse=None, wait_seconds=3,
           control_approval_id=None):
    """Run one oracle and record it. Returns {"result", "reason", "record", "text", ...}."""
    if oracle not in ORACLES:
        raise ValueError(f"oracle must be one of {', '.join(ORACLES)}")
    if not isinstance(request, dict) or not request.get("url"):
        raise ValueError("request must be {method, url, headers?, body?, identity?}")
    if marker and not MARKER_RX.match(marker):
        raise ValueError("a marker is 6-128 letters, digits and _ . : @ -")
    kw = {"approval_id": approval_id or None, "max_tier": max_tier, "task": task, "send": send}
    if not marker and oracle == "out_of_band":
        marker = "rv" + os.urandom(16).hex()
    if not marker and _has_placeholder(request) and oracle in ("marker", "read_back", "browser_xss"):
        marker = canary()   # chosen here so a request that needs an approval can be sent again with the same one
    try:
        if oracle == "marker":
            result, reason, mark, steps = marker_oracle(eng, request, marker, expect, control, kw)
        elif oracle == "identity_difference":
            result, reason, mark, steps = identity_difference(eng, request, identities, marker, kw)
        elif oracle == "browser_xss":
            result, reason, mark, steps = browser_xss(eng, request, marker, {**kw, "browse": browse})
        elif oracle == "timing":
            result, reason, mark, steps = timing(eng, request, control, samples, min_delay, kw)
        elif oracle == "out_of_band":
            result, reason, mark, steps = out_of_band(eng, request, marker, control, wait_seconds, finding, kw,
                                                     control_approval_id)
        else:
            result, reason, mark, steps = read_back(eng, request, check, marker, kw)
    except Stopped as s:
        r = s.result
        approval_arg = "control_approval_id" if oracle == "out_of_band" and r.get("role", "").startswith("control:") \
            else "approval_id"
        again = (f" Call verify again with the same arguments, marker='{marker}' and the {approval_arg} once it is "
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

