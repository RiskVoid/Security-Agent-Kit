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

  oob_callback        blind issue (SSRF, blind command injection, XXE): the probe makes the target call back to the
                      kit's own catcher with a token unique to this verification (<engagement>.<canary>), and the
                      oracle passes only when that token arrives. Control: a request that does not trigger a
                      callback (or an unreachable catcher) must not deliver its token. RULES.md needs
                      'Out-of-band callbacks: on'; the firewall drops every engagement user's traffic to the
                      catcher, so a token can only arrive from the target itself. No public callback service:
                      client traffic stays in the kit, and every expected callback is evidence with an audit entry.
  response_diff       two request specs and the caller's rule for what difference counts: the probe's answer
                      must contain `expect`, the control's must not. identity_difference is the authorization
                      special case; this is for debug detail, verbose errors, hidden functionality.
  persistence         a write, then a separate read at the stored location in the sandboxed browser: one oracle
                      for stored issues (stored XSS, stored injection echoes) instead of read_back and
                      browser_xss chained by hand. The proof request stores {{marker}}; check: {url} reads it
                      back. Controls: the page before the write runs nothing of the marker.

Every run writes a verification record (evidence/verify/<ts>-<oracle>-<id>.json) with the oracle, the result, the
reason and each request's evidence file and status, and the record is audited and hashed like any evidence.
results: pass (holds, control clean), fail (doesn't hold), inconclusive (the control or a precondition failed:
no conclusion either way), or the broker's refusal or approval request.
"""
import datetime, json, os, re

import core
import actions
try:
    import oob
except Exception:  # noqa: BLE001
    oob = None

ORACLES = ("marker", "identity_difference", "read_back", "browser_xss", "timing", "oob_callback",
           "response_diff", "persistence", "rate_limit")
BROWSER_EVIDENCE = re.compile(r"\[browser evidence: /work/[^/]+/(\S+?)/ ")
MAX_SAMPLES = 10
RATE_SAMPLES = 100               # the rate-limit oracle's own ceiling: burst requests in one verification
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
            "_text": _response_text(r)}


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


def response_diff(eng, request, control, expect, send_kw=None):
    """Two request specs and the caller's rule for what difference counts (#W7): the probe's response must
    contain `expect`, the control's must not. identity_difference is the authorization special case of this;
    response_diff is for everything else - debug detail an error page shows, a verbose stack trace, hidden
    functionality one parameter unlocks."""
    kw = send_kw or {}
    if not control or not control.get("url"):
        raise ValueError("response_diff needs control: the same request without the part that should differ")
    if not expect:
        raise ValueError("response_diff needs expect: the text only the probe's answer should contain")
    probe = _send(eng, _fill(request, ""), "probe", **kw)
    ctl = _send(eng, _fill(control, ""), "control", **{k: v for k, v in kw.items() if k != "approval_id"})
    steps = [probe, ctl]
    if probe.get("error"):
        return "inconclusive", f"the probe request failed: {probe['error']}", "", steps
    if expect not in probe["_text"]:
        return "fail", f"{expect!r} is not in the probe's response", "", steps
    if expect in ctl["_text"]:
        return "inconclusive", f"the control's response contains {expect!r} too: it doesn't come from the probe", \
            "", steps
    return "pass", (f"{expect!r} is in the probe's answer and not in the control's "
                    f"(status {probe.get('status')} vs {ctl.get('status')})"), "", steps


def persistence(eng, request, check, marker="", send_kw=None):
    """A write, then a separate read at the stored location in the sandboxed browser: one oracle for stored
    issues (stored XSS, stored injection echoes), instead of read_back and browser_xss chained by hand (#W7).
    The proof request stores {{marker}} in a form the page executes; check: {url} reads the location back in
    the browser, read-only. Controls: the page before the write runs nothing of the marker, and the proof
    request's evidence is kept like any write."""
    kw = send_kw or {}
    if not check or not check.get("url"):
        raise ValueError("persistence needs check: the page (or request) that reads the stored value back")
    if not marker and not _has_placeholder(request):
        raise ValueError("persistence: put {{marker}} in the write's payload (e.g. "
                         "<script>rvMarker('{{marker}}')</script>), or give marker")
    mark = marker or canary()
    page = _fill(check, mark)["url"]
    before = _browse(eng, page, "control: the page before the write", check.get("identity"),
                     max_tier=kw.get("max_tier"), task=kw.get("task"))
    if any(x.split(":", 1)[-1] == mark for x in before.get("executed") or []):
        return "inconclusive", f"the page already runs {mark!r} before the write: it isn't stored by this " \
            "request", mark, [before]
    proof = _send(eng, _fill(request, mark), "proof", **kw)
    after = _browse(eng, page, "check after the write", check.get("identity"),
                     max_tier=kw.get("max_tier"), task=kw.get("task"))
    steps = [before, proof, after]
    if proof.get("error"):
        return "inconclusive", f"the proof request failed: {proof['error']}", mark, steps
    if not any(x.split(":", 1)[-1] == mark for x in after.get("executed") or []):
        return "fail", f"the page stored the write but nothing ran with {mark!r}", mark, steps
    return "pass", f"the page ran {mark!r} after the write and not before it: the stored value is executed " \
        "where it is read back", mark, steps


def _stats(xs):
    m = sum(xs) / len(xs)
    return m, (sum((x - m) ** 2 for x in xs) / max(1, len(xs) - 1)) ** 0.5


BLOCKED = (429, 423)   # statuses that are rate limiting, or a lockout beside a different control status


def rate_limit(eng, request, samples=30, cooldown=10.0, send_kw=None):
    """The probe is a brokered burst (actions.rate_burst): the same request N times at the engagement's own max
    rate — one approval names the N and the control — then one more request after a cooldown.

    pass: every burst request was answered like the control — no rate limiting at the measured rate. That is the
    evidence a 'missing rate limit' finding needs (a run once proved it with five requests and the validator
    rightly refused: N, the exact statuses and every response are in the record).
    fail: some burst requests were refused while the cooldown control was answered — rate limiting IS present;
    record that instead, this record is its proof. inconclusive: the control failed, so nothing distinguishes a
    limiter from the endpoint being down."""
    kw = send_kw or {}
    n = 30 if not samples or int(samples) < 10 else int(samples)
    r = actions.rate_burst(eng, request.get("method") or "GET", request["url"], request.get("headers"),
                           request.get("body") or "", n=min(n, RATE_SAMPLES), cooldown=cooldown,
                           approval_id=kw.get("approval_id"), identity=request.get("identity") or None,
                           task=kw.get("task"))
    if r.get("refused") or r.get("approval"):
        raise Stopped({**r, "role": "burst"})
    steps = [{"role": f"{r['n']} rapid requests, then the cooldown control", "status": r.get("control"),
              "evidence": f"/work/{eng}/{r['evidence']}" if r.get("evidence") else None}]
    c_status = r.get("control")
    if c_status is None:
        return "inconclusive", "the control request after the cooldown failed, so nothing distinguishes a " \
                                "limiter from the endpoint being down", "", steps
    blocked = [i + 1 for i, st in enumerate(r.get("statuses") or [])
               if st in BLOCKED or (st != c_status and st in (403, 503))]
    detail = (f"{r['n']} requests in {r.get('seconds', 0)}s at the engagement's max rate, statuses "
              f"{sorted(set(s for s in (r.get('statuses') or []) if s))}, control after {cooldown:.0f}s "
              f"cooldown: {c_status}; every response is in the evidence")
    if blocked:
        return "fail", detail + f"; refused at {', '.join(f'#{i}' for i in blocked)} while the cooldown control " \
                                "was answered: rate limiting IS present — record that, this record is its proof", "", steps
    return "pass", detail + "; every request of the burst was answered as the control was: no rate limiting " \
                            "at this rate", "", steps


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


def oob_callback(eng, request, marker="", control=None, send_kw=None, timeout=10.0):
    """Blind issue (SSRF, blind command injection, XXE): the probe makes the target call back to the kit's own
    catcher with a token unique to this verification, and the oracle passes only when that token arrives.

    The request carries {{marker}} where the callback URL goes (e.g. ...url=http://10.250.0.2:8080/{{marker}},
    or the host/path arguments of a GraphQL mutation that fetches); the token is <engagement>.<canary>. The
    engagement's RULES.md needs 'Out-of-band callbacks: on': the catcher is a host decision, like an identity.
    Control: a request that does not trigger a callback, or the same request with an unreachable catcher."""
    kw = send_kw or {}
    if oob is None:
        raise ValueError("oob callback catcher is not available in this kali-mcp process")
    if not core.info(eng)["rules"].get("out_of_band"):
        raise ValueError("Out-of-band callbacks are off for this engagement: the catcher is a host decision, "
                         "RULES.md needs 'Out-of-band callbacks: on' (./rvkit scope <engagement> applies it)")
    mark = marker or oob.token_for(eng)
    eng_part, _ = oob.token_parts(mark)
    if eng_part != eng:
        raise ValueError("oob_callback: the callback token is <engagement>.<canary>; leave {{marker}} in the "
                         "request and the oracle generates one")
    # both tokens are pre-registered so their arrivals become evidence; the control's must never be the probe's
    control_token = oob.token_for(eng)
    probe_req = _fill(request, mark)
    if control:
        control_req = _fill(control, control_token)
    else:
        # Default control: a GET of the probe request's own origin, the same target without the payload: the
        # token's job is to prove the target processed our payload, and an unguessable token that arrives is
        # already strong evidence, so the control only has to stay clean of it. (The same request with an
        # unreachable catcher is a fine explicit control, but it can't be the default: a POST would need its own
        # single-use approval, and the probe's is consumed.)
        origin = "/".join(probe_req["url"].split("/", 3)[:3]) + "/"
        control_req = {"method": "GET", "url": origin, "headers": {}, "body": "", "identity": probe_req.get("identity")}
    oob.expect(mark)
    oob.expect(control_token)
    probe = _send(eng, probe_req, "probe", **kw)
    ctl = _send(eng, control_req, "control", **{k: v for k, v in kw.items() if k != "approval_id"})
    steps = [probe, ctl]
    if probe.get("error"):
        return "inconclusive", f"the probe request failed: {probe['error']}", mark, steps
    # wait for the probe's token to arrive at the catcher
    arrived = oob.wait(mark, timeout=timeout)
    if not arrived:
        return "fail", f"callback token {mark!r} did not arrive at the catcher", mark, steps
    # the control's token must not have arrived (spurious traffic would make the result meaningless)
    if oob.received(control_token):
        return "inconclusive", f"the control's token {control_token!r} arrived too: the callback is not tied to the probe", \
            mark, steps
    # a token that was never sent must not be present either
    if oob.received(oob.token_for(eng)):
        return "inconclusive", "an unsent token arrived at the catcher: spurious traffic", mark, steps
    cb = oob.evidence(eng, mark)
    steps.append({"role": "callback", "status": "received", "evidence": cb, "error": None})
    where = f", recorded as {cb}" if cb else ""
    return "pass", f"callback token {mark!r} arrived at the catcher{where}; the control's did not", mark, steps


def verify(eng, oracle, request, marker="", expect="", identities=None, check=None, control=None, approval_id=None,
           max_tier=None, task=None, finding="", send=None, samples=5, min_delay=1.0, browse=None, timeout=10.0):
    """Run one oracle and record it. Returns {"result", "reason", "record", "text", ...}."""
    if oracle not in ORACLES:
        raise ValueError(f"oracle must be one of {', '.join(ORACLES)}")
    if not isinstance(request, dict) or not request.get("url"):
        raise ValueError("request must be {method, url, headers?, body?, identity?}")
    if marker and not MARKER_RX.match(marker):
        raise ValueError("a marker is 6-128 letters, digits and _ . : @ -")
    kw = {"approval_id": approval_id or None, "max_tier": max_tier, "task": task, "send": send}
    if not marker and _has_placeholder(request) and oracle in ("marker", "read_back", "browser_xss"):
        marker = canary()   # chosen here so a request that needs an approval can be sent again with the same one
    if not marker and _has_placeholder(request) and oracle == "persistence":
        marker = canary()
    if not marker and oracle == "oob_callback":
        marker = oob.token_for(eng) if oob else f"{eng}.{canary()}"
    try:
        if oracle == "marker":
            result, reason, mark, steps = marker_oracle(eng, request, marker, expect, control, kw)
        elif oracle == "identity_difference":
            result, reason, mark, steps = identity_difference(eng, request, identities, marker, kw)
        elif oracle == "browser_xss":
            result, reason, mark, steps = browser_xss(eng, request, marker, {**kw, "browse": browse})
        elif oracle == "timing":
            result, reason, mark, steps = timing(eng, request, control, samples, min_delay, kw)
        elif oracle == "rate_limit":
            result, reason, mark, steps = rate_limit(eng, request, samples, timeout, kw)
        elif oracle == "oob_callback":
            result, reason, mark, steps = oob_callback(eng, request, marker, control, kw, timeout=timeout)
        elif oracle == "response_diff":
            result, reason, mark, steps = response_diff(eng, request, control, expect, kw)
        elif oracle == "persistence":
            result, reason, mark, steps = persistence(eng, request, check, marker, kw)
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

