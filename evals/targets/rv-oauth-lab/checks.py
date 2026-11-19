"""The OAuth lab's seeded flaws and clean controls, as pure HTTP checks with no model (issue #138).

Each check returns whether the vulnerable behaviour is present, so the same function verifies both builds:
  - the vulnerable build (rv-oauth-lab): every check is True (the flaw is there);
  - the fixed build (rv-oauth-lab-fixed): every check is False (the flow is implemented correctly).

Run inside the kit (the lab network is internal): `python3 checks.py <host> <port>`, or import `checks(host, port)`.
"""
import http.client, sys, urllib.parse

CB = "https://client.example.com/callback"
CLIENT_ID = "rv-oauth-client"


def _req(host, port, method, path, body=None):
    c = http.client.HTTPConnection(host, port, timeout=10)
    headers = {"Content-Type": "application/x-www-form-urlencoded"} if body is not None else {}
    c.request(method, path, body=body, headers=headers)
    r = c.getresponse()
    data = r.read().decode("utf-8", "replace")
    hdrs = {k.lower(): v for k, v in r.getheaders()}
    c.close()
    return r.status, hdrs, data


def _code(host, port, **params):
    params.setdefault("response_type", "code")
    params.setdefault("client_id", CLIENT_ID)
    st, h, _ = _req(host, port, "GET", "/authorize?" + urllib.parse.urlencode(params))
    if st != 302:
        return None
    loc = h.get("location", "")
    return urllib.parse.parse_qs(urllib.parse.urlsplit(loc).query).get("code", [None])[0]


def _token(host, port, form):
    return _req(host, port, "POST", "/token", urllib.parse.urlencode(form))


def checks(host, port):
    """(name, flaw-present, detail) for the four seeded flaws. flaw-present is True on the vulnerable build."""
    out = []

    # 1. redirect_uri validated only by prefix
    st, _, _ = _req(host, port, "GET", "/authorize?" + urllib.parse.urlencode(
        {"response_type": "code", "client_id": CLIENT_ID,
         "redirect_uri": CB + ".attacker.test/cb", "state": "s"}))
    out.append(("redirect_uri validated by prefix", st == 302, f"status {st}"))

    # 2. state not required
    st, _, _ = _req(host, port, "GET", "/authorize?" + urllib.parse.urlencode(
        {"response_type": "code", "client_id": CLIENT_ID, "redirect_uri": CB}))
    out.append(("authorize without state accepted", st == 302, f"status {st}"))

    # 3. PKCE not enforced (code issued and exchanged with no challenge / verifier)
    code = _code(host, port, redirect_uri=CB)
    st, _body, _ = _token(host, port, {"grant_type": "authorization_code", "code": code,
                                       "redirect_uri": CB, "client_id": CLIENT_ID})
    out.append(("code exchanged without PKCE", st == 200, f"status {st}"))

    # 4. the authorization code is replayable (two exchanges both mint tokens)
    code = _code(host, port, redirect_uri=CB, state="s")
    form = {"grant_type": "authorization_code", "code": code, "redirect_uri": CB, "client_id": CLIENT_ID}
    st1, _, _ = _token(host, port, form)
    st2, _, _ = _token(host, port, form)
    out.append(("authorization code replay accepted", st1 == 200 and st2 == 200, f"status {st1} then {st2}"))

    return out


def main():
    host, port = sys.argv[1], int(sys.argv[2])
    ok = True
    for name, present, detail in checks(host, port):
        print(("FLAW  " if present else "CLEAN ") + f"{name} ({detail})")
        ok = ok and present
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
