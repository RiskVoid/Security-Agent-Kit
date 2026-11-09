# Authenticated testing

Most real findings in a web application sit behind a login: one tenant reading another tenant's records, a member
doing what only an admin may do, an API that checks the token but not the owner. This page covers the four pieces
the kit has for that work:

- **Identities**: test accounts the agent can act as, without seeing their passwords or tokens.
- **Captures**: HAR or Burp files you record while using the application, sanitized for the agent and replayable.
- **The browser**: a headless browser in the engagement's sandbox, signed in as an identity, held to the scope.
- **Authorization matrices**: which identity may do what, proposed by the agent, approved by you, run and scored.

Everything here works in the console's **Testing** tab and from `./rvkit`. The Laravel lab (Ledgerly, see
[lab-and-benchmarks.md](lab-and-benchmarks.md#ledgerly-laravel-lab)) is a ready practice target.

---

## Where secrets live

Credentials and sessions are kept in the engagement's control folder, encrypted with the vault key
(`/control/vault.key`, root only, mode 0600, generated on first use). The agent never sees them: tools return
names, roles, tenants and status, and every output, evidence file and audit entry has secret values replaced by a
reference. Capture originals are encrypted too and only `./rvkit capture <eng> raw <id>` on the host shows them.

```sh
./rvkit cred acme set ALICE_PASS                      # asks for the value (hidden)
./rvkit cred acme set API_TOKEN --expires 2026-12-01  # refused after that date
./rvkit vault rotate                                  # new key; credentials and sessions re-encrypted
```

A credentials file from an older version (`credentials.json`, plain text) is encrypted on first use and removed.

---

## Identities

An identity is one test account: how it authenticates (it names a stored credential, never a value), the hosts its
session may go to, the tiers and effects it may be used for, and the fixture records it owns.

```sh
./rvkit identity acme set alice-web alice.json   # the spec below
./rvkit identity acme check alice-web            # the valid-session control
./rvkit identity acme list
./rvkit identity acme revoke alice-web           # stop using it now (kept for the record)
./rvkit identity acme rm alice-web
```

### The spec

```json
{
  "kind": "form",
  "role": "admin",
  "tenant": "acme",
  "login_url": "https://app.acme.test/login",
  "username": "alice@acme.test",
  "secret": "ALICE_PASS",
  "check": {"url": "https://app.acme.test/dashboard", "marker": "ACME-INV-1001"},
  "fixtures": [{"kind": "invoice", "id": 1, "marker": "ACME-CONFIDENTIAL-1001"}],
  "tiers": ["active", "intrusive"],
  "effects": ["read"]
}
```

| Field | Meaning |
|---|---|
| `kind` | `bearer` (Authorization: Bearer), `header` (an API key header named by `header`), `cookie` (a session cookie named by `cookie`, copied from a browser), `basic` (with `username`), `form` (an HTML login form), `json` (a JSON login endpoint). |
| `secret` | The name of a stored credential (`./rvkit cred`). Must exist and not be expired. |
| `login_url` | `form` and `json`: where to log in. Must be in scope. |
| `username`, `username_field`, `password_field`, `csrf_field` | `form`: the account and the form's field names (defaults `email`, `password`, `_token`). The CSRF token is read from the login page. |
| `body`, `token_path`, `token_header`, `token_prefix` | `json`: the login body with `{{secret}}` where the password goes, the dotted path of the token in the response (`data.token`), and how to send it (default `Authorization: Bearer `). |
| `check` | The valid-session control: `url` (required), `marker` (text only this account sees), `expect_status` (default `[200]`), `method`, `accept`. |
| `hosts` | Where the session may be sent. Defaults to the hosts of `login_url` and `check.url`. Credentials and sessions are dropped on a redirect to another host. |
| `tiers` | The tiers it may be used at (default `active`). |
| `effects` | `read` and/or `write` (default `read`). A read-only identity can't send a request that may change state, and can't click or fill in the browser. |
| `fixtures` | Records this account owns, each `{"kind", "id", "marker"}`. The marker is text only that record contains: it is how a cross-tenant read is proven rather than guessed. |
| `role`, `tenant`, `note` | Labels for you and the agent. |
| `expires` | A date or time after which the identity is refused. |

### The valid-session control

`check` sends the check request with the session and classifies the answer:

| State | Means |
|---|---|
| `valid` | The expected status and the marker: the session works as this account. |
| `expired` | A login page, a login redirect, 401 or 419. A `form` or `json` identity logs in again once. |
| `challenge` | A CAPTCHA, WAF page or rate limit answered instead of the application. |
| `denied` | Authenticated but the check URL is forbidden, or the marker is missing (not the expected account view). |
| `error` | Anything else (5xx, a refused URL). |
| `revoked` | You revoked it. |

A test whose identity isn't `valid` is reported as **blocked**, never as "not vulnerable".

### Using an identity

The agent passes `identity` to `http_request`, `replay_request` and `browse`. The execution broker checks the
policy and the tier, then that the identity may be used for this host, tier and effect, then the approval (which
names the identity: an approval for alice doesn't let bob send the request), and only then adds the session.

---

## Captures

Record the application in your browser's developer tools (Save all as HAR), ZAP, mitmproxy or Burp Suite (Save
items as XML), then import:

```sh
./rvkit capture acme import session.har "checkout flow"
./rvkit capture acme list
./rvkit capture acme show <id>      # the sanitized copy the agent sees
./rvkit capture acme raw <id>       # the original, host only
./rvkit capture acme rm <id>
```

The sanitized copy has cookies, authorization headers, secret-looking query parameters, form fields and JSON keys
(password, token, session, csrf, api_key and similar) and secret-looking values (JWTs, bearer tokens, AWS, GitHub,
Slack and OpenAI keys, private keys) replaced by `[redacted]`. Requests to hosts outside the scope are kept but
flagged and can't be replayed. Response bodies are cut to an excerpt.

The agent replays an entry with `replay_request`, as an identity (the capture's own cookies and tokens are never
sent), optionally changed (`method`, `url`, `query`, `headers`, `remove_headers`, `body`). The result compares
the replayed response with the captured one: status, size, similarity, JSON fields added or removed, the markers
each contains, and a diff. A redacted query value is dropped; a request whose body was redacted must be given a
new body. Replays go through the same broker as `http_request` (scope, approvals, budgets, evidence in
`evidence/replay/`).

---

## The browser

`browse` opens an in-scope page in headless Chromium inside the engagement's sandbox (as the engagement's user,
with its firewall), optionally signed in as an identity, and runs steps: `goto`, `wait_for`, `wait`, `text`,
`click`, `fill`, `press`.

- Every request the page makes is checked against the scope. Out-of-scope requests are blocked and listed.
  WebSockets and downloads are refused, service workers are blocked.
- Fonts and scripts from a CDN are out of scope too. List the ones the page needs in the rules:
  `- Browser support: fonts.gstatic.com, cdn.example.net`. They are allowed for GET page assets only.
- A run with only navigation and reading is tier active and read-only: requests that may change state are
  aborted. `click`, `fill` and `press` make it intrusive, so it needs an approval bound to the URL, the steps
  and the identity.
- Evidence in `evidence/browser/<run>/`: `requests.jsonl` (each request and whether it was allowed),
  `page.html` (input values masked), `screenshot.png` (password fields and `mask` selectors masked),
  `summary.json`.

---

## Authorization matrices

A matrix lists operations (requests), identities (plus `anonymous`) and the expected answer for each pair:

```json
{
  "operations": [
    {"id": "invoice-1", "method": "GET", "url": "https://app.acme.test/api/invoices/1", "marker": "ACME-CONFIDENTIAL-1001"},
    {"id": "payment-1", "method": "GET", "url": "https://app.acme.test/api/payments/1", "marker": "ACME-PAY-5001"}
  ],
  "identities": ["bob-api", "carol-api", "anonymous"],
  "expect": {
    "invoice-1": {"bob-api": "allow", "carol-api": "deny", "anonymous": "deny"},
    "payment-1": {"bob-api": "allow", "carol-api": "deny", "anonymous": "deny"}
  }
}
```

1. The agent proposes it (`propose_authz_matrix`). The expectations come from the client's documentation or
   from you, not from guessing at responses.
2. You review and approve exactly that version: the Testing tab's **Review** and **Approve this version**, or
   `./rvkit authz acme approve tenants` (it prints the matrix and asks). The approval is bound to the matrix's
   digest and the engagement's policy revision: a changed matrix or a changed scope needs a new approval.
3. The agent (or you: **Run**, `./rvkit authz acme run tenants`) runs it. Every identity is checked first; cells
   of an identity that isn't valid are `blocked`.

Each cell gets an outcome (`allowed`, `denied`, `blocked`) and a verdict:

| Verdict | Means |
|---|---|
| `pass` | As expected. |
| `FAIL` | Allowed where deny was expected: the data came back (the owner's marker, or a response like the owner's). A candidate finding: verify it before recording. |
| `unexpected-deny` | Denied where allow was expected: a broken test setup or a functional bug, not a security finding. |
| `blocked` | The identity's session wasn't valid, or the request was refused by the policy. |

Operations that may change state (`effect: write`; any method other than GET, HEAD and OPTIONS by default) need
`allow_writes: true`, `max_writes` and `cleanup` requests (or `no_cleanup_reason`). Results are saved in
`evidence/authz/<name>-<time>.json` and shown in the Testing tab.
