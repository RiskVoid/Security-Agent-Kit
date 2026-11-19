---
version: 2
title: API security test (REST, GraphQL)
standard: OWASP API Security Top 10 2023, OWASP WSTG (APIT)
tiers: passive, active; fuzzing and exploitation are intrusive (approval)
---
# API security test (REST and GraphQL)

Ask the client for: the API spec (OpenAPI/Swagger, GraphQL schema or Postman collection), two test accounts per
role (needed for authorisation tests), and which endpoints change real data. Put credentials in
`/work/<eng>/creds/` (never in findings or PLAN.md) and pass them with `-H` / `--header`.

## 1. Discovery and inventory (API9: improper inventory)
- [ ] Recon map first: kali `recon_map` on the API and its web client (schema, crawl, script API paths, which
      need authentication); `get_map` is the inventory the plan items reference (E-xxxxxx)
- [ ] Then let the kit check: kali `probe_map` (after `recon_map`) — injection probes on every parameter (path
      parameters included), JWT keys cracked offline, mass assignment on object-creating writes, timing on
      validated string fields. Its reads run at once; its writes are one authorization matrix the user approves.
      `import_observations` its evidence and triage the hits: a hit names the parameter and the exact requests
      (leads, not findings, until confirmed). The cells it covered count as tested.
- [ ] Spec: try `/openapi.json`, `/swagger.json`, `/v3/api-docs`, `/api-docs`, `/swagger-ui/`, `/graphql`,
      `/graphiql`, `/.well-known/` with `curl -s -o /dev/null -w '%{http_code} %{url}\n' <url>/<path>`
- [ ] Routes: `ffuf -u <base>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt
      -ac -mc all -fc 404 -of json -o ffuf-api.json`; versions: `/v1 /v2 /api/v1 /internal /admin /beta`
- [ ] Crawl the web client for API calls: `katana -u <app> -jc -d 3 -f qurl -o api-urls.txt`
- [ ] Parameters on interesting endpoints: `arjun -u <endpoint> -m JSON -oJ arjun.json`
- [ ] GraphQL: `graphw00f -d -f -t <url>/graphql` (engine fingerprint); introspection:
      `curl -s <url>/graphql -H 'Content-Type: application/json' -d '{"query":"{__schema{types{name}}}"}'`
- [ ] GraphQL with introspection disabled: `clairvoyance <url>/graphql -o schema.json` (field suggestions)
- [ ] Record every endpoint, method, auth requirement and object id in PLAN.md (the inventory is a deliverable)

## 2. Authentication (API2)
- [ ] Endpoints that answer without a token (call each read endpoint with no Authorization header)
- [ ] JWT: decode `jwt_tool <token>` (alg, kid, jku, exp, claims); weak HS secret, offline:
      `jwt_tool <token> -C -d /usr/share/seclists/Passwords/scraped-JWT-secrets.txt`; against the API (`-t <url>
      -rh "Authorization: Bearer <token>"`, intrusive with attacks): `-M pb` playbook scan, `-X a` (alg none),
      `-X k` (key confusion), `-S hs256 -p <cracked-secret> -I -pc sub -pv <other-user>` (forged identity)
- [ ] Token lifetime, logout/revocation, refresh token reuse, password reset flow, user enumeration in login/
      register/reset responses (status codes, messages, timing)
- [ ] Rate limiting on login, OTP and reset (API4): send 30 requests at the engagement's max rate and record
      whether any are refused. Real brute force is intrusive (approval)

## 3. Authorisation (API1 BOLA, API3 BOPLA, API5 BFLA). Most important part
- [ ] BOLA: for every endpoint with an object id, request user A's object with user B's token. Try numeric ±1,
      UUIDs seen elsewhere, ids in body/query/headers, and arrays `[1,2]`
- [ ] BFLA: call admin and other-role functions (methods too: `PUT/DELETE` where only `GET` is documented) with a
      low-privilege token
- [ ] Excessive data exposure (API3): compare response fields with what the UI shows; look for password hashes,
      tokens, internal ids, other users' PII; `/debug`, `?fields=*`, `?expand=` parameters
- [ ] Mass assignment (API3): add `isAdmin`, `role`, `admin`, `balance`, `owner_id`, `verified` to create/update
      bodies and check whether they stick
- [ ] GraphQL: per-field authorisation on every type reachable from `Query` and `Mutation`; mutations as a
      low-privilege user; `node(id:)` / global id access

## 4. Input handling (API8 misconfiguration, API7 SSRF, injection)
- [ ] Schema fuzzing (intrusive, approval; GET-only first if the client worries about data):
      `schemathesis run <spec-url> --url <base> -H "Authorization: Bearer <t>" --checks all
      --max-examples 30 --report har --report-dir st-report` (add `--include-method GET` for read-only)
- [ ] GraphQL checks: `graphql-cop -t <url>/graphql -o json` (introspection, field suggestions, batching, alias
      and depth DoS indicators, GET-based CSRF, tracing/debug)
- [ ] Injection on parameters found: SQL/NoSQL (`'`, `{"$ne":null}`), command, template, XXE on XML endpoints;
      sqlmap / commix only after manual signs, intrusive (approval)
- [ ] SSRF (API7): any parameter that takes a URL, webhook or file location; try the lab's or client's own hosts
      only (the sandbox blocks metadata and other out-of-scope addresses anyway)
- [ ] Misconfiguration: CORS (`-H 'Origin: https://evil.example'`), verbose errors and stack traces, HTTP methods,
      missing security headers, TLS (`testssl`)

## 5. Resources and business flows (API4, API6, API10)
- [ ] Regex-validated inputs (CWE-1333): on every string field whose malformed value is rejected, send inputs of
      growing length built to backtrack (`a` × 16/20/24 + `@`) and watch the response time; a clear growth is the
      finding. `probe_map` runs this ladder for you (and stops before the sizes that stop the API); test what it
      skipped by hand
- [ ] Pagination and size limits: `?limit=100000`, huge bodies, deep JSON, GraphQL aliases/batching
      (measure response time; stop at the first sign of impact)
- [ ] Sensitive business flows (API6): purchase, transfer, invite, voucher: replay, race (parallel requests),
      negative/zero amounts, skipping steps
- [ ] Unsafe consumption (API10): third-party data the API trusts (webhooks, redirects, imported URLs)

## 6. OAuth2 and OIDC (CWE-351, CWE-308, CWE-384)

Applies when the map has an authorize, token, callback or OIDC route, or redirect_uri/client_id parameters (the
`oauth` coverage class). Test the flow end to end with your own throwaway OAuth client registration if the target
allows one, and record each check's requests as evidence. Recipes assume `<idp>` is the authorization server and
`<cb>` your registered redirect URI.

- [ ] redirect_uri validation: send the authorize request with the exact `<cb>`, then with variants:
      a different host, a subdomain (`evil.<cb-host>`), a suffix path (`<cb>/../evil`), a query or fragment
      appended, and an IP literal. A 200 redirect with `code` for any variant but the exact match is the finding
      (authorization-code injection: another site can receive the code)
- [ ] state: authorize without the state parameter (does the server accept it?), and with one — confirm the
      callback echoes it back unchanged. No state, or state not validated at the token endpoint, is CSRF in the
      authorization flow
- [ ] PKCE downgrade: authorize with `code_challenge` omitted, or `response_type=token` (implicit flow). If the
      code is issued without PKCE or the implicit flow is live, code interception gets easier
- [ ] authorization-code reuse: complete a flow, then replay the exact token request (same grant_type=code and
      code). The second use must fail; a 200 with a fresh token pair is the finding (CWE-384)
- [ ] token substitution and audience: use A's access token on B's flow (call the resource server directly), and
      check whether tokens carry an `aud` claim the server verifies. An audience-less token accepted everywhere
      is the finding; a forged `aud` against the cracked/leaked key proves it
- [ ] refresh token rotation: use a refresh token twice. If both work and return the SAME refresh token
      (no rotation), or the old one still works after use, stolen refresh tokens are long-lived — the finding
- [ ] Token endpoint auth: `client_secret` in the query string or body instead of the Authorization header,
      and whether the token endpoint rate-limits (it mints tokens: brute force is intrusive — approval)

## Findings
- Asset = method + path (+ GraphQL operation). Reproduction = exact curl with tokens replaced by `<token-userB>`.
- BOLA/BFLA: show both requests (owner and attacker) and both responses (excerpt).
- Map each finding to API1–API10 in its description and to a CWE (639 BOLA, 285/862 authz, 915 mass assignment,
  307 rate limit, 918 SSRF, 89 SQLi, 200/213 data exposure, 347 JWT signature, 1333 ReDoS).

## Done when
Every endpoint in the inventory (the recon map) has had the authentication and authorisation checks, the coverage
matrix (`get_coverage matrix=true`) has no gaps, API1–API10 are each covered
or marked out of scope in PLAN.md, fuzzing was approved or skipped with a reason, and candidates are triaged.
