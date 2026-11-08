---
title: API security test (REST, GraphQL)
standard: OWASP API Security Top 10 2023, OWASP WSTG (APIT)
tiers: passive, active; fuzzing and exploitation are intrusive (approval)
---
# API security test (REST and GraphQL)

Ask the client for: the API spec (OpenAPI/Swagger, GraphQL schema or Postman collection), two test accounts per
role (needed for authorisation tests), and which endpoints change real data. Put credentials in
`/work/<eng>/creds/` (never in findings or PLAN.md) and pass them with `-H` / `--header`.

## 1. Discovery and inventory (API9: improper inventory)
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
- [ ] Pagination and size limits: `?limit=100000`, huge bodies, deep JSON, GraphQL aliases/batching
      (measure response time; stop at the first sign of impact)
- [ ] Sensitive business flows (API6): purchase, transfer, invite, voucher: replay, race (parallel requests),
      negative/zero amounts, skipping steps
- [ ] Unsafe consumption (API10): third-party data the API trusts (webhooks, redirects, imported URLs)

## Findings
- Asset = method + path (+ GraphQL operation). Reproduction = exact curl with tokens replaced by `<token-userB>`.
- BOLA/BFLA: show both requests (owner and attacker) and both responses (excerpt).
- Map each finding to API1–API10 in its description and to a CWE (639 BOLA, 285/862 authz, 915 mass assignment,
  307 rate limit, 918 SSRF, 89 SQLi, 200/213 data exposure, 347 JWT signature, 1333 ReDoS).

## Done when
Every endpoint in the inventory has had the authentication and authorisation checks, API1–API10 are each covered
or marked out of scope in PLAN.md, fuzzing was approved or skipped with a reason, and candidates are triaged.
