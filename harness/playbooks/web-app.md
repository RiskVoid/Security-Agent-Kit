---
version: 3
title: Web application test
standard: OWASP WSTG 4.2
tiers: passive, active; intrusive steps need approval
---
# Web application test

Every step names who runs it — **[kit]** the harness runs it (the fused recon sweep, an oracle),
**[worker]** a delegated task carries it (`delegate_task`, one class against one endpoint per task,
`plan_item` set, its output stays out of your context), **[you]** a single check you run yourself
(one request, one file to read, one confirmation). The measured rule behind this: the same model that
spent 11-13M planner tokens hand-rolling what the sweep covers carried delegated web attacks in 3-9
worker steps when the task was shaped.

## 1. Information gathering (passive, then active)
- [ ] Recon map first, with the kit's checks fused into it: kali `recon_map` on each web target (crawl, script
      API paths, OpenAPI/GraphQL schema, which paths need authentication) — and in the same call the fixed
      checks: injection probes on every parameter, JWT keys, ReDoS timing, CORS and headers, one authorization
      matrix proposed for the write checks, and every identity the engagement has swept with its own pass
      **[kit]**. Approve that matrix (console or `./rvkit authz approve`), then run `probe_map` with
      `matrix=<name>` for the writes **[kit]**. `get_map` gives the entries (E-xxxxxx) the plan references
- [ ] `import_observations` the sweep's evidence and triage the hits (leads, not findings, until confirmed)
      **[you]**; the cells it covered count as tested
- [ ] WSTG-INFO: `whatweb <url>`, `httpx-toolkit -u <url> -title -tech-detect -status-code -json -o httpx.json`
      **[worker]** (one recon task, several tools)
- [ ] WAF/CDN in front: `wafw00f <url>` (explains blocked payloads later; never try to evade a WAF unless the RoE
      says so) **[worker]**
- [ ] CMS: WordPress → `wpscan --url <url> --enumerate vp,vt,u --no-update` (plugin/theme/user enumeration)
      **[worker]**
- [ ] Crawl: `katana -u <url> -jc -d 3 -o katana.txt`; screenshots `gowitness scan single -u <url> --write-jsonl`
      (PNG/JPEG in screenshots/) **[worker]**
- [ ] Parameters: `arjun -u <endpoint> -oJ arjun.json` on interesting endpoints **[worker]**
- [ ] Content discovery, first pass: `ffuf -u <url>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt
      -ac -mc 200,204,301,302,307,401,403 -of json -o ffuf.json -s`. Keep `-ac`: single-page apps answer 200 to
      every path, and without auto-calibration every word "matches". Bigger list (raft-small-words.txt, 43k words)
      only after that, with timeout_s above words / rate (43k at 100 req/s is about 450 s, so timeout_s=900).
      Recursive: `feroxbuster -u <url> -w /usr/share/seclists/Discovery/Web-Content/common.txt -d 2 --json -o
      ferox.json` **[worker]** (its output is a list, not a conversation)
- [ ] APIs found here (`/api`, `/graphql`, spec files): also run the api-security playbook
- [ ] AI features (chat, assistant, summarise): also run the ai-llm playbook
- [ ] Record the application map (roles, functions, inputs) in PLAN.md **[you]**

## 2. Configuration and transport (active)
- [ ] WSTG-CRYP-01: `testssl --jsonfile testssl.json <https://host>` — the TLS endpoint only; a plain
      `http://` URL has no TLS to test and the tool refuses it **[worker]**
- [ ] WSTG-CONF: security headers, HTTP methods, admin interfaces, default files: `nikto -h <url> -o nikto.txt`
      **[worker]**
- [ ] Templates: `nuclei -u <url> -severity low,medium,high,critical -jsonl -o nuclei.jsonl -t
      /opt/nuclei-templates` (intrusive templates are blocked unless approved) **[worker]**

## 3. Authentication, session, authorisation (active)
- [ ] WSTG-ATHN: lockout, reset flow, default credentials **[you]** (single checks); brute force is intrusive →
      approval, and the `rate_limit` oracle proves what a lockout policy actually is **[kit]** for the
      verification
- [ ] WSTG-SESS: cookie flags, fixation, logout invalidation, CSRF tokens; JWT sessions: `jwt_tool <token>`
      (see api-security step 2) **[worker]**
- [ ] WSTG-ATHZ: IDOR on every object id with two accounts if the client provided them; vertical escalation
      **[worker]** (one endpoint or route group per task); where the target's fixtures have markers, verify with
      the `identity_difference` oracle **[kit]**

## 4. Input validation (active → intrusive)
- [ ] Regex-validated inputs (CWE-1333): on string fields whose malformed value is rejected, inputs of growing
      length built to backtrack, timed — the sweep runs this ladder where it can reach **[kit]**; a field it
      couldn't reach becomes one narrow worker task **[worker]**; stop at the first clear slowdown, never at the
      sizes that stop the app
- [ ] Reflected/stored XSS: manual probes **[you]**; `dalfox url <url>` is intrusive → approval **[worker]**;
      where a marker can prove it, the `marker` or `browser_xss` oracle decides **[kit]**
- [ ] SQL injection: the sweep's error-based and boolean probes cover every parameter **[kit]**; what they hit,
      confirm by hand **[you]**; `sqlmap` is intrusive → approval, `--batch --level 1 --risk 1` **[worker]**
- [ ] SSRF, path traversal, template injection, open redirect on parameters found in step 1: one class against
      one endpoint per task **[worker]**; blind SSRF proves with the `oob_callback` oracle **[kit]**
- [ ] CRLF / header injection: `crlfuzz -u <url> -o crlfuzz.txt` **[worker]**
- [ ] OS command injection: manual first **[you]**; `commix --url=<url> --data=<body> --batch` is intrusive →
      approval **[worker]**; blind command injection proves with `oob_callback` **[kit]**
- [ ] ZAP active scan (intrusive) only with approval and outside business hours if the RoE says so **[worker]**

## 5. Business logic and client side
- [ ] WSTG-BUSL: workflow bypass, price/quantity tampering, race conditions — the `race_request` action fires
      the simultaneous requests under one approval **[kit]**, the read-back that shows the invariant broke is
      an oracle's **[kit]**, the business reasoning around it is yours **[you]**
- [ ] WSTG-CLNT: DOM XSS sinks in crawled JS, CORS, postMessage, clickjacking **[worker]**; CORS and headers on
      page routes are already in the sweep's evidence **[kit]**
- [ ] If the app logs in through an OAuth2/OIDC provider (the map's `oauth` class): the api-security playbook's
      section 6 applies unchanged - redirect_uri validation, state, PKCE downgrade, code reuse, token
      substitution and refresh rotation **[worker]**, one flow per task

## Findings
- Asset = URL + parameter. Reproduction = exact request (curl) and the response excerpt.
- Never include session cookies or credentials in findings; reference the evidence file.

## Done when
Every WSTG area above is covered or explicitly out of scope in PLAN.md, the coverage matrix
(`get_coverage matrix=true`) has no gaps, all intrusive steps were approved or skipped with a reason, and every
candidate is triaged.
