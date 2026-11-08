---
title: Web application test
standard: OWASP WSTG 4.2
tiers: passive, active; intrusive steps need approval
---
# Web application test

## 1. Information gathering (passive, then active)
- [ ] WSTG-INFO: `whatweb <url>`, `httpx-toolkit -u <url> -title -tech-detect -status-code -json -o httpx.json`
- [ ] WAF/CDN in front: `wafw00f <url>` (explains blocked payloads later; never try to evade a WAF unless the RoE
      says so)
- [ ] CMS: WordPress → `wpscan --url <url> --enumerate vp,vt,u --no-update` (plugin/theme/user enumeration)
- [ ] Crawl: `katana -u <url> -jc -d 3 -o katana.txt`; screenshots `gowitness scan single -u <url> --write-jsonl`
      (PNG/JPEG in screenshots/)
- [ ] Parameters: `arjun -u <endpoint> -oJ arjun.json` on interesting endpoints
- [ ] Content discovery, first pass: `ffuf -u <url>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt
      -ac -mc 200,204,301,302,307,401,403 -of json -o ffuf.json -s`. Keep `-ac`: single-page apps answer 200 to
      every path, and without auto-calibration every word "matches". Bigger list (raft-small-words.txt, 43k words)
      only after that, with timeout_s above words / rate (43k at 100 req/s is about 450 s, so timeout_s=900).
      Recursive: `feroxbuster -u <url> -w /usr/share/seclists/Discovery/Web-Content/common.txt -d 2 --json -o
      ferox.json`
- [ ] APIs found here (`/api`, `/graphql`, spec files): also run the api-security playbook
- [ ] AI features (chat, assistant, summarise): also run the ai-llm playbook
- [ ] Record the application map (roles, functions, inputs) in PLAN.md

## 2. Configuration and transport (active)
- [ ] WSTG-CRYP-01: `testssl --jsonfile testssl.json <host>`
- [ ] WSTG-CONF: security headers, HTTP methods, admin interfaces, default files: `nikto -h <url> -o nikto.txt`
- [ ] Templates: `nuclei -u <url> -severity low,medium,high,critical -jsonl -o nuclei.jsonl` (intrusive
      templates are blocked unless approved)

## 3. Authentication, session, authorisation (active)
- [ ] WSTG-ATHN: lockout, reset flow, default credentials (manual; brute force is intrusive → approval)
- [ ] WSTG-SESS: cookie flags, fixation, logout invalidation, CSRF tokens; JWT sessions: `jwt_tool <token>`
      (see api-security step 2)
- [ ] WSTG-ATHZ: IDOR on every object id with two accounts if the client provided them; vertical escalation

## 4. Input validation (active → intrusive)
- [ ] Reflected/stored XSS: manual probes; `dalfox url <url>` is intrusive → approval
- [ ] SQL injection: manual probes first; `sqlmap` is intrusive → approval, with `--batch --level 1 --risk 1`
- [ ] SSRF, path traversal, template injection, open redirect on parameters found in step 1
- [ ] CRLF / header injection: `crlfuzz -u <url> -o crlfuzz.txt`
- [ ] OS command injection: manual first; `commix --url=<url> --data=<body> --batch` is intrusive → approval
- [ ] ZAP active scan (intrusive) only with approval and outside business hours if the RoE says so

## 5. Business logic and client side
- [ ] WSTG-BUSL: workflow bypass, price/quantity tampering, race conditions (manual)
- [ ] WSTG-CLNT: DOM XSS sinks in crawled JS, CORS, postMessage, clickjacking

## Findings
- Asset = URL + parameter. Reproduction = exact request (curl) and the response excerpt.
- Never include session cookies or credentials in findings; reference the evidence file.

## Done when
Every WSTG area above is covered or explicitly out of scope in PLAN.md, all intrusive steps were approved or
skipped with a reason, and every candidate is triaged.
