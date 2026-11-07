---
title: Source code security review
standard: OWASP ASVS 5.0 (level 2 by default; level 3 if the client asks)
tiers: passive
---
# Source code security review

## 1. Orientation (passive)
- [ ] Inventory: languages, frameworks, entry points (routes, handlers, CLI, queue consumers), auth layer,
      data stores, outbound calls. `find /src/<repo> -type f | head`, read README, build files, route tables.
- [ ] Write the attack surface into PLAN.md: each entry point with its inputs and the trust boundary it crosses.

## 2. Automated analysis (passive), one output file each
- [ ] semgrep: `semgrep --config p/<lang> --config p/owasp-top-ten --json -o semgrep.json /src/<repo>`
      (offline: `--config /opt/semgrep-rules/<lang>`)
- [ ] Language linters: bandit (Python) `bandit -r /src/<repo> -f json -o bandit.json`; others via semgrep
- [ ] Data flow: `rv-joern taint /src/<repo> joern-flows.json`: input-to-sink paths
- [ ] Secrets: run the secrets-review playbook's step 2
- [ ] Dependencies: run the supply-chain playbook

## 3. Manual verification (consultant, may delegate per area)
Tool output is a lead list, not findings. For each lead: read the code, follow the data, decide.
Cover the ASVS areas below even where tools found nothing:
- [ ] V1 Encoding and sanitization: SQL/NoSQL/OS/LDAP/template injection, output encoding, deserialisation
- [ ] V2 Validation and business logic: server-side validation, mass assignment, workflow bypass
- [ ] V3 Web frontend: CSP, cookie flags, CORS, clickjacking
- [ ] V4 API and web service: verb tampering, GraphQL depth/introspection
- [ ] V5 File handling: upload type/size, path traversal, SSRF via file URLs
- [ ] V6 Authentication: password storage (argon2/bcrypt/scrypt), MFA, reset flow, lockout
- [ ] V7 Session management: rotation on login, timeout, logout invalidation
- [ ] V8 Authorization: object- and function-level checks on every route (IDOR)
- [ ] V9 Self-contained tokens: JWT algorithm pinning, expiry, audience
- [ ] V11 Cryptography: algorithms, randomness, key handling, hard-coded keys
- [ ] V13 Configuration: debug modes, default credentials, verbose errors, security headers
- [ ] V14 Data protection: sensitive data in logs, caches, URLs
- [ ] V16 Security logging: auth events logged, no secrets in logs

## 4. Findings
- One finding per root cause (group identical sinks). Asset = file:line or route.
- Evidence: the tool output file plus the code location (`/src/<repo>/file.py:12-20`).
- Severity from exploitability in context: reachable without auth? data exposed? Give the CWE.

## Done when
Every entry point in PLAN.md is reviewed against the areas above, every tool lead is confirmed or marked false
positive, and the executive summary names the top three risks.
