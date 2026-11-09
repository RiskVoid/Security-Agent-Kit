---
version: 1
title: Secrets review
standard: OWASP ASVS V13.3 (secret management), CWE-798
tiers: passive
---
# Secrets review

## 1. Scan
- [ ] Working tree: `gitleaks dir /src/<repo> --report-format json --report-path gitleaks.json`
- [ ] History (if .git is present): `gitleaks git /src/<repo> --report-format json --report-path gitleaks-history.json`
- [ ] Verified-capable scan: `trufflehog filesystem /src/<repo> --json --no-verification > trufflehog.json`
      (verification calls the provider: only with explicit client consent, and it's active, not passive)
- [ ] Config files: `trivy fs --scanners secret /src/<repo>`; grep env files, CI configs, Dockerfiles, notebooks

## 2. Triage
- [ ] Remove test fixtures, examples and placeholders; note the rule for each false positive
- [ ] For each real secret: type, where (file:line, commit), still in HEAD or only in history, scope of access
- [ ] Never copy the secret into findings, PLAN.md or chat: cite the evidence file and line, show at most the
      first 4 characters

## 3. Hygiene
- [ ] Secrets loaded from env / a secret manager? .env files ignored? Pre-commit secret scanning in CI?

## Findings
- One finding per secret type and location group. Remediation: rotate first, then remove from history
  (git filter-repo), then add scanning to CI.

## Done when
Every scanner hit is triaged, every live-looking secret has a rotation recommendation, and history was scanned
or its absence noted.
