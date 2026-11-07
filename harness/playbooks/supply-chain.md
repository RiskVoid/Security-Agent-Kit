---
title: Dependency and supply-chain review
standard: OWASP Top 10 A06 (vulnerable components), SLSA / OpenSSF Scorecard concepts
tiers: passive
---
# Dependency and supply-chain review

## 1. Inventory
- [ ] SBOM: `syft dir:/src/<repo> -o cyclonedx-json=sbom.cdx.json`
- [ ] Note package managers, lock files present or missing, pinned vs ranged versions, private registries

## 2. Known vulnerabilities (two sources, they disagree)
- [ ] `osv-scanner scan source -r /src/<repo> --format json --output-file osv.json`
- [ ] `grype sbom:sbom.cdx.json -o json --file grype.json`
- [ ] Python: `pip-audit -r requirements.txt -f json -o pip-audit.json`; container files: `trivy fs`
- [ ] Rank all ids with intel `prioritize`; KEV and high-EPSS items first

## 3. Reachability (consultant)
- [ ] For each High/Critical: is the vulnerable function used? grep/semgrep for the API, or `rv-joern`.
      Unreachable → keep, lower severity, say why
- [ ] Group by package: one finding per package with all its ids, fixed version = highest needed

## 4. Supply-chain hygiene
- [ ] Lock files committed and used in CI; versions pinned; integrity hashes (pip --require-hashes, npm ci)
- [ ] CI/CD: `trivy config` on Dockerfiles, workflows (unpinned actions, `pull_request_target`, secrets in logs)
- [ ] Base images: pinned by digest, maintained, minimal
- [ ] Typosquatting / unmaintained packages (last release, maintainers)

## Findings
- Asset = manifest file. Remediation = exact upgrade target from `fixed_in`, and note breaking changes.

## Done when
Every manifest is scanned by two scanners, every High/Critical has a reachability verdict, and hygiene items
are reported as one grouped finding if weak.
