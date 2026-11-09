---
version: 1
title: External network assessment
standard: PTES (intelligence gathering, vulnerability analysis); CIS-style service hardening
tiers: passive, active; intrusive steps need approval
---
# External network assessment

## 1. Passive reconnaissance
- [ ] Subdomains: `subfinder -d <domain> -o subfinder.txt`, `amass enum -passive -d <domain> -o amass.txt`
- [ ] Resolve and keep only in-scope hosts: `dnsx -l subs.txt -a -resp -json -o dnsx.json`
      (anything resolving outside scope is listed in PLAN.md as "discovered, not tested")
- [ ] Web search for exposed documents, leaked credentials mentions, code repositories (SearXNG)

## 2. Discovery (active)
- [ ] Ports: `naabu -list hosts.txt -top-ports 1000 -json -o naabu.json` (rate is capped by the RoE)
- [ ] Services: `nmap -sV -sC -p <open ports> -oA nmap-services <host>`
- [ ] Web services found: hand over to the web-app playbook (steps 1–2)

## 3. Vulnerability analysis (active)
- [ ] Map service versions to CVEs: `nuclei -l urls.txt -tags cve -jsonl -o nuclei-cve.jsonl`, nmap vulners
      output, vendor advisories
- [ ] Rank every CVE with intel `prioritize` (KEV first); check each product with `kev_search`
- [ ] TLS on every TLS port: `testssl --jsonfile testssl-<host>.json <host:port>`
- [ ] Exposed management: SSH (auth methods, versions), RDP, SMB, databases, admin panels, VPN portals

## 4. Validation (intrusive, approval required)
- [ ] Only for high-value leads: safe proof (version banner, harmless check request), never DoS, never data
      modification

## Findings
- Asset = host:port/service. Evidence = scanner output file + banner excerpt.
- KEV-listed exposures are at least High; say so in the impact.

## Done when
Every in-scope host has a port/service inventory in PLAN.md, every service is assessed, and every CVE lead is
ranked and triaged.
