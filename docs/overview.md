# What the kit is

This page explains what the RiskVoid Security Agent Kit does, how its two models share the work, which kinds of
security testing it covers, and the terms used throughout the rest of the documentation.

## Who it's for

Security consultants, penetration testers and in-house security teams who want an AI assistant to do the
hands-on work of an **authorised** assessment: run the tools, read the code, triage results and write the report.
You stay in charge. You set the scope, approve risky steps, and review findings before anything goes to a client.

The kit runs on your own computer in Docker. Client code, evidence, findings and reports stay in folders you
choose. The only parts that can run elsewhere are the models, and you choose where those run (see
[Models](models.md)).

## What it does

You give the agent a task in plain language, for example "source code review of `/src/acme-repo`, including
dependencies and secrets". The agent then:

1. reads the engagement's scope and rules, and refuses to work outside them;
2. picks the matching methodology playbooks and writes a test plan (`PLAN.md`);
3. runs real security tools (nmap, nuclei, ZAP, semgrep, Joern, trivy and more than 40 others) in a sandbox
   that can reach only the authorised targets;
4. records leads as **candidate** findings, verifies them, and marks each one **confirmed** or
   **false-positive**;
5. writes an executive summary and generates a branded HTML / `.docx` / PDF report and an `.xlsx` findings register,
   with SHA-256 hashes for every evidence file and the audited command that produced each one.

You watch from the browser UI at http://localhost:8000/ and from the terminal (`./rvkit watch`,
`./rvkit status`, `./rvkit audit <engagement>`).

## Planner and worker

The kit uses two models with different jobs.

| Model | Job | Sees |
|---|---|---|
| **Planner**: a hosted model via OpenRouter (default GLM-5.3) | plans, decides what to run next, verifies, writes findings and the report | task descriptions, the worker's redacted summaries, findings, files it chooses to open |
| **Worker**: Qwen3.8-27B on a Colab GPU, your own or a rented GPU, any OpenAI-compatible endpoint, or a hosted model on OpenRouter (no GPU) | carries out one focused, hands-on task at a time: runs tools, reads code, records candidates | raw tool output, client code, evidence |

The split keeps the bulk of client data with the worker. The planner hands over a goal ("run semgrep and bandit
on `/src/acme`, check the top results in the code, record candidates with file:line evidence") through the
`delegate_task` tool. The worker runs the tools, saves the raw output under
`/work/<engagement>/evidence/tasks/<task_id>/`, and sends back a short summary with secrets redacted. If you run
the worker on hardware you control, raw tool output and client code never leave your setup.

You can also run everything on the worker model alone with the `riskvoid-local` agent: no OpenRouter, nothing sent
to a cloud model. Results are usually weaker, because a 27B model is a less capable planner. See
[Models](models.md#agent-profiles).

## What you can test

Each testing type has a playbook: a checklist with phases, exact commands and a "done when" bar. The planner
copies the matching playbooks into `PLAN.md` and works through them.

| Testing type | Playbook | Standard | Main tools |
|---|---|---|---|
| Source code review | `code-review` | OWASP ASVS 5.0 (level 2 by default) | semgrep, bandit, Joern data-flow tracing (`rv-joern taint`), manual review |
| Secrets in code and history | `secrets-review` | OWASP ASVS V13.3, CWE-798 | gitleaks, trufflehog |
| Dependencies and supply chain | `supply-chain` | OWASP Top 10 A06, SLSA / OpenSSF Scorecard concepts | osv-scanner, pip-audit, trivy, syft (SBOM), grype, plus KEV / EPSS / NVD ranking |
| Web applications | `web-app` | OWASP WSTG 4.2 | katana, httpx, nuclei, nikto, ffuf, feroxbuster, ZAP, sqlmap, dalfox, testssl |
| APIs (REST and GraphQL) | `api-security` | OWASP API Security Top 10 2023 | schemathesis, jwt_tool, graphw00f, graphql-cop, clairvoyance, arjun |
| AI applications, agents and MCP servers | `ai-llm` | OWASP Top 10 for LLM Applications 2025, MITRE ATLAS | `rv-llm` (probe library with canaries, MCP server audit, injection payloads), garak |
| External network | `external-network` | PTES | subfinder, amass, dnsx, naabu, nmap, httpx, nuclei, testssl, sslscan |

Code-based types (code review, secrets, supply chain) are passive: they need no network access to the client.
The others send traffic to the targets in scope. One engagement can combine several types, for example a web
app and its source code.

The full tool list, with the tier each tool runs at, is in the [Tools reference](tools-reference.md).

## Safety controls

The agent runs real attack tools, so the kit puts limits around it that the agent can't change:

- **Scope firewall.** Every Kali command runs as an unprivileged user for that engagement. An nftables firewall
  lets that user reach only the IPs and domains in the engagement's `SCOPE.md`, plus package and
  vulnerability-database sites when the engagement is online. Everything else is dropped, including the kit's
  own services, loopback and cloud metadata addresses.
- **Command sandbox.** Each command sees only its own engagement folder and its in-scope client code (read-only).
- **Intensity tiers.** Commands are classed passive, active or intrusive. Commands above the tiers allowed in
  `RULES.md` are refused, and rate-limitable tools get the engagement's maximum rate added.
- **Human approval.** Intrusive commands (exploitation, brute force, fuzzing that changes data) wait for you to
  approve them. An approval is single-use, bound to the exact command, and expires after 24 hours.
- **Halt.** `./rvkit halt <engagement>` kills everything running for an engagement and blocks new commands.
- **Testing window.** `RULES.md` can limit testing to set UTC hours.
- **Audit log.** Every command, refusal, approval, halt and scope change is logged, in a control volume only
  `./rvkit` can change.
- **Contained agent.** The OpenHands agent container has no direct internet access. It reaches package
  registries and vulnerability databases through an allowlisting proxy, and sees engagement files read-only.
- **Scope changes need you.** Only `./rvkit scope <engagement>` applies edits to `SCOPE.md` and `RULES.md`. An
  agent that edits those files changes nothing.

How these fit together: [Architecture](architecture.md). Exact behaviour and known gaps:
[SECURITY.md](../SECURITY.md).

## Evidence and reporting

- Every file a Kali command writes in the engagement folder is SHA-256 hashed in the audit log, with the
  command, time and tier that produced it.
- The report checks each finding's evidence against that log. A file that was changed after it was produced, or
  wasn't produced by an audited command, is flagged.
- The report stays **DRAFT** until it's ready to send: executive summary written, every candidate triaged,
  evidence unchanged, client name set.
- Reports use the RiskVoid design by default, a neutral design with your organisation's name, or your own logo,
  colours and fonts.
- `./rvkit close <engagement>` seals the engagement: a SHA-256 manifest of the folder, an archive with its own
  checksum, and a halt.

Details: [Findings and reports](findings-and-reports.md).

## What it is not

- **Not an unattended pentest robot.** It's built for a consultant who sets the scope, watches the run and
  approves intrusive steps. It won't test anything outside the scope you write down, and it asks before taking
  risks.
- **Not a replacement for your judgement.** Scanner output is treated as a lead, and the agent is told to verify
  before confirming. You still review every finding before it reaches a client.
- **Not a scanner replacement.** It drives standard open-source scanners and reads their output. It doesn't
  bring its own vulnerability signatures.
- **Not a guarantee of containment against a determined agent.** Some gaps are known and documented, for
  example tiers are assigned by program name, so a script (passive tier) or `curl` (active tier) can send
  intrusive traffic to in-scope hosts without approval. Read [Known limitations](../SECURITY.md#known-limitations) before client work.

Use it only on systems you own or have written permission to test.

## Glossary

| Term | Meaning |
|---|---|
| **Engagement** | One piece of authorised work for one client, with its own folder (`/work/<engagement>/`), scope, rules, findings, evidence and report. Created with `./rvkit new`. See [Engagements](engagements.md). |
| **Scope** | The authorised targets, in the engagement's `SCOPE.md`: hosts, domains (a domain includes its subdomains), CIDRs, and client code as `/src/<repo>`. Enforced by the firewall. |
| **Rules** | The engagement's `RULES.md`: allowed tiers, maximum rate, online or offline, an optional testing window, and whether the worker is private. |
| **Tier** | How intrusive a command is. **Passive**: code and config analysis, DNS, research. **Active**: scans, crawling, fingerprinting. **Intrusive**: exploitation, brute force, attack payloads, DoS-capable tools. |
| **Approval** | Your OK for one intrusive command, given with `./rvkit watch` or `./rvkit approve <engagement> <id>`. Single-use, exact command only, valid 24 hours. |
| **Halt** | An emergency stop for one engagement (`./rvkit halt <engagement>`): running commands are killed and new ones refused until `./rvkit resume <engagement>`. |
| **Planner** | The frontier model (via OpenRouter) that plans, verifies and writes up. Used by the `riskvoid-planner` agent. |
| **Worker** | The model that does the hands-on tool work and sees raw output and client code. Qwen3.8-27B by default, on Colab, your GPU or any OpenAI-compatible endpoint; or a hosted model on OpenRouter when you have no GPU. |
| **Fallback** | An optional OpenRouter model that takes over worker calls while the worker endpoint is down. Off by default, because it then sees client data. |
| **Private worker** | `Worker model: private` in `RULES.md`: this engagement's tool work never uses the fallback, even when it's on. |
| **Playbook** | A methodology checklist for one testing type (`harness/playbooks/`). |
| **Candidate finding** | A lead recorded by the worker or planner, not yet verified. Candidates never appear in the report, and open ones keep it in DRAFT. |
| **Confirmed finding** | A finding the planner has verified. Findings can also be `false-positive`, `duplicate`, `fixed` or `accepted-risk`. |
| **Evidence provenance** | The check that an evidence file's current SHA-256 matches what an audited Kali command produced. Shown per file in the report. |
| **Audit log** | The authoritative record of every command, refusal, approval, halt and scope change. `./rvkit audit <engagement>` shows it. |
| **Close-out** | `./rvkit close <engagement>`: audit extract, SHA-256 manifest, archive with checksum, then halt. |
| **Lab** | Deliberately vulnerable practice targets on an isolated Docker network (`./rvkit lab up`). See [Lab and benchmarks](lab-and-benchmarks.md). |
| **Egress proxy** | The allowlisting proxy that is the agent container's only way out: package registries and vulnerability databases only. |
| `/src` | Client code (`PROJECTS_DIR` on your computer, default `~/riskvoid/projects`), read-only everywhere. |
| `/work` | Engagements (`ENGAGEMENTS_DIR`, default `~/riskvoid/engagements`). Read-only for the agent; written by Kali commands and the findings tools. |
| `/workspace/project` | The agent's own scratch space inside the OpenHands container. |

Next: [Getting started](getting-started.md).
