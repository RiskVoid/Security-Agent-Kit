<p align="center">
  <img src="docs/img/banner.svg" alt="RiskVoid Security Agent Kit: a self-hosted AI pentester and code reviewer" width="100%">
</p>

<p align="center">
  <a href="LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-47B6FF?style=flat-square"></a>
  <img alt="Version 0.1.0" src="https://img.shields.io/badge/version-0.1.0-47B6FF?style=flat-square">
  <img alt="macOS and Linux" src="https://img.shields.io/badge/runs_on-macOS_%7C_Linux-1c1f26?style=flat-square&logo=linux&logoColor=white">
  <img alt="Docker" src="https://img.shields.io/badge/Docker-Compose-1c1f26?style=flat-square&logo=docker&logoColor=white">
  <img alt="Python" src="https://img.shields.io/badge/Python-3-1c1f26?style=flat-square&logo=python&logoColor=white">
  <br>
  <img alt="Kali Linux tools" src="https://img.shields.io/badge/tools-Kali_Linux_·_45%2B-1c1f26?style=flat-square&logo=kalilinux&logoColor=white">
  <img alt="Model Context Protocol" src="https://img.shields.io/badge/MCP-servers-1c1f26?style=flat-square">
  <img alt="OWASP methodology" src="https://img.shields.io/badge/method-OWASP_·_PTES-1c1f26?style=flat-square&logo=owasp&logoColor=white">
  <img alt="Self-hosted" src="https://img.shields.io/badge/self--hosted-your_data_stays_local-5cc28c?style=flat-square">
</p>

<p align="center">
  <b>An AI security agent you run on your own machine.</b><br>
  It reviews code and tests web apps, APIs, AI apps and networks with real security tools,<br>
  stays inside the scope you authorise, asks before anything risky, and writes the client report.
</p>

<p align="center">
  <a href="#quick-start">Quick start</a> ·
  <a href="#what-it-can-do">What it can do</a> ·
  <a href="#how-it-works">How it works</a> ·
  <a href="#safety-built-in">Safety</a> ·
  <a href="docs/README.md">Documentation</a>
</p>

> [!WARNING]
> **For authorised work only.** Use it on systems you own or have written permission to test.

---

## What is this?

The Security Agent Kit is a ready-to-run **AI security assistant** for penetration testers, security engineers
and consultants. You describe the job in plain language: *"review this repo"* or *"test this API"*. The agent
then plans the work, runs the tools, checks what it finds and hands you a branded report.

It's built so you can **trust it on client work**:

| | |
|:-:|---|
| <img src="docs/img/icons/sparkles.svg" width="22" alt=""> | **Two models, one team.** A strong cloud model **plans** and writes. A separate **worker** model on a GPU you control runs the tools and reads the client's code. Raw tool output and source code stay with the worker. |
| <img src="docs/img/icons/lock.svg" width="22" alt=""> | **A locked sandbox.** Every tool runs in a Kali Linux sandbox with a firewall that only reaches the targets you authorised. Nothing else is reachable. |
| <img src="docs/img/icons/shield-check.svg" width="22" alt=""> | **You stay in charge.** Risky (intrusive) steps wait for your approval. One command stops everything. |
| <img src="docs/img/icons/file-text.svg" width="22" alt=""> | **Evidence you can defend.** Every command is logged, and every piece of evidence is hashed (SHA-256) and linked to the command that produced it. |

Everything runs in Docker on your own computer. One command sets it up.

---

## What it can do

| | Work | Method | Example tools |
|:-:|---|---|---|
| <img src="docs/img/icons/code.svg" width="20" alt=""> | **Source code review** | OWASP ASVS 5.0 | semgrep, Joern data flow, bandit, manual review |
| <img src="docs/img/icons/package.svg" width="20" alt=""> | **Dependencies & supply chain** | SLSA / OpenSSF | trivy, grype, osv-scanner, syft (SBOM) |
| <img src="docs/img/icons/key.svg" width="20" alt=""> | **Secrets in code & git history** | | gitleaks, trufflehog |
| <img src="docs/img/icons/globe.svg" width="20" alt=""> | **Web applications** | OWASP WSTG 4.2 | ZAP, nuclei, ffuf, sqlmap, httpx |
| <img src="docs/img/icons/plug.svg" width="20" alt=""> | **APIs: REST & GraphQL** | OWASP API Top 10 | schemathesis, jwt_tool, GraphQL tools |
| <img src="docs/img/icons/bot.svg" width="20" alt=""> | **AI apps, agents & MCP servers** | OWASP LLM Top 10, MITRE ATLAS | garak, `rv-llm` (prompt injection, MCP audit) |
| <img src="docs/img/icons/server.svg" width="20" alt=""> | **External networks** | PTES | nmap, nuclei, testssl, DNS tools |

On top of that:
- **Vulnerability intel:** CVE lookups from CISA KEV, EPSS, NVD and OSV.
- **Findings database:** triage, dedupe and severity.
- **Report:** a **web page, Word document, PDF and Excel register**, in RiskVoid branding or your own.

<details>
<summary><b>See the full list of 45+ tools</b></summary>
<br>

The full list, with the tier of each tool (passive, active or intrusive), is in
[docs/tools-reference.md](docs/tools-reference.md). Tiers are defined in
[`kali-mcp/tiers.yaml`](kali-mcp/tiers.yaml), so adding a tool is a one-line change.

</details>

---

## What you need

| | Requirement | Notes |
|:-:|---|---|
| <img src="docs/img/icons/laptop.svg" width="20" alt=""> | **A Mac or Linux computer** with **Docker** | Docker Desktop, OrbStack or Docker Engine. 16 GB RAM recommended (8 GB minimum), ~25 GB free disk |
| <img src="docs/img/icons/key.svg" width="20" alt=""> | **A planner key** (optional) | An [OpenRouter](https://openrouter.ai/keys) key, or an Anthropic / OpenAI key. Without one, use the fully local agent |
| <img src="docs/img/icons/cpu.svg" width="20" alt=""> | **A GPU for the worker model** | **Google Colab Pro** (default, nothing to install), or your own GPU (Ollama, LM Studio, llama.cpp, vLLM; ~24 GB VRAM), or any OpenAI-compatible API |
| <img src="docs/img/icons/terminal.svg" width="20" alt=""> | `python3`, `curl`, `perl`, `openssl` | Already on most Macs and Linux machines |

---

## Quick start

```sh
git clone https://github.com/RiskVoid/Security-Agent-Kit.git
cd Security-Agent-Kit
./rvkit setup
```

`setup` asks four questions (press Enter for the defaults):
- where to keep client files;
- your organisation name;
- your planner key (hidden input);
- where the worker model runs.

It then starts everything, which takes about 10 minutes the first time.

```sh
./rvkit doctor        # checks everything and tells you what to fix
./rvkit quickstart    # a practice engagement against a vulnerable app in an isolated lab
```

Open **http://localhost:8000**, pick the **`riskvoid-planner`** agent and start talking.

> [!TIP]
> Using **Claude Code**? Type `/rv-setup`, then `/rv-start`, in the kit folder, and it does all of the above,
> including starting the Colab GPU.

**Next:** [Your first engagement](docs/first-engagement.md), a guided 20-minute run against OWASP Juice Shop.

---

## Using it on a real job

```sh
./rvkit new             # 1. create an engagement: client, targets, allowed tiers, rate limit
./rvkit console         # 2. open the console: live view, approvals, findings, report
```

**3.** In the agent UI, tell the planner what to do:

> Engagement `acme-2026-11`: review the source code in `/src/acme-repo`, including dependencies and secrets.
> Follow the matching playbooks, then write the executive summary and generate the report.

**4.** Approve intrusive steps when asked, in the console or with `./rvkit watch` in a terminal.
**5.** `./rvkit report acme-2026-11` builds the report. `./rvkit close acme-2026-11` seals and archives the
engagement with a checksum manifest.

<p align="center">
  <img src="docs/img/canvas-home.png" alt="The agent UI" width="85%">
</p>

---

## How it works

```mermaid
flowchart LR
    you(["You"]) --> ui["Agent UI<br/>localhost:8000"]
    you --> console["RiskVoid Console<br/>approvals · findings · live view"]
    ui --> planner["Planner<br/>cloud model: plans, triages, writes"]
    planner --> worker["Worker<br/>your GPU model: runs the tools"]
    planner --> findings["Findings & report"]
    worker --> kali
    planner --> kali["Kali sandbox<br/>45+ tools"]
    kali -->|"scope firewall<br/>only authorised targets"| target[("Target")]
    console -.->|approve · halt| kali
    kali --> audit["Audit log<br/>+ hashed evidence"]

    classDef rv fill:#14161b,stroke:#47B6FF,color:#f2f4f7
    classDef safe fill:#14161b,stroke:#5cc28c,color:#f2f4f7
    class ui,planner,worker,findings,console rv
    class kali,audit safe
```

| Piece | What it does |
|---|---|
| **Agent UI** ([OpenHands](https://github.com/All-Hands-AI/OpenHands)) | Where you talk to the agent. Its container has **no direct internet**. |
| **Planner** | A frontier model (default Claude Sonnet via OpenRouter, ZDR providers only) that plans, triages and writes. |
| **Worker** | Qwen3.8-27B on Colab, your GPU or any OpenAI-compatible endpoint. It runs the tools and reads the code. |
| **Kali sandbox** | The tools, isolated per engagement, behind the scope firewall, with tiers, rate caps and approvals. |
| **Console** | A local web page for engagements, the live run view, approvals, findings triage, reports and the audit log. |
| **LiteLLM** | One model gateway with a daily spend budget and fallbacks. |

More detail: [Architecture](docs/architecture.md).

---

## Safety built in

| | Control | What it means for you |
|:-:|---|---|
| <img src="docs/img/icons/target.svg" width="20" alt=""> | **Scope firewall** | Each engagement can only reach the IPs, domains and code you listed. Everything else is blocked at the network level. |
| <img src="docs/img/icons/layers.svg" width="20" alt=""> | **Tiers** | Commands are **passive**, **active** or **intrusive**. You choose which tiers an engagement allows. |
| <img src="docs/img/icons/shield-check.svg" width="20" alt=""> | **Approvals** | Intrusive commands (sqlmap, hydra, exploit scripts…) wait for your yes. Each approval works once, for one exact command. |
| <img src="docs/img/icons/gauge.svg" width="20" alt=""> | **Rate limits** | Scanners get your max rate added automatically, and faster rates are refused. |
| <img src="docs/img/icons/stop.svg" width="20" alt=""> | **Halt button** | `./rvkit halt <eng>` kills everything running for an engagement immediately. |
| <img src="docs/img/icons/file-text.svg" width="20" alt=""> | **Audit log** | Every command, refusal and approval is recorded where the agent can't touch it. |
| <img src="docs/img/icons/lock.svg" width="20" alt=""> | **Contained agent** | The agent has no direct internet, read-only engagement files, and can't widen its own scope. |
| <img src="docs/img/icons/flask.svg" width="20" alt=""> | **Strict mode** | Optional: scripts and data-sending requests also need approval (`Strict tiers: on`). |

Known limitations and how to report a vulnerability: [SECURITY.md](SECURITY.md).

---

## Where your data goes

| Part | Sees | Runs on |
|---|---|---|
| **Worker model** | tool output, client code, evidence | Colab (your Google account), **or your own GPU / endpoint** |
| **Planner** | task descriptions, redacted summaries, findings | OpenRouter (zero-data-retention providers only), or Anthropic / OpenAI directly |
| **Everything else** | findings, evidence, audit log, reports | **your machine** |

> [!NOTE]
> **Need nothing to leave your machine?** Run the worker locally (`./rvkit worker local`), use the
> `riskvoid-local` agent, and pick `offline` when you create the engagement. Details:
> [Models](docs/models.md#where-your-data-goes).

---

## Practice lab & benchmarks

`./rvkit lab up` starts deliberately vulnerable targets on an **isolated network with no internet**:
OWASP Juice Shop, DVWA, VAmPI (REST), DVGA (GraphQL) and a RiskVoid LLM lab (AI agent + MCP).

`./rvkit bench <name>` runs the agent unattended against a known target and scores it on recall, precision,
cost and time. See [Lab and benchmarks](docs/lab-and-benchmarks.md).

---

## Commands

<details>
<summary><b>The main <code>./rvkit</code> commands</b> (run <code>./rvkit help</code> for all)</summary>

```
setup [--yes]          first-time setup              doctor [--models]     check everything
up | down              start / stop the stack        status                one-screen overview
quickstart             practice engagement + UI      console               local web console

new [name]             create an engagement          watch                 approve commands live
eng list               engagements + scope           scope <eng> [--yes]   apply SCOPE.md / RULES.md edits
approvals | approve | deny | halt | resume | audit | show | report | close <eng> …

connect <url> [key] [model]       Colab worker       worker [local|api|colab|fallback …]
planner [--direct] <model>        planner model      budget [usd]          daily spend cap
lab up|down|status                practice targets   bench <name|all>      benchmarks
```

</details>

---

## Documentation

| Start here | Do the work | Go deeper |
|---|---|---|
| [What the kit is](docs/overview.md) | [Engagements & scope](docs/engagements.md) | [Architecture](docs/architecture.md) |
| [Getting started](docs/getting-started.md) | [Working with the agent](docs/running-the-agent.md) | [Models & costs](docs/models.md) |
| [Your first engagement](docs/first-engagement.md) | [The console](docs/console.md) | [Tools reference](docs/tools-reference.md) |
| [Troubleshooting](docs/troubleshooting.md) | [Findings & reports](docs/findings-and-reports.md) | [Configuration](docs/configuration.md) |
| [Commands](docs/cli-reference.md) | [Lab & benchmarks](docs/lab-and-benchmarks.md) | [Operations](docs/operations.md) |

Stuck? Run **`./rvkit doctor`** first. It checks Docker, every service, the firewall and the models, and says
what to fix.

---

## Contributing, security & licence

- **Contributing:** dev setup, tests and how to send changes are in [CONTRIBUTING.md](CONTRIBUTING.md).
- **Security:** the security model, known limitations and private vulnerability reporting are in [SECURITY.md](SECURITY.md).
- **Licence:** [Apache-2.0](LICENSE) ([NOTICE](NOTICE)). Third-party components are listed in [THIRD_PARTY.md](THIRD_PARTY.md).

<p align="center">
  <br>
  <sub>Built by <a href="https://riskvoid.com"><b>RiskVoid</b></a> for security people who want an AI teammate they can actually trust.</sub>
</p>
