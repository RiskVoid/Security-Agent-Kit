# RiskVoid Security Agent Kit

A self-hosted AI security assistant for **authorised** security work: source code review, dependency and secrets
review, web application, API (REST/GraphQL), AI application / agent / MCP and external network testing, with
evidence and a client-ready report. Open source (Apache-2.0), from [RiskVoid](https://riskvoid.com).

- **Planner + worker.** A frontier model (via OpenRouter) plans, triages and writes up. A separate worker model
  (Qwen3.8-27B on a Colab GPU, your own GPU, or any OpenAI-compatible endpoint) does the hands-on tool work, so raw
  tool output and client code go to the worker, not the planner. Or run everything on the worker model. See
  [Where your data goes](#where-your-data-goes).
- **Real tools, safely.** 45+ tools (nmap, nuclei, ZAP, sqlmap, schemathesis, jwt_tool, garak, semgrep, Joern,
  trivy, …) behind a per-engagement sandbox: network firewall limited to the authorised scope, intensity tiers,
  human approval for intrusive steps, emergency halt, and an audit log.
- **Contained agent.** The agent's own container has no direct internet access and read-only access to
  engagement files. Targets are reached only through the audited tool sandbox.
- **Method and evidence.** Playbooks (OWASP ASVS / WSTG / API Top 10 / LLM Top 10, PTES, supply chain, secrets), a
  findings database, vulnerability intel (CISA KEV, EPSS, NVD, OSV), SHA-256-verified evidence, and a branded
  `.docx` / PDF report with your own name and logo if you like.
- **Ready on first launch.** `./rvkit setup` asks a few questions, starts the stack and configures the OpenHands
  agent UI: models, tools and agents are set up.

```
YOUR COMPUTER (Docker)                                                       WORKER MODEL (pick one)
┌─────────────────────────────────────────────────────────────────────┐     ┌──────────────────────────────┐
│ browser ─► localhost:8000 ─► OpenHands agent (no direct internet)   │     │ Google Colab GPU (default)   │
│                                │                                    │     │ your own GPU: Ollama,        │
│      LiteLLM ◄─────────────────┤ models   planner ── OpenRouter     │     │   LM Studio, llama.cpp, vLLM │
│        └─────────────────────────────────  worker ──────────────────┼────►│ any OpenAI-compatible URL    │
│                                ├─► kali      sandboxed tools, scope firewall, audit log                │
│                                ├─► worker    delegates tool work to the worker model                   │
│                                ├─► findings  findings DB, playbooks, file writes, branded report        │
│                                ├─► intel     CVE/GHSA: KEV, EPSS, NVD, OSV                              │
│                                ├─► web       web search + public page fetch (never engagement targets)  │
│                                └─► egress proxy: package registries and vulnerability databases only    │
│ lab (optional): vulnerable practice targets, isolated network       │
└─────────────────────────────────────────────────────────────────────┘
```

> Use it only on systems you own or have written permission to test.

**Documentation:** [docs/](docs/README.md) has the full guides: [what the kit is](docs/overview.md),
[getting started](docs/getting-started.md), [engagements](docs/engagements.md),
[working with the agent](docs/running-the-agent.md), [the console](docs/console.md), [findings and reports](docs/findings-and-reports.md),
[models](docs/models.md), [architecture](docs/architecture.md), [tools](docs/tools-reference.md),
[commands](docs/cli-reference.md), [configuration](docs/configuration.md), [operations](docs/operations.md) and
[troubleshooting](docs/troubleshooting.md). This README is the short version.

---

## What you need

| | |
|---|---|
| Computer | macOS or Linux with **Docker** (Docker Desktop, OrbStack or Docker Engine), 16 GB RAM recommended (8 GB minimum), ~25 GB free disk, `python3`, `curl`, `perl`, `openssl` |
| Planner | an **OpenRouter** API key (https://openrouter.ai/keys). Optional: without it, use the local-only agent |
| Worker model | one of: **Google Colab Pro** (default, nothing to install), a local GPU server (Ollama / LM Studio / llama.cpp / vLLM, ~24 GB VRAM for Qwen 27B), or any OpenAI-compatible endpoint |
| Optional | **Claude Code** (or another coding agent) + `uv` for the one-command Colab start |

---

## Quick start

```sh
git clone https://github.com/RiskVoid/Security-Agent-Kit.git
cd Security-Agent-Kit
./rvkit setup
```

`setup` checks your machine and asks four things (Enter accepts the default):

| Question | Default | Stored in `.env` as |
|---|---|---|
| Folder for client code and engagements | `~/riskvoid` | `PROJECTS_DIR=~/riskvoid/projects`, `ENGAGEMENTS_DIR=~/riskvoid/engagements` |
| Organisation name on reports | RiskVoid | `ORG_NAME`, `REPORT_BRAND` ([Branding](#branding)) |
| OpenRouter API key (hidden input) | skip | `OPENROUTER_API_KEY` |
| Worker model | colab | `WORKER_*` ([The worker model](#the-worker-model)) |

It then creates `.env` with fresh secrets, starts the containers (pulling published images, or building them,
~10 min the first time) and configures OpenHands. `./rvkit setup --yes` takes every default without asking.

Then:

```sh
./rvkit doctor        # checks everything and says what to fix
./rvkit quickstart    # practice engagement against a vulnerable app in the isolated lab, opens the UI
```

Open **http://localhost:8000/** and talk to the `riskvoid-planner` agent. A step-by-step first run against the
practice lab: [docs/first-engagement.md](docs/first-engagement.md). `./rvkit install` puts `rvkit` on your
PATH, and `./rvkit completion bash|zsh|fish` prints tab completion.

With Claude Code you can do all of this by typing `/rv-setup` and `/rv-start` in the kit folder.

| Agent | Model | Use |
|---|---|---|
| `riskvoid-planner` (default) | planner (OpenRouter) + the `colab-qwen` worker for tool work | best results |
| `riskvoid-local` | `private-llm`: your worker model only, never the fallback | nothing leaves your setup except web searches and CVE lookups |

`./rvkit up` re-applies the OpenHands configuration every time, so prompt and tool updates from `git pull` take
effect without manual steps. Your own extra profiles and MCP servers are left alone.

---

## The worker model

Switch any time; nothing else changes (`./rvkit worker` shows the current one):

| Option | Command |
|---|---|
| **Google Colab** (default): Qwen3.8-27B on an L4 / A100, started per session | `/rv-start` in Claude Code, or the notebook by hand (below) |
| **Local server** on this machine (Ollama, LM Studio, llama-server, vLLM) | `./rvkit worker local` (finds it on the usual ports), or `./rvkit worker local http://host.docker.internal:8080/v1 <model>` |
| **Fixed endpoint**: RunPod, Modal, your GPU server, any OpenAI-compatible API | `./rvkit worker api https://host/v1 <model-name> [api-key]` |

On Linux, a local server must listen on an address Docker containers can reach (Ollama: `OLLAMA_HOST=0.0.0.0`).

**Which model.** The Colab launcher serves the mainstream **Qwen3.8-27B** (Apache-2.0, Qwen's own weights,
`qwen38-27b`) by default. An **abliterated** community build with refusals removed is available as an option
(`/rv-start abliterated`, or `MODEL = "abliterated"` in the notebook; served as `qwen38-27b-obl`). It refuses
fewer offensive-security tasks, but it's a third-party modification: you're responsible for how you use it.

### Colab by hand

In Colab, **File → Upload notebook** → `colab/rvkit_model_server.ipynb`, then **File → Save a copy in Drive**.
Run `./rvkit key colab` and paste the result into the notebook's **API_KEY** field (it stays fixed).
Each session: **Runtime → Change runtime type → L4** (or A100), **Runtime → Run all**, approve the Google Drive
popup, and run the `./rvkit connect https://xxxx.trycloudflare.com/v1 rv-xxxx qwen38-27b` line it prints. It
should end with **"Model reachable"**. Stop with `/rv-stop` or **Runtime → Disconnect and delete runtime**; it also
stops itself after **30 idle minutes**. The first session takes ~25–30 min (one-time build, cached in your
Drive), later ones 3–6 min.

### When the worker isn't running: fallback model (off by default)

By default, worker calls fail while the worker endpoint is down (Colab stopped, tunnel expired): nothing is sent
anywhere else. If you turn the fallback on, those calls go to an OpenRouter model instead, by default
**DeepSeek V4.1 Flash** (cheap, uses tools well, doesn't refuse authorised pentest tasks in our tests; Kimi K2.6,
Qwen3 235B and Mistral Large 4 also passed). **That model then sees tool output and client code**, so only
zero-data-retention providers are used; check it against your client agreements before turning it on.

```sh
./rvkit worker show                                   # endpoint + fallback state
./rvkit worker fallback on                            # allow the fallback (DeepSeek V4.1 Flash)
./rvkit worker fallback moonshotai/kimi-k2.6          # allow it, with another OpenRouter model
./rvkit worker fallback off                           # back to the default
```

With the fallback on, you can still keep one client's data off cloud models: answer yes to "keep this client's
tool output on the worker endpoint only" in `./rvkit new` (or add `- Worker model: private` to `RULES.md`). The
`riskvoid-local` agent never uses the fallback either.

### Costs and limits

- **Planner models:** `./rvkit planner` shows them (default Claude Sonnet 5.5, GPT-6.1 as fallback);
  `./rvkit planner <openrouter-model> [fallback-model]` changes them.
- **Budget:** OpenRouter spend is capped per 24 hours (default **$20**): `./rvkit budget` shows the cap and what's
  spent, `./rvkit budget 50` changes it. Over the cap, OpenRouter calls are refused until the period ends. Spend
  is stored in the `redis` service, so restarting the stack doesn't reset it.
- To see what a run costs with your models, run a benchmark (`./rvkit bench smoke`): it reports the OpenRouter cost.
- Colab GPU costs: see [Which GPU?](#which-gpu-costs).

---

## Using it for client work

**1. Put the client's code** in `~/riskvoid/projects/<repo>` (your `PROJECTS_DIR`). The agent and tools see it,
read-only, as `/src/<repo>`.

**2. Create an engagement** with the authorised scope:

```sh
./rvkit new
```

It asks for the name, the client (shown on the report), the targets (hosts, domains, `*.example.com` for
subdomains, CIDRs, and client code as `/src/<repo>`), the allowed tiers, the rate limit, online/offline, and
whether to keep tool output off cloud models. It writes `SCOPE.md` and `RULES.md` and activates them. Without
questions: `./rvkit engagement acme-2026-11 --client "Acme Ltd" app.acme.com "*.acme.io" 203.0.113.0/28 /src/acme-repo`.

To change scope or rules later, edit the file and run `./rvkit scope acme-2026-11` (shows the diff; `--yes`
applies). Edits that aren't applied with `./rvkit scope` have no effect, so an agent can't widen its own scope.

**3. Start a conversation** with the `riskvoid-planner` agent at http://localhost:8000/:
> Engagement `acme-2026-11`: source code review of `/src/acme-repo`, including dependencies and secrets. Follow
> the matching playbooks, then write the executive summary and generate the report.

In another terminal, run **`./rvkit console`**: a local web page with your engagements, the approval queue,
findings triage, the report and the audit log ([docs/console.md](docs/console.md)). Or run **`./rvkit watch`**
to approve intrusive commands from the terminal, with a desktop notification for each.

The planner picks playbooks, copies their checklists into `PLAN.md`, works through them and records findings:

| Playbook | Standard | For |
|---|---|---|
| `code-review` | OWASP ASVS 5.0 | source code (SAST, Joern data flow, manual review) |
| `web-app` | OWASP WSTG 4.2 | web applications |
| `api-security` | OWASP API Security Top 10 2023 | REST and GraphQL APIs |
| `ai-llm` | OWASP Top 10 for LLM Apps 2025, MITRE ATLAS | chatbots, RAG, AI agents, MCP servers |
| `external-network` | PTES | internet-facing hosts and services |
| `supply-chain` | SLSA / OpenSSF | dependencies, SBOM, containers |
| `secrets-review` | | secrets in code and history |

**4. Report.** The planner writes `report/executive-summary.md` and calls `generate_report`, or you run
`./rvkit report acme-2026-11`. You get a branded `.docx`, a PDF and a findings register `.xlsx` in
`<engagement>/report/`. Every evidence file is listed with its SHA-256 and the audited command that produced it.
The report says **DRAFT** and lists what's missing until it's ready to send (summary written, candidates triaged,
evidence unchanged, client name set).

**5. Close out.** `./rvkit close acme-2026-11` writes a SHA-256 manifest of the engagement folder, archives it to
`<ENGAGEMENTS_DIR>/_archive/` with its own checksum, and halts the engagement.

`./rvkit status` shows everything on one screen: services, models, spend, engagements and pending approvals.
`./rvkit eng list` lists engagements with their scope.

### How scope is enforced

- Every Kali command runs as an unprivileged user for that engagement, in a sandbox that shows only its own
  engagement folder and its in-scope code (read-only).
- A firewall only lets that user reach in-scope IPs and domains, plus package and vulnerability-database sites
  on HTTPS for online engagements. Everything else, including the kit's own services, is blocked.
- Commands above the allowed tiers are refused; rate-limitable tools (nmap, nuclei, ffuf, httpx, …) get the max
  rate added. **Intrusive** commands wait for you (`./rvkit watch`, or `./rvkit approvals` and
  `./rvkit approve <eng> <id>`). Tiers are assigned by program name: scripts run at the passive tier and `curl` at the
  active tier, without approval ([SECURITY.md](SECURITY.md), known limitations).
- `./rvkit halt <eng>` kills everything running for an engagement and blocks new commands (`resume` to undo).
- Every command, refusal and approval is in the audit log: `./rvkit audit <eng>`.

### How the agent's own container is contained

- **No direct internet.** The OpenHands container sits on an internal Docker network. It reaches the models
  (LiteLLM) and the kit's MCP servers, and package registries and vulnerability databases through an allowlisting
  proxy (`egress/allowlist.txt`; add domains with `EGRESS_EXTRA_DOMAINS=a.com,b.org` in `.env`, then
  `./rvkit up`). The UI is served on `127.0.0.1:8000` by a small gateway.
- **Web research** goes through the `web` tool (private SearXNG search, and a page fetch that refuses every
  engagement target and non-public address).
- **Engagement files are read-only** for the agent. It writes `PLAN.md`, notes and the report text through the
  findings tool's `write_file` (a fixed list of paths). Evidence is only written by Kali commands, which hash it.

The same paths work everywhere: `/src/<repo>` for client code, `/work/<engagement>/` for engagement files.
`/workspace/project` is the agent's scratch space.

---

## Branding

Reports use the RiskVoid design by default. To use your own:

| `.env` | Result |
|---|---|
| `REPORT_BRAND=riskvoid` (default) | RiskVoid logo, colours and fonts |
| `REPORT_BRAND=plain` + `ORG_NAME=Your Company` | neutral design, no logo, your name |
| `REPORT_BRAND=custom` + `REPORT_BRAND_FOLDER=/path/to/brand` | your logo, colours and fonts: copy `harness/brands/example/` and see its README |

`ORG_NAME` also sets who the planner works for ("lead security consultant for …"). Run `./rvkit up` after
changing these. `./rvkit setup` sets `plain` with your name if you enter an organisation other than RiskVoid.

---

## Which GPU? (costs)

The launcher picks the right setup for whichever GPU you choose.

| GPU | Model quality | Speed | Compute units/hour* | Hours from 200 units |
|---|---|---|---|---|
| **L4** (recommended) | Q4, 32K context | ~15–20 tok/s | ~1.7 | ~115 |
| A100 40 GB | Q8 (near-full quality), 64K | ~35–50 tok/s | ~5.4 | ~37 |
| A100 80 GB | Q8, 128K | fast | ~7.5 | ~27 |

\*Community measurements (March 2026). Check Colab's usage meter during your first session.

Ways to save units: stop when you're done, keep thinking mode off (`/rv-start l4` rather than
`/rv-start l4 thinking`), and use the L4 by default.

---

## Practice lab and benchmarks

`./rvkit lab up` starts deliberately vulnerable targets on an isolated Docker network with no internet access
(`./rvkit quickstart` does this and creates a practice engagement for you):

| Target | Address | Practice |
|---|---|---|
| OWASP Juice Shop | `10.250.0.10:3000` | modern web app (WSTG) |
| DVWA | `10.250.0.11` | classic web vulnerabilities |
| VAmPI | `10.250.0.13:5000` | REST API (OWASP API Top 10), OpenAPI spec |
| DVGA | `10.250.0.14:5013/graphql` | GraphQL API |
| RiskVoid LLM lab | `10.250.0.15:8000` | AI assistant with tools + MCP server (OWASP LLM Top 10); simulated model, so results are reproducible and free |

Only engagements that have a lab host in scope can reach them. `./rvkit lab down` removes them (they reset).

Benchmarks run the real agent unattended on a known target and score it:

```sh
./rvkit bench smoke                        # 2-issue file, ~3 min, cents: does the whole loop work?
./rvkit bench code-flask                   # also: code-node, web-juice-shop, web-dvwa, api-vampi,
                                           # api-graphql-dvga, ai-llm-lab (lab), or all
./rvkit bench code-node --agent riskvoid-local
python3 evals/run_benchmark.py --history   # compare runs: recall, precision, cost, time, models, prompt version
```

Each run reports recall, severity-weighted recall, precision, OpenRouter cost and time, and saves the details to
`evals/results/bench/`.

---

## Commands

`./rvkit help` lists everything. The main ones:

```
setup [--yes]          first-time setup              doctor [--models]     check everything
up | down              start / stop the stack        status                one-screen overview
quickstart             practice engagement + UI      logs [service]        recent logs

new [name]             create an engagement          watch                 approve intrusive commands live
eng list               engagements + scope           scope <eng> [--yes]   apply SCOPE.md / RULES.md edits
approvals | approve | deny | halt | resume | audit | show | report | close <eng> …

connect <url> [key] [model]       Colab worker       worker [local|api|colab|fallback …]
planner [<model> [fallback]]      planner models     budget [usd]          OpenRouter cap and spend
test [planner]                    test prompt        key [colab|litellm|openhands]
lab up|down|status                practice targets   bench <name|all>      benchmarks
install [dir]                     rvkit on PATH      completion bash|zsh|fish
```

`./rvkit` runs under bash, so it works the same from bash, zsh and fish. Every engagement command also works as
`rvkit eng <command>`.

---

## Troubleshooting

Start with **`./rvkit doctor`**: it checks Docker, memory, disk, settings, every service, the MCP servers, the
sandbox firewall, the agent's network lockdown and the worker endpoint, and says what to fix. More symptoms and
an FAQ: [docs/troubleshooting.md](docs/troubleshooting.md).

| Problem | Fix |
|---|---|
| `port is already allocated` during setup | Another app uses port 8000, 4000 or 8888. Set `GATEWAY_PORT`, `LITELLM_PORT` or `SEARXNG_PORT` in `.env` and run `./rvkit up` ([docs/operations.md](docs/operations.md#ports)). |
| OpenHands doesn't start; its log says `Can't locate revision` | Its data volume was used by a newer OpenHands. Set `AGENT_CANVAS_TAG` in `.env` to that version, then `./rvkit up`. |
| The agent can't install a package or reach a site it needs | Its container has no direct internet. Add the domain to `EGRESS_EXTRA_DOMAINS` in `.env`, then `./rvkit up`. Engagement targets are reached with the kali tool, not from the agent's terminal. |
| OpenHands can't reach the model | `./rvkit status`. If the worker isn't reachable, the Colab session ended or the URL changed: start it again ([The worker model](#the-worker-model)). |
| Colab says "No GPU" or that the GPU is too small | Runtime → Change runtime type → L4 or A100, then run it again. A100s are sometimes unavailable. |
| Error 524 or timeouts on long answers | Cloudflare quick tunnels cut responses that take over ~100 s. Use ngrok instead: add Colab secrets `NGROK_TOKEN` (free account) and optionally `NGROK_DOMAIN` (a free static domain, so the URL never changes). |
| The agent chats but doesn't use tools | `./rvkit openhands` (it tests every tool server), then start a **new** conversation. |
| Planner calls fail with "crossed budget" | The daily OpenRouter budget is used up: `./rvkit budget <usd>` raises it. |
| Planner calls fail with "requires more credits" | Top up your OpenRouter balance. |
| The Kali tool says `REFUSED` | The target isn't in the engagement's active scope. Add it to `SCOPE.md`, then `./rvkit scope <eng>` to review and `--yes` to apply. Editing the file alone has no effect. |
| `/rv-start` can't find the Colab tools | Install uv (`brew install uv`), restart `claude` in the kit folder, and allow the `colab-mcp` server. The Colab MCP works with Claude Code and Gemini CLI, but not with Claude Desktop. |

---

## Where your data goes

| Part | Sees | Where it runs |
|---|---|---|
| Worker model (`colab-qwen`, `private-llm`) | tool output, client code, evidence | **Colab** (default): processed by Google on your Colab account. **Local / your own endpoint**: stays with you |
| Worker fallback (off by default) | the same as the worker, while the endpoint is down | OpenRouter, zero-data-retention providers only |
| Planner (`riskvoid-planner` agent) | task descriptions, the worker's redacted summaries, findings, files it chooses to open | OpenRouter, zero-data-retention providers only |
| Web search and page fetch (`web` tool) | search queries, public URLs | SearXNG's upstream engines; the public site |
| Vulnerability intel, package installs | CVE / package ids, package names | NVD, EPSS, CISA KEV, OSV; package registries (through the egress proxy) |
| Everything else (findings, evidence, audit log, reports) | everything | your machine |

For work where nothing may leave your machine, run the worker on a local or self-hosted endpoint
(`./rvkit worker local|api`), use the `riskvoid-local` agent, keep the fallback off, and choose `offline` in
`./rvkit new` if package and vulnerability-database lookups must not happen either. The secret redaction in
summaries is pattern-based: treat it as a safety net, not a guarantee.

## Privacy and terms

- **Client data:** see [Where your data goes](#where-your-data-goes), and check it against your client agreements.
- **Colab terms:** Colab restricts some uses of tunnels and proxies. The endpoint here is protected by an API key
  and meant only for your own use. Check the current terms for your plan.
- **Models:** Qwen3.8-27B is Apache-2.0. The optional abliterated build is a third-party modification with
  refusals removed; you're responsible for how you use it.
- **Your `.env`** holds your keys and is git-ignored. Never commit it. Everyone runs `./rvkit setup` to get their
  own secrets.

## Licence, security and contributing

- Licence: [Apache-2.0](LICENSE) ([NOTICE](NOTICE)). Third-party components and their licences, including what
  applies if you redistribute built images: [THIRD_PARTY.md](THIRD_PARTY.md).
- Security model, known limitations and how to report a vulnerability: [SECURITY.md](SECURITY.md).
- Development setup, tests and how to send changes: [CONTRIBUTING.md](CONTRIBUTING.md).

## What's inside

```
rvkit                     control script (./rvkit help)
docs/                     user documentation (start at docs/README.md)
docker-compose.yml        OpenHands, gateway, egress proxy, LiteLLM, SearXNG, MCP servers, Kali, lab
gateway/                  serves the UI on localhost:8000 (the agent container itself has no published port)
egress/                   allowlisting proxy for the agent container (allowlist.txt)
colab/serve.py            Colab launcher (GPU → profile, llama.cpp, model, tunnel, idle-off)
colab/rvkit_model_server.ipynb   notebook version (built from serve.py)
kali-mcp/                 Kali tools as an MCP server, with scope check, sandbox and audit log
kali-mcp/aitools/rv-llm   LLM / agent / MCP testing tool (probe library, MCP audit, injection payloads)
harness/                  MCP servers: worker (delegate_task), findings (findings, playbooks, files, report),
                          intel (OSV / NVD / EPSS / CISA KEV), web (search + fetch)
harness/playbooks/        methodology playbooks
harness/brands/example/   template for your own report brand
prompts/                  planner and local-agent instructions
litellm/config.yaml       model routing (template: ./rvkit renders it with your .env settings into .rvkit/)
scripts/                  OpenHands configuration, LiteLLM rendering
evals/                    tests (policy, tools, report e2e, lab isolation), benchmarks + targets, runner
.github/workflows/        CI (lint + integration tests) and image publishing
.mcp.json, .claude/       Claude Code automation (/rv-setup, /rv-start, /rv-stop)
AGENT_PLAYBOOK.md         step-by-step procedure a coding agent follows
IMPLEMENTATION_PLAN.md    roadmap, phase by phase
```
