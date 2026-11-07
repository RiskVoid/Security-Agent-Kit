# RiskVoid agent kit

A self-hosted AI security assistant for **authorised** security work: source code review, dependency and secrets
review, web application, API (REST/GraphQL), AI application / agent / MCP and external network testing, with evidence and a client-ready report. Open source,
from [RiskVoid](https://riskvoid.com).

- **Planner + worker.** A frontier model (via OpenRouter) plans, triages and writes up; a local, uncensored
  Qwen model does the hands-on tool work, so raw tool output and client code stay on hardware you control.
  Or run everything on the local model.
- **Real tools, safely.** 45+ tools (nmap, nuclei, ZAP, sqlmap, schemathesis, jwt_tool, garak, semgrep, Joern, trivy, …) behind a per-engagement
  sandbox: network firewall limited to the authorised scope, intensity tiers, human approval for intrusive steps,
  emergency halt, and an audit log.
- **Method and evidence.** Playbooks (OWASP ASVS / WSTG / API Top 10 / LLM Top 10, PTES, supply chain, secrets), a findings database,
  vulnerability intel (CISA KEV, EPSS, NVD, OSV), SHA-256-verified evidence, and a branded `.docx` / PDF report.
- **Pre-configured.** `./rvkit setup` builds the stack and configures the OpenHands agent UI: models, tools and
  agents are ready on first launch.

```
YOUR COMPUTER (Docker)                                                 WORKER MODEL (pick one)
┌───────────────────────────────────────────────────────────────┐     ┌──────────────────────────────┐
│ OpenHands UI ─► LiteLLM ─► planner ── OpenRouter (frontier)   │     │ Google Colab GPU (default)   │
│   agent           │                                           │     │ your own GPU / LM Studio     │
│   │               └──────► worker ────────────────────────────┼────►│ any OpenAI-compatible URL    │
│   ├─► kali     sandboxed tools, scope firewall, audit log     │     └──────────────────────────────┘
│   ├─► worker   delegates tool work to the worker model        │
│   ├─► findings findings DB, playbooks, branded report         │
│   ├─► intel    CVE/GHSA: KEV, EPSS, NVD, OSV                   │
│   └─► search / fetch  private web search (SearXNG)            │
│ lab (optional): vulnerable practice targets, isolated network │
└───────────────────────────────────────────────────────────────┘
```

> Use it only on systems you own or have written permission to test.

---

## What you need

| | |
|---|---|
| Computer | macOS or Linux with **Docker** (Docker Desktop or OrbStack), 16 GB RAM recommended, ~25 GB free disk, `python3` |
| Planner | an **OpenRouter** API key (https://openrouter.ai/keys). Optional: without it, use the local-only agent |
| Worker model | one of: **Google Colab Pro** (default, nothing to install), a local GPU server (llama.cpp / LM Studio / Ollama / vLLM, ~24 GB VRAM for Qwen 27B), or any OpenAI-compatible endpoint |
| Optional | **Claude Code** (or another coding agent) + `uv` for the one-command Colab start |

---

## Setup (~15 min, once)

```sh
git clone https://github.com/riskvoid/riskvoid-agent-kit.git
cd riskvoid-agent-kit
./rvkit setup
```

`setup` creates `.env` with fresh secrets, builds the containers (~10 min the first time), starts them, and
configures OpenHands: LLM profiles `planner` and `colab-qwen`, the six MCP tool servers, and two agents:

| Agent | Model | Use |
|---|---|---|
| `riskvoid-planner` (default) | planner (OpenRouter) + the `colab-qwen` worker for tool work | best results |
| `riskvoid-local` | `private-llm`: your worker model only, never the fallback | nothing leaves your setup except web searches and CVE lookups |

LLM profiles in OpenHands: `planner` (frontier model via OpenRouter), `colab-qwen` (the abliterated Qwen served
from Colab by default, or your own endpoint via `./rvkit worker`, falling back to an OpenRouter model while it's
down) and `private-llm` (the same worker endpoint with the fallback disabled — nothing leaves it, so it fails
closed instead; for confidential work, point the worker at a local or self-hosted endpoint).

Then:
1. Add your OpenRouter key to `.env` (`OPENROUTER_API_KEY=...`) and run `./rvkit up`. Check: `./rvkit test planner`.
2. Connect a worker model (next section). Check: `./rvkit test`.
3. Open **http://localhost:8000/canvas** and start a conversation with the `riskvoid-planner` agent.

With Claude Code you can do all of this by typing `/rv-setup` and `/rv-start` in the kit folder.

`./rvkit up` re-applies the OpenHands configuration every time, so prompt and tool updates from `git pull` take
effect without manual steps. Your own extra profiles and MCP servers are left alone.

---

## The worker model

Switch any time; nothing else changes (`./rvkit worker` shows the current one):

| Option | Command |
|---|---|
| **Google Colab** (default): Qwen3.8-27B on an L4 / A100, started per session | `/rv-start` in Claude Code, or the notebook by hand (below), then `./rvkit connect <url>` |
| **Local server** on this machine (llama-server, LM Studio, Ollama, vLLM) | `./rvkit worker local http://host.docker.internal:8080/v1 <model-name>` |
| **Fixed endpoint**: RunPod, Modal, your GPU server, any OpenAI-compatible API | `./rvkit worker api https://host/v1 <model-name> [api-key]` |

### Colab by hand

In Colab, **File → Upload notebook** → `colab/rvkit_model_server.ipynb`, then **File → Save a copy in Drive**.
Run `./rvkit key colab` and paste the result into the notebook's **API_KEY** field (it stays fixed).
Each session: **Runtime → Change runtime type → L4** (or A100), **Runtime → Run all**, approve the Google Drive
popup, and run the `./rvkit connect https://xxxx.trycloudflare.com/v1 rv-xxxx` line it prints. It should end with
**"Model reachable"**. Stop with `/rv-stop` or **Runtime → Disconnect and delete runtime**; it also stops itself
after **30 idle minutes**. The first session takes ~25–30 min (one-time build, cached in your Drive), later ones
3–6 min.

### When Colab isn't running: fallback model

While the worker endpoint is down (Colab stopped, tunnel expired), worker calls go to a less restrictive
OpenRouter model, by default **DeepSeek V4.1 Flash** (cheap, uses tools well, doesn't refuse authorised pentest
tasks in our tests; Kimi K2.6, Qwen3 235B and Mistral Large 4 also passed). Only zero-data-retention providers
are used, because the worker sees tool output and client code. As soon as the endpoint is back, calls go there
again. Delegated task results show which model did the work.

```sh
./rvkit worker show                                   # endpoint + fallback
./rvkit worker fallback moonshotai/kimi-k2.6          # another OpenRouter model
./rvkit worker fallback off                           # never fall back: worker calls fail while Colab is down
```

For a client whose data must not reach any cloud model, add `- Worker model: private` to that engagement's
`RULES.md` (then `./rvkit scope <eng>`): its delegated tasks never use the fallback. The `riskvoid-local` agent
never does either.

### Costs and limits

- **Planner budget:** OpenRouter spend is capped per day (default **$20**): `./rvkit budget` to see,
  `./rvkit budget 50` to change. Over the cap, planner calls are refused until the next day (the call that crosses
  it still completes). The counter resets when LiteLLM restarts.
- Each planner call can produce at most 16k tokens. To see what a run costs with your models, run a benchmark
  (`./rvkit bench smoke`): it reports the OpenRouter cost.
- Colab GPU costs: see [Which GPU?](#which-gpu-costs).

---

## Using it for client work

**1. Put the client's code** in `~/projects/<repo>`.

**2. Create an engagement** with the authorised scope (hosts, domains, CIDRs, and the client code under `/src`):
```sh
./rvkit engagement acme-2026-11 app.acme.com "*.acme.io" 203.0.113.0/28 /src/acme-repo
```
This writes `SCOPE.md` and a default `RULES.md` (tiers passive + active, max 100 req/s, online) and activates
them. To change either, edit the file and run `./rvkit scope acme-2026-11` (shows the diff; `--yes` applies).
Edits that aren't applied with `./rvkit scope` have no effect, so an agent can't widen its own scope.

How scope is enforced:
- Every Kali command runs as an unprivileged user for that engagement, in a sandbox that shows only its own
  engagement folder and its in-scope code (read-only).
- A firewall only lets that user reach in-scope IPs and domains, plus package and vulnerability-database sites
  on HTTPS for online engagements. Everything else, including the kit's own services, is blocked.
- Commands above the allowed tiers are refused; rate-limitable tools (nmap, nuclei, ffuf, httpx, …) get the max
  rate added. **Intrusive** commands wait for you: `./rvkit approvals <eng>`, then `./rvkit approve <eng> <id>`.
- `./rvkit halt <eng>` kills everything running for an engagement and blocks new commands (`resume` to undo).
- Every command, refusal and approval is in the audit log: `./rvkit audit <eng>`. The authoritative copy lives in
  the control volume; `~/projects/engagements/audit.log` is a convenience mirror.

Only test systems you have written authorisation for. The OpenHands agent's own terminal and browser are not
behind this firewall (see `IMPLEMENTATION_PLAN.md`, Phase 3 known gaps).

**3. Start a conversation** with the `riskvoid-planner` agent, like this:
> Engagement `acme-2026-11`: source code review of `/src/acme-repo`, including dependencies and secrets. Follow
> the matching playbooks, then write the executive summary and generate the report.

The planner picks playbooks (`list_playbooks`), copies their checklists into `PLAN.md`, works through them and
records findings:

| Playbook | Standard | For |
|---|---|---|
| `code-review` | OWASP ASVS 4.0.3 | source code (SAST, Joern data flow, manual review) |
| `web-app` | OWASP WSTG 4.2 | web applications |
| `api-security` | OWASP API Security Top 10 2023 | REST and GraphQL APIs |
| `ai-llm` | OWASP Top 10 for LLM Apps 2025, MITRE ATLAS | chatbots, RAG, AI agents, MCP servers |
| `external-network` | PTES | internet-facing hosts and services |
| `supply-chain` | SLSA / OpenSSF | dependencies, SBOM, containers |
| `secrets-review` | | secrets in code and history |

**4. Report.** Put the client name in `<engagement>/report/meta.txt`. The planner writes
`report/executive-summary.md` and calls `generate_report`, or you run `./rvkit report acme-2026-11`. You get a
RiskVoid-branded `.docx`, a PDF and a findings register `.xlsx` in `<engagement>/report/`. Every evidence file is
listed with its SHA-256 and the audited command that produced it. The report says **DRAFT** and lists what's
missing until it's ready to send (summary written, candidates triaged, evidence unchanged, client name set).
For the PDF to look right in Word or Google Docs, install Space Grotesk, Inter Tight and JetBrains Mono.

**5. Close out.** `./rvkit close acme-2026-11` writes a SHA-256 manifest of the engagement folder, archives it to
`~/projects/engagements/_archive/` with its own checksum, and halts the engagement.

**Planner and worker.** With the `riskvoid-planner` agent, the planner (OpenRouter) plans and reviews, and hands
hands-on tool work to the worker (`delegate_task`), which runs on the local Qwen model. The worker records
*candidate* findings; the planner verifies them and marks them `confirmed` or `false-positive` in the findings
store (`/work/<engagement>/findings.db`). Raw tool output stays in `evidence/tasks/<task_id>/`, and secrets are
redacted from what goes back to the planner. Only summaries reach OpenRouter.

How each part sees the files:

| | OpenHands | Kali / worker / findings tools |
|---|---|---|
| Your code | `/projects/<repo>` | `/src/<repo>` (read-only) |
| Engagement | `/projects/engagements/<engagement>/` | `/work/<engagement>/` |

---

## Which GPU? (costs)

The launcher picks the right setup for whichever GPU you choose.

| GPU | Model quality | Speed | Compute units/hour* | Hours from 200 units |
|---|---|---|---|---|
| **L4** (recommended) | Q4, 32K context | ~15–20 tok/s | ~1.7 | ~115 |
| A100 40 GB | Q8 (near-full quality), 64K | ~35–50 tok/s | ~5.4 | ~37 |
| A100 80 GB | Q8, 128K | fast | ~7.5 | ~27 |

\*Community measurements (March 2026). Check Colab's usage meter during your first session.

Ways to save units: stop when you're done, keep thinking mode off (`/rv-start l4` rather than `/rv-start l4 thinking`), and use the L4 by default.

---

## Practice lab and benchmarks

`./rvkit lab up` starts deliberately vulnerable targets on an isolated Docker network with no internet access:

| Target | Address | Practice |
|---|---|---|
| OWASP Juice Shop | `10.250.0.10:3000` | modern web app (WSTG) |
| DVWA | `10.250.0.11` | classic web vulnerabilities |
| VAmPI | `10.250.0.13:5000` | REST API (OWASP API Top 10), OpenAPI spec |
| DVGA | `10.250.0.14:5013/graphql` | GraphQL API |
| RiskVoid LLM lab | `10.250.0.15:8000` | AI assistant with tools + MCP server (OWASP LLM Top 10); simulated model, so results are reproducible and free |

 Only engagements that have a lab host in
scope can reach them: `./rvkit engagement lab-juice 10.250.0.10`. `./rvkit lab down` removes them (they reset).

Benchmarks run the real agent unattended on a known target and score it:

```sh
./rvkit bench smoke                        # 2-issue file, ~3 min, cents: does the whole loop work?
./rvkit bench code-flask                   # also: code-node, web-juice-shop, web-dvwa, api-vampi,
                                           # api-graphql-dvga, ai-llm-lab (lab), or all
./rvkit bench code-node --agent riskvoid-local
python3 evals/run_benchmark.py --history   # compare runs: recall, precision, cost, time, models, prompt version
```

Each run reports recall (expected issues found), severity-weighted recall, precision, OpenRouter cost and time,
and saves the details to `evals/results/bench/`. Run one after changing the prompt, the playbooks or a model.
The benchmark definitions and targets are in `evals/benchmarks/` and `evals/targets/`.

---

## Commands

```
./rvkit setup                 first-time setup (also configures OpenHands)
./rvkit up | down             start / stop the local stack
./rvkit status                containers + model check
./rvkit connect <url> [key]   point the worker at a running Colab model
./rvkit worker [colab | local [url] [model] | api <url> <model> [key]]   switch the worker endpoint
./rvkit worker fallback [on | off | <openrouter-model>]   model used while the endpoint is down
./rvkit test [planner]        send a test prompt
./rvkit budget [usd]          daily OpenRouter budget
./rvkit key [colab|litellm|openhands]   print a key
./rvkit openhands             re-apply the OpenHands configuration
./rvkit engagement <name> <targets…>
./rvkit scope | show | approvals | approve | deny | halt | resume | audit <eng> …
./rvkit report <eng>          branded report (.docx, .pdf, .xlsx)
./rvkit close <eng>           manifest + archive + halt
./rvkit lab up | down | status
./rvkit bench <name|all> [--agent riskvoid-local]
./rvkit logs [service]        e.g. ./rvkit logs litellm
```

`./rvkit` runs under bash, so it works the same from bash, zsh and fish.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `port is already allocated` during setup | Another app uses that port. In `docker-compose.yml`, change the left number of that service's `ports:` line (e.g. `"127.0.0.1:8001:8000"`). |
| OpenHands can't reach the model | Run `./rvkit status`. If the model isn't reachable, the Colab session ended or the URL changed. Start it again (Part 2). |
| Colab says "No GPU" or that the GPU is too small | Go to Runtime → Change runtime type → L4 or A100, then run it again. A100s are sometimes unavailable. |
| Error 524 or timeouts on long answers | Cloudflare quick tunnels cut responses that take over ~100 s. Use ngrok instead: add Colab secrets `NGROK_TOKEN` (free account) and optionally `NGROK_DOMAIN` (a free static domain, so the URL never changes). |
| The agent chats but doesn't use tools | Run `./rvkit openhands` (it tests every tool server), then start a **new** conversation. |
| Planner calls fail with "crossed budget" | The daily OpenRouter budget is used up: `./rvkit budget <usd>` raises it. |
| Planner calls fail with "requires more credits" | Top up your OpenRouter balance. |
| An MCP server test fails | `./rvkit logs mcp-gateway` / `./rvkit logs kali-mcp` |
| The Kali tool says `REFUSED` | The target isn't in that engagement's `SCOPE.md`. Edit the file; no restart needed. |
| `/rv-start` can't find the Colab tools | Install uv (`brew install uv`), restart `claude` in the kit folder, and allow the `colab-mcp` server. The Colab MCP works with Claude Code and Gemini CLI, but not with Claude Desktop. |

---

## Privacy and terms

- **Client data:** the worker model sees tool output and client code: on Colab, that is processed by Google; with a local or your own endpoint, it stays with you. The planner (OpenRouter) gets task descriptions and redacted summaries, routed only to zero-data-retention providers. Check this against your client agreements.
- **Colab terms:** Colab restricts some uses of tunnels and proxies. The endpoint here is protected by an API key and meant only for your own use. Check the current terms for your plan.
- **Model:** the default model is an *abliterated* (refusal-removed) community build of Qwen3.8-27B (Apache-2.0). You're responsible for how you use it.
- **Your `.env`** holds your keys and is git-ignored. Never commit it. Everyone runs `./rvkit setup` to get their own secrets.

## What's inside

```
rvkit                     control script
docker-compose.yml        OpenHands, LiteLLM, SearXNG, MCP gateway, Kali MCP, worker, findings, intel, lab
colab/serve.py            Colab launcher (GPU → profile, llama.cpp, model, tunnel, idle-off)
colab/rvkit_model_server.ipynb   notebook version (built from serve.py)
kali-mcp/                 Kali tools as an MCP server, with scope check and audit log
harness/                  worker MCP (delegate_task on Qwen), findings MCP (findings, playbooks, report),
                          intel MCP (OSV / NVD / EPSS / CISA KEV); brand/ = vendored RiskVoid doc toolkit
harness/playbooks/        methodology playbooks (ASVS, WSTG, API Top 10, LLM Top 10, PTES, supply chain, secrets)
kali-mcp/aitools/rv-llm   LLM / agent / MCP testing tool (probe library, MCP audit, injection payloads)
prompts/planner.md        planner agent instructions
evals/                    tests (policy, tools, report e2e, lab isolation), benchmarks + targets, runner
scripts/openhands_config.py   configures OpenHands through its API (run by setup / up / ./rvkit openhands)
prompts/local.md          extra instructions for the local-only agent
IMPLEMENTATION_PLAN.md    harness roadmap, phase by phase
mcp-gateway/              web search + fetch MCP servers
litellm/config.yaml       model routing
.mcp.json, .claude/       Claude Code automation (/rv-setup, /rv-start, /rv-stop)
AGENT_PLAYBOOK.md         step-by-step procedure the agent follows
```
