# Architecture and design

This page explains how the kit is put together: the containers and networks, how one task flows from your prompt
to a finished report, where the trust boundaries are, and why it's built this way. For the known gaps in these
controls and what counts as a security bug, see [SECURITY.md](../SECURITY.md).

## The big picture

The kit is a Docker Compose stack on your machine, plus a worker model that runs wherever you choose (a Colab
GPU, a local server or any OpenAI-compatible endpoint).

- **OpenHands** (the `agent-canvas` container) is the agent runtime and web UI. It runs the planner agent.
- **LiteLLM** is the single model gateway. Every model call, from OpenHands and from the worker, goes through it.
- **MCP servers** are the agent's tools: `kali` (sandboxed security tools), `worker` (delegation to the worker
  model), `findings` (findings, playbooks, file writes, reports), `intel` (vulnerability intelligence) and `web`
  (search and page fetch).
- **The host folders** `PROJECTS_DIR` and `ENGAGEMENTS_DIR` hold client code and engagement files. They are
  mounted into the containers as `/src` and `/work`, so a path means the same thing everywhere.

```
 browser ── 127.0.0.1:8000 ──► gateway
                                  │
 ┌─ rvagent: internal network, no internet, no host ─────────────────────────────────────┐
 │                                ▼                                                       │
 │                     agent-canvas (OpenHands)                                          │
 │         HTTP(S) proxy │          │ model calls          │ MCP tool calls              │
 │                       ▼          ▼                      ▼                             │
 │              egress-proxy     litellm     web-mcp  kali-mcp  worker-mcp  findings-mcp  intel-mcp
 └───────────────────┼──────────────┼──────────┼─────────┼─────────┼───────────────────────┼──────┘
                     │              │          │         │   (internal only:       │
                     │              │          │         │    litellm, kali-mcp,     │
                     │              │          │         │    web-mcp, intel-mcp)    │
 default network ────┼──────────────┼──────────┼─────────┼─────────────────────────────────┼──────
 (has internet)      ▼              ▼          ▼         │                                 ▼
            allowlisted       OpenRouter     searxng,    │                            OSV, NVD,
            registries and    worker endpoint public     │                            EPSS, KEV
            vuln databases    (redis: spend)  pages      │
                                                         ▼
                                        Kali sandbox (per-engagement firewall)
                                 ┌───────────────────────┼─────────────────────────┐
                                 ▼                       ▼                         ▼
                          in-scope targets     rvlab 10.250.0.0/24        package / vuln-db sites
                                               practice targets,          on 80/443 (online
                                               only if in scope           engagements only)
```

`./rvkit` on your machine reaches the control plane with `docker compose exec kali-mcp …`, and LiteLLM on
`127.0.0.1:4000`.

## Components

| Service | Image | Role | Networks and host ports | Volumes and folders |
|---|---|---|---|---|
| `agent-canvas` | `ghcr.io/openhands/agent-canvas` (pinned, `AGENT_CANVAS_TAG`) | OpenHands: agent runtime, UI, conversations. Runs the `riskvoid-planner` and `riskvoid-local` agents | `rvagent` only. No published port | `openhands-data`; `/src` and `/work` **read-only** |
| `gateway` | `caddy` (pinned) | Publishes the UI on `127.0.0.1:8000`, proxies to OpenHands (websockets included), serves the start page at `/` | `default`, `rvagent`; **127.0.0.1:8000** | `gateway/Caddyfile`, `gateway/start.html` |
| `egress-proxy` | kit image `-egress` (tinyproxy) | The agent container's only way out: allowlisted domains, deny by default | `default`, `rvagent` | built from `egress/` |
| `litellm` | `ghcr.io/berriai/litellm` (pinned) | Model gateway: `planner`, `planner-fallback`, `colab-qwen`, `private-llm`, `colab-qwen-fallback`; daily OpenRouter budget | `default`, `rvagent`; **127.0.0.1:4000** | `.rvkit/litellm.yaml` (rendered), `.env` |
| `redis` | `valkey/valkey` (pinned) | Stores LiteLLM's OpenRouter spend so the budget survives restarts | `default` | `litellm-spend` |
| `searxng` | `searxng/searxng` (pinned) | Private metasearch for web research | `default`; **127.0.0.1:8888** | `searxng/settings.yml` |
| `web-mcp` | kit image `-harness` | `web_search` and `fetch` for the planner; fetch refuses engagement targets and non-public addresses | `default`, `rvagent` | none |
| `kali-mcp` | kit image `-kali` | Kali toolbox as MCP; per-engagement scope firewall, sandbox, tiers, approvals, audit log | `default`, `rvagent`, `rvlab` (10.250.0.2) | `/work` (read-write), `/src` (read-only), `kali-control`, `semgrep-rules` |
| `worker-mcp` | kit image `-harness` | `delegate_task`: runs a tool-calling loop on the worker model; search and fetch go through `web-mcp` | `rvagent` only (no internet) | `/work` (read-write), `/src` (read-only) |
| `findings-mcp` | kit image `-report` | Findings database, playbooks, `write_file`, branded report (python-docx, LibreOffice) | `default`, `rvagent` | `/work` (read-write), your brand folder at `/brand-custom` (read-only) |
| `intel-mcp` | kit image `-harness` | OSV, NVD, EPSS and CISA KEV lookups, cached | `default`, `rvagent` | `intel-cache` |
| `lab-*` (profile `lab`) | Juice Shop, DVWA + MariaDB, VAmPI, DVGA, `riskvoid-lab-llm` | Deliberately vulnerable practice targets | `rvlab` only | none |

Kit images are published as `ghcr.io/riskvoid/security-agent-kit-{egress,harness,kali,report}:<VERSION>`
(`RVKIT_REGISTRY` and `RVKIT_VERSION` override them). See [Design decisions](#design-decisions).

### Networks

| Network | Type | Members | Purpose |
|---|---|---|---|
| `default` | normal bridge, has internet | every service except `agent-canvas`, `worker-mcp` and the lab | the kit's services talk to each other and to model providers, SearXNG engines and vulnerability databases |
| `rvagent` | `internal: true` | `agent-canvas`, `gateway`, `egress-proxy`, `litellm` and the five MCP servers | everything OpenHands and the worker are allowed to talk to. No route to the internet or the host |
| `rvlab` | `internal: true`, `10.250.0.0/24` | `kali-mcp` (10.250.0.2) and the lab targets | practice targets. No internet, no host, and no other kit service |

### Host ports

All published ports bind to `127.0.0.1` only:

| Port | Service | Use |
|---|---|---|
| 8000 | `gateway` | the UI: http://localhost:8000/ |
| 4000 | `litellm` | used by `./rvkit` (`test`, `budget`, `status`, `doctor`) |
| 8888 | `searxng` | the search engine, if you want to use it yourself |

### Volumes and folders

| Name | Mounted in | Holds |
|---|---|---|
| `PROJECTS_DIR` (host folder) | `/src`, read-only in every container | client code, one folder per repository |
| `ENGAGEMENTS_DIR` (host folder) | `/work`: read-only in `agent-canvas`, read-write in `kali-mcp`, `worker-mcp`, `findings-mcp` | one folder per engagement, plus `audit.log` (a convenience copy) and `_archive/` |
| `openhands-data` | `agent-canvas` | conversations, LLM profiles, agent profiles, MCP settings |
| `kali-control` | `kali-mcp` at `/control` (root-only) | the authoritative scope, rules, approvals, halt flags, engagement registry and audit log |
| `litellm-spend` | `redis` | OpenRouter spend counter |
| `intel-cache` | `intel-mcp` | vulnerability lookups (24 h; KEV feed 12 h) |
| `semgrep-rules` | `kali-mcp` at `/opt/semgrep-rules` | Semgrep community rules, downloaded on first start |

## How one task flows

What happens between "Engagement `acme`: review `/src/acme`…" and a finished report:

1. **Prompt.** You start a conversation with the `riskvoid-planner` agent. OpenHands sends the conversation,
   with the system prompt from `prompts/planner.md`, to LiteLLM as model `planner`. LiteLLM forwards it to
   OpenRouter (zero-data-retention providers only), and retries once on `planner-fallback` if that fails.
2. **Scope check.** The planner calls the kali tool `list_engagements` / `engagement_info` to read the active
   scope and rules, then `list_playbooks` and `get_playbook` on the findings server, and writes `PLAN.md` with
   `write_file`.
3. **Delegation.** For hands-on work it calls the worker's `delegate_task` with one focused goal, the engagement
   and a tier. `worker-mcp` asks `kali-mcp` for the authoritative scope and rules, refuses if the engagement is
   halted or the tier isn't allowed, and starts a tool-calling loop on the worker model through LiteLLM: model
   `colab-qwen`, or `private-llm` when `RULES.md` says `Worker model: private`. Tasks run one at a time.
4. **Tool call.** The worker model calls `kali_run`, which calls the kali tool `run` (the planner can also call
   `run` directly). `kali-mcp` then:
   1. refuses if the engagement is halted or outside its testing window;
   2. classifies the command's **tier** from the programs it runs and refuses it if `RULES.md` doesn't allow it;
   3. **prechecks** the hosts named in network-tool commands against the scope, for a readable early refusal;
   4. for an **intrusive** command without an approval, records a pending approval and returns
      `APPROVAL REQUIRED` with its id. After you approve it on the host, the same command with that
      `approval_id` runs once;
   5. adds or caps the **rate** flag of rate-limitable tools at the engagement's max rate;
   6. runs the command with `unshare` (new mount and pid namespace) and `rv-sandbox.sh`, as the engagement's own
      unprivileged user. The sandbox shows only `/work/<engagement>/` and the in-scope `/src` paths (read-only),
      with `SCOPE.md` and `RULES.md` replaced by the authoritative copies;
   7. the **nftables** chain for that user allows only in-scope addresses, names resolved by that engagement's
      **dnsmasq**, and (online engagements) package and vulnerability-database sites on TCP 80/443;
   8. after the command, every file it created or changed in the engagement folder is **SHA-256 hashed** and
      written to the audit log with the command, tier, exit code and duration.
5. **Candidates.** The worker records candidate findings in the engagement's `findings.db` with
   `record_candidate`, writes each step's full output to `/work/<engagement>/evidence/tasks/<task_id>/`, and
   calls `finish`.
6. **Summary back.** `delegate_task` returns a short structured result: commands run, candidate ids, the
   worker's summary and the evidence folder. Secrets are **redacted** from it. Raw tool output and client code
   stay with the worker model.
7. **Verification.** The planner reads what it needs, verifies each candidate (reproduces it, reads the code,
   checks versions with the `intel` tools) and marks it `confirmed` or `false-positive` with `update_finding`.
8. **Write-up.** It writes `report/executive-summary.md` (and optionally `methodology.md`, `conclusion.md`) with
   `write_file`, then calls `generate_report`.
9. **Report.** `findings-mcp` asks `kali-mcp` for `engagement_info`, `engagement_activity` (the methodology
   numbers) and `evidence_provenance` (each evidence file's current hash and the audited command that produced
   exactly that content). It builds the `.docx`, converts it to PDF with LibreOffice and writes the findings
   register `.xlsx`. Anything that blocks delivery keeps the report a DRAFT.

The `riskvoid-local` agent follows the same path without step 3: it runs on `private-llm` and calls the kali tool
itself. More on the agents and models: [running-the-agent.md](running-the-agent.md) and [models.md](models.md).

## Trust boundaries and controls

### Control plane and agent-visible files

| Where | Who can change it | What it holds |
|---|---|---|
| `/control` (volume `kali-control`, root-only in `kali-mcp`) | only `rvctl.py`, which only `./rvkit` runs (`docker compose exec`) | the active `SCOPE.md` / `RULES.md` per engagement, approvals, `HALT` flags, the engagement registry (name → uid), the authoritative `audit.log`, optional `infra_domains.txt` override |
| `/work/<engagement>/` (host folder) | you; kali commands; the worker; `findings-mcp` (`write_file`, findings, reports) | the files you edit (`SCOPE.md`, `RULES.md`), plan, notes, evidence, findings database, report |

`SCOPE.md` and `RULES.md` in the engagement folder are what you edit. They take effect only when you run
`./rvkit scope <engagement> --yes`, which copies them into `/control` and rebuilds the firewall. So an agent that
edits them changes nothing. Inside the sandbox, the files are replaced by the read-only active copies. See
[engagements.md](engagements.md).

### The Kali sandbox

- **One user per engagement.** Each registered engagement gets a uid from 20001 upwards (at most 250). Commands
  run as that user through `setpriv` with no supplementary groups, `no_new_privs`, and only `CAP_NET_RAW` (for
  nmap).
- **Own mount and pid namespace per command.** `/work` and `/src` are replaced by tmpfs with only the
  engagement's folder and its in-scope code paths bound in (code read-only). `/control`, `/tmp` and `/run` are
  empty tmpfs. Other engagements and other code don't exist inside the sandbox.
- **Firewall by uid.** An nftables table `inet rvkit` sends each engagement user's traffic to its own chain:
  - always dropped: `127.0.0.0/8`, `169.254.0.0/16` (link-local, cloud metadata), `0.0.0.0/8`, `224.0.0.0/4`, and
    every Docker subnet `kali-mcp` is on except the lab, so the kit's own services are unreachable;
  - allowed: the scope's IPv4 networks; addresses that dnsmasq resolved for in-scope domains; for online
    engagements, addresses resolved for the infrastructure domains (`kali-mcp/infra_domains.txt`) on TCP 80/443;
  - all IPv6 is dropped; everything else is dropped.
- **DNS by engagement.** Each engagement user's DNS is redirected to its own dnsmasq, which resolves only
  in-scope domains (and their subdomains) and, for online engagements, the infrastructure domains. It refuses
  every other name and adds the addresses it returns to the engagement's allowed set.
- **The `kali-mcp` container itself** needs `NET_ADMIN`, `SYS_ADMIN` and no AppArmor profile to build this
  sandbox. An escape to its root would be serious: that's in scope for security reports.

The firewall is the hard boundary. Tiers, rate caps and the host precheck are guardrails against mistakes: a
script (passive tier) or `curl` (active tier) can still send intrusive traffic to in-scope hosts.

### The agent's own container

- **No direct internet.** `agent-canvas` is only on the internal `rvagent` network. Its HTTP(S) traffic goes to
  `egress-proxy`, which allows only the domains in `egress/allowlist.txt` plus `EGRESS_EXTRA_DOMAINS` (each with
  its subdomains; HTTPS only to port 443) and refuses everything else, including engagement targets.
- **Read-only engagement files.** `/src` and `/work` are mounted read-only. The planner writes only through the
  findings server: `write_file` accepts a fixed list of paths (`PLAN.md`, `NOTES.md`, `notes/<name>.md|.txt`,
  `report/executive-summary.md`, `report/methodology.md`, `report/conclusion.md`, `report/meta.txt`). Evidence is
  written only by kali commands, findings only through the findings tools.
- **Web research through `web-mcp`.** `fetch` resolves the host and refuses it if it is in any engagement's
  scope (the union of all of them, from `kali-mcp`'s `all_scopes`) or resolves to a non-public address. It checks
  again on every redirect. If it can't read the scopes, it refuses (fails closed).

### Secrets

- The **OpenRouter key** is only in the `litellm` container (`env_file: .env`). OpenHands, the worker and the
  MCP servers call LiteLLM with the LiteLLM master key; `worker-mcp` gets only that key. Nothing in the Kali
  sandbox gets any key: the sandbox environment is cleared (`env -i`).
- **Redaction.** `harness/redact.py` removes private keys, cloud and API tokens, JWTs and `password=`-style
  values from what the worker returns to the planner, and from finding fields in the report. It's pattern-based:
  a safety net, not a guarantee. The values stay in the evidence files.
- `./rvkit openhands` reads keys from `.env` and sends them only to the local OpenHands API. It doesn't print them.

## Configuration plumbing

- **LiteLLM.** `litellm/config.yaml` is a tracked template. `./rvkit` runs `scripts/render_litellm.py` to render
  it with your `.env` settings (daily budget, worker fallback on or off) into `.rvkit/litellm.yaml`, the file the
  container reads. Commands that change those settings (`connect`, `worker`, `planner`, `budget`) re-render it
  and recreate the `litellm` container. Model names and endpoints come from `.env` (`PLANNER_MODEL`,
  `WORKER_API_BASE`, …) through `os.environ/…` references.
- **OpenHands.** `scripts/openhands_config.py` configures OpenHands through its local API. It's idempotent, and
  `./rvkit setup`, `./rvkit up` and `./rvkit openhands` all run it. It creates or updates:
  - LLM profiles `colab-qwen`, `private-llm` and `planner` (all pointing at LiteLLM);
  - MCP servers `web`, `kali`, `worker`, `findings`, `intel` (and removes the old `search` / `fetch` servers);
  - agent profiles `riskvoid-planner` (planner model, all five servers, `prompts/planner.md`) and
    `riskvoid-local` (`private-llm`, all servers except `worker`, `prompts/planner.md` + `prompts/local.md`).
    `{{ORG_NAME}}` in the prompt is replaced by `ORG_NAME`, or RiskVoid / "the security team" by brand;
  - `riskvoid-planner` and `planner` as the defaults for new conversations;
  - then it checks that every MCP server answers. Your own extra profiles and MCP servers are left alone.
- **Gateway start page.** `http://localhost:8000/` (and `/riskvoid`) serves `gateway/start.html`, which marks
  OpenHands' generic onboarding as done, declines telemetry and opens the canvas. Every other path goes straight
  to OpenHands.
- **Egress allowlist.** `egress/start.sh` builds the tinyproxy filter at container start from
  `egress/allowlist.txt` (copied into the image) and `EGRESS_EXTRA_DOMAINS`. Change `EGRESS_EXTRA_DOMAINS` and
  run `./rvkit up`; changing `allowlist.txt` itself needs a rebuild (`RVKIT_BUILD=1 ./rvkit up`).

All settings are listed in [configuration.md](configuration.md).

## Design decisions

| Decision | Why |
|---|---|
| **Planner and worker are separate models** | A frontier model is best at planning, triage and writing; tool output and client code are the bulk of the tokens and the most sensitive data. The worker sees those; the planner gets short, redacted summaries. You can also run everything on the worker (`riskvoid-local`). |
| **MCP is the integration boundary** | Every capability the agent has is an MCP tool with a narrow interface. The kit's controls live in those servers, not in the agent runtime, so they hold whichever agent or model calls them (OpenHands today, any MCP client tomorrow). |
| **The firewall is the hard boundary; tiers are guardrails** | Network policy built from the scope can't be argued with or worked around by rephrasing. Tiers, rate caps and the precheck catch honest mistakes and keep the agent within the agreed intensity. |
| **Tiers by program name** | Classifying arbitrary code by what it might send isn't reliable. Program names are predictable and easy to review. The cost (scripts run at the passive tier, `curl` at the active tier, without approval) is documented in [SECURITY.md](../SECURITY.md). |
| **Human approvals bound to the exact command** | An approval covers one run of one exact command (matched by hash), expires after 24 hours, and can only be given on the host. The agent can't approve itself or reuse an approval for something else. |
| **Evidence hashed when it's written** | `kali-mcp` hashes every file a command creates or changes, in the same step, into a log the agent can't write. The report then proves each evidence file is unchanged and names the command that produced it. |
| **Files on the host** | Engagements are plain folders (Markdown, SQLite, tool output) you can read, back up, archive and hand over without the kit. Client code is mounted read-only. |
| **Pinned versions, at least two weeks old** | Every image, package, binary and Git dependency is pinned to an exact version that has been public for two weeks or more, so builds are reproducible and a freshly compromised release isn't picked up automatically. Exceptions are listed in [CONTRIBUTING.md](../CONTRIBUTING.md). |
| **Published multi-arch images, build as fallback** | `./rvkit setup` and `up` pull the kit's images for the current `VERSION` (amd64 and arm64), so first start is minutes, not a 10-minute build. Anything that can't be pulled is built locally; `RVKIT_BUILD=1` builds everything (use it after changing the kit's code). |
| **Semgrep rules downloaded at runtime** | The Semgrep Rules License doesn't allow redistributing the rules, so they aren't in the published image. `kali-mcp` downloads them from a pinned commit into the `semgrep-rules` volume on first start. See [THIRD_PARTY.md](../THIRD_PARTY.md). |
| **OpenHands pinned** | `./rvkit` configures OpenHands through its API, which changes between versions. The pinned version is the one the configuration script is tested with. Its database can't be downgraded, so `AGENT_CANVAS_TAG` lets you match a newer data volume ([troubleshooting.md](troubleshooting.md)). |

## Source layout

```
rvkit                       control script (./rvkit help)
docker-compose.yml          the stack: OpenHands, gateway, egress proxy, LiteLLM, Valkey, SearXNG, MCP servers, lab
VERSION                     kit version; selects the published image tags
gateway/                    Caddyfile and start page (UI on 127.0.0.1:8000)
egress/                     tinyproxy allowlisting proxy for the agent container (allowlist.txt)
litellm/config.yaml         model routing template (rendered into .rvkit/litellm.yaml)
searxng/settings.yml        search engine settings
prompts/                    planner.md (planner persona and method), local.md (local-only additions)
scripts/                    openhands_config.py (OpenHands API setup), render_litellm.py
kali-mcp/
  server.py                 MCP tools: list_engagements, engagement_info, all_scopes, run, evidence_provenance, …
  core.py                   policy: scope parsing, tiers, rate caps, approvals, halt, firewall, DNS, audit, close-out
  rvctl.py                  admin CLI behind ./rvkit (sync, approve, halt, audit, close, …)
  rv-sandbox.sh             per-command sandbox (mount namespace, unprivileged user)
  infra_domains.txt         package / vulnerability-database domains for online engagements
  aitools/                  rv-llm (LLM / agent / MCP testing), jwt_tool wrapper
  joern/                    rv-joern and the taint-tracking script
  Dockerfile                the Kali image with every tool, pinned
harness/
  worker.py                 worker MCP server (delegate_task) and the worker model's tool loop
  findings.py, findings_db.py   findings MCP server, SQLite store, write_file, playbooks, generate_report
  report.py, branding.py, brand/, brands/example/   report generator and branding
  intel.py                  vulnerability intelligence MCP server
  web.py, webfetch.py       web research MCP server and the scope-aware fetch
  redact.py                 secret redaction
  playbooks/                methodology playbooks
colab/                      serve.py (Colab launcher), the notebook built from it
evals/                      regression tests, benchmarks, benchmark targets
.github/workflows/          CI and image publishing
.claude/, .mcp.json         Claude Code commands (/rv-setup, /rv-start, /rv-stop) and the Colab MCP server
```

See also: [SECURITY.md](../SECURITY.md) · [tools-reference.md](tools-reference.md) ·
[configuration.md](configuration.md) · [models.md](models.md)
