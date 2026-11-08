# Getting started

This page takes you from a fresh clone to a working kit: requirements, setup, the health check, the first look at
the UI, and the steps for your first real engagement.

## Requirements

| | |
|---|---|
| Computer | macOS or Linux with **Docker** (Docker Desktop, OrbStack or Docker Engine) and Docker Compose v2. 16 GB of memory for Docker is recommended (8 GB minimum), and about 25 GB of free disk. |
| Command-line tools | `python3`, `curl`, `perl`, `openssl` (setup checks for them) |
| Planner | An **OpenRouter** API key (https://openrouter.ai/keys). Optional: without it, only the `riskvoid-local` agent works. |
| Worker model | One of: **a hosted model on OpenRouter** (no GPU, just your OpenRouter key), **Google Colab Pro** (default, nothing to install), a local model server (Ollama, LM Studio, llama.cpp, vLLM; about 24 GB of VRAM for Qwen 27B), or any OpenAI-compatible endpoint. Optional for a first look: without one, the planner runs the Kali tools itself. |
| Optional | **Claude Code** (or another coding agent) and `uv`, for the one-command Colab start |

The kit has been verified on macOS (Apple Silicon) with OrbStack. Linux and amd64 haven't been through the full
test suites yet ([SECURITY.md](../SECURITY.md#known-limitations)).

## Install

```sh
git clone https://github.com/RiskVoid/Security-Agent-Kit.git
cd Security-Agent-Kit
./rvkit setup
```

`setup` runs five steps:

| Step | What happens |
|---|---|
| 1. Checking prerequisites | Docker is installed and running, Compose v2 is there, and `openssl`, `python3`, `curl` and `perl` are on your PATH. |
| 2. Settings (`.env`) | Creates `.env` from `.env.example` with fresh secrets and asks the first three questions below. If `.env` already exists, it's kept as it is and nothing is asked. |
| 3. Starting containers | Pulls the published images for this version and builds any that can't be pulled. A few minutes with published images, about 10 minutes when building. |
| 4. Configuring OpenHands | Creates the LLM profiles, connects the five MCP servers, creates the `riskvoid-planner` and `riskvoid-local` agents and tests that every tool server answers. |
| 5. Worker model | Asks the fourth question and sets up the worker. |

The four questions (press Enter to accept the default):

| Question | Default | Stored in `.env` as |
|---|---|---|
| Folder for client code and engagements | `~/riskvoid` | `PROJECTS_DIR=<folder>/projects`, `ENGAGEMENTS_DIR=<folder>/engagements` |
| Organisation name on reports | `RiskVoid` | Any other name sets `ORG_NAME=<name>` and `REPORT_BRAND=plain` (a neutral report with your name). See [Configuration](configuration.md). |
| OpenRouter API key for the planner | skip (input hidden) | `OPENROUTER_API_KEY` |
| Worker | `colab` | `colab`, `local`, `api` or `later`. See [Choosing a worker](#choosing-a-worker). |

### Setup without questions

`./rvkit setup --yes` (or `RVKIT_YES=1`) takes every default without asking. It also does this when there's no
terminal. You can set the answers with environment variables:

```sh
RVKIT_DATA_DIR=~/clients RVKIT_ORG="Acme Security" RVKIT_WORKER=later ./rvkit setup --yes
```

| Variable | Answers |
|---|---|
| `RVKIT_DATA_DIR` | the folder question |
| `RVKIT_ORG` | the organisation question |
| `RVKIT_WORKER` | the worker question (`colab`, `local`, `api`, `later`) |

The OpenRouter key is never taken from a variable: add it to `.env` yourself afterwards, then run `./rvkit up`.
Set `RVKIT_BUILD=1` to build every image locally instead of pulling (useful after changing the kit's code).

### What setup creates

- **`.env`** in the kit folder: your settings and secrets (LiteLLM master key, SearXNG secret, Colab API key,
  OpenHands API key, Redis password). It's git-ignored. Never commit or share it.
- **Your data folders**: `<folder>/projects` for client code and `<folder>/engagements` for engagements.
- **`.rvkit/litellm.yaml`**: the model routing config, rendered from `litellm/config.yaml` and your `.env`.
- **Docker containers and volumes**: OpenHands, the gateway on `127.0.0.1:8000`, the egress proxy, LiteLLM on
  `127.0.0.1:4000`, Redis, SearXNG on `127.0.0.1:8888`, and the five MCP servers (web, kali, worker, findings,
  intel). Every port is bound to 127.0.0.1 only.

Running `./rvkit setup` again is safe: it keeps your `.env`, starts anything that isn't running and re-applies the
OpenHands configuration.

## Choosing a worker

The worker model runs the tools and sees client code. Pick where it runs:

| Option | When | How |
|---|---|---|
| `colab` | You have Colab Pro and no local GPU | Started per session with `/rv-start` in Claude Code, or the notebook by hand |
| `local` | You run Ollama, LM Studio, llama-server or vLLM on this machine | `./rvkit worker local` finds it on the usual ports |
| `api` | You have a fixed OpenAI-compatible endpoint (RunPod, Modal, your GPU server) | `./rvkit worker api <url/v1> <model> [key]` |
| `openrouter` | You have no GPU and no Colab | `./rvkit worker openrouter`: a hosted model with your OpenRouter key; client data goes to OpenRouter (zero-data-retention providers) |
| `later` | You want to look around first | `./rvkit worker` any time |

You can switch at any time without changing anything else. Details, GPU costs and the fallback model:
[Models](models.md).

## Check everything

```sh
./rvkit doctor
```

`doctor` checks the host (Docker, memory, disk), your settings, every service, the OpenHands database, LiteLLM,
OpenHands through the gateway, the MCP servers, the Kali scope firewall, the agent's network lockdown and the
worker endpoint. Each line is one of:

- `✔` fine;
- `!` a warning: works, but worth knowing (for example "Worker endpoint not reachable" before you've started
  Colab, or "Worker fallback ON");
- `✘` a problem, with what to do about it.

It ends with a count and exits with status 1 if there's any `✘`. The planner isn't called by default, because
that costs a fraction of a cent: `./rvkit doctor --models` calls it too.

For a quick overview at any time, `./rvkit status` shows the services, worker, planner, OpenRouter spend,
engagements and pending approvals on one screen.

## Open the UI

Open **http://localhost:8000/**. The start page skips OpenHands' generic onboarding and opens the canvas with the
`riskvoid-planner` agent and the `planner` model selected.

| Agent | Model | Use |
|---|---|---|
| `riskvoid-planner` (default) | planner (OpenRouter), with the worker for tool work | best results |
| `riskvoid-local` | `private-llm`: your worker model only, never the fallback | nothing leaves your setup except web searches and CVE lookups |

## Try it on the practice lab

```sh
./rvkit quickstart
```

This starts the stack if needed, starts the isolated lab targets, creates the practice engagement `lab-juice`
against OWASP Juice Shop, prints a ready-made prompt and opens the UI. It needs no client data and no GPU.
Follow [Your first engagement](first-engagement.md) for a guided run.

## Optional: rvkit on your PATH

```sh
./rvkit install                 # links ~/.local/bin/rvkit (or ./rvkit install <dir>)
```

Then you can type `rvkit status` from anywhere. Tab completion:

```sh
echo 'eval "$(rvkit completion bash)"' >> ~/.bashrc                  # bash
echo 'eval "$(rvkit completion zsh)"' >> ~/.zshrc                    # zsh
rvkit completion fish > ~/.config/fish/completions/rvkit.fish       # fish
```

Completion knows the commands, the `eng`, `worker` and `lab` subcommands, and your engagement names. `rvkit` runs
under bash, so it works the same from bash, zsh and fish.

## With Claude Code or another coding agent

In the kit folder, start `claude` and type:

| Command | Does |
|---|---|
| `/rv-setup` | First-time setup: asks for the folder and organisation, runs setup, checks the planner, helps you pick a worker, runs `doctor` |
| `/rv-start [auto\|l4\|a100-40\|a100-80] [thinking] [abliterated]` | Starts the worker on a Colab GPU and connects the stack to it |
| `/rv-stop` | Releases the Colab GPU so it stops using compute units |

`/rv-start` drives Colab through the Colab MCP server (`colab-mcp` in `.mcp.json`), which needs `uv`
(`brew install uv` on macOS). Allow the `colab-mcp` server when Claude Code asks. It works with Claude Code and
Gemini CLI, not with Claude Desktop. The steps it follows are in [AGENT_PLAYBOOK.md](../AGENT_PLAYBOOK.md).

Claude Code never asks you to paste your OpenRouter key into the chat: add it to `.env` yourself.

**Other coding agents** (Codex, Gemini CLI, Cursor, GitHub Copilot…) work the same way without the slash
commands: open the kit folder and say "Set up the RiskVoid kit. Follow AGENT_PLAYBOOK.md." Agents that read
`AGENTS.md` find the playbook by themselves. To let them start Colab, add the `colab-mcp` entry from `.mcp.json`
to that agent's MCP settings. After setup you can keep asking in plain words ("what's waiting for my approval?",
"build the report for acme-2026-11"); the playbook maps those requests to `./rvkit` commands.

## Your first real engagement

1. **Put the client's code**, if there is any, in `~/riskvoid/projects/<repo>` (your `PROJECTS_DIR`). The agent
   and the tools see it read-only as `/src/<repo>`.
2. **Create the engagement** with `./rvkit new`. It asks for the name, client, targets, allowed tiers, rate limit,
   online or offline, and whether to keep tool output on the worker only. See [Engagements](engagements.md).
3. **Start the worker** (`/rv-start`, or check `./rvkit status` if it's local or an API endpoint).
4. **Start a new conversation** with `riskvoid-planner` at http://localhost:8000/ and name the engagement in your
   first message:
   > Engagement `acme-2026-11`: source code review of `/src/acme-repo`, including dependencies and secrets.
   > Follow the matching playbooks, then write the executive summary and generate the report.

   Prompt templates for each testing type: [Running the agent](running-the-agent.md).
5. **Watch and approve** with `./rvkit watch` in a second terminal, then review the report in
   `<engagement>/report/` and close out with `./rvkit close <engagement>`.

Only test systems you have written permission to test.

## Next

- [Overview](overview.md): what the kit does and the key terms
- [Engagements](engagements.md): scope, rules, tiers, approvals, close-out
- [Running the agent](running-the-agent.md): prompts, monitoring, re-running
- [Models](models.md): worker options, fallback, planner, costs
- [Troubleshooting](troubleshooting.md)
