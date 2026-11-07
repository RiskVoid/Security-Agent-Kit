# rvkit command reference

`rvkit` is the kit's control script: it starts and stops the stack, manages engagements and switches models. This
page lists every command with its arguments. `./rvkit help` prints a short version.

Run it from the kit folder as `./rvkit …`, or from anywhere after `./rvkit install`. It runs under bash (macOS
bash 3.2 works), so it behaves the same from bash, zsh and fish. Commands that change settings write them to
`.env` and restart only what needs restarting.

**Interactive prompts.** `setup`, `new` and `watch` ask questions on the terminal. With `--yes` (setup only),
`RVKIT_YES=1`, or no terminal (CI, a coding agent), every question takes its default; `watch` refuses to run
without a terminal.

## Overview

| Area | Commands |
|---|---|
| Start and check | [`setup`](#setup), [`up`](#up), [`down`](#down), [`status`](#status), [`doctor`](#doctor), [`quickstart`](#quickstart), [`logs`](#logs) |
| Models | [`connect`](#connect), [`worker`](#worker), [`planner`](#planner), [`budget`](#budget), [`test`](#test), [`key`](#key), [`openhands`](#openhands) |
| Engagements | [`new`](#new), [`engagement`](#engagement), [`eng`](#eng), [`watch`](#watch), [`approvals`](#approvals), [`approve` / `deny`](#approve--deny), [`scope`](#scope), [`show`](#show), [`halt` / `resume`](#halt--resume), [`audit`](#audit), [`report`](#report), [`close`](#close) |
| Practice and tests | [`lab`](#lab), [`bench`](#bench) |
| Shell | [`install`](#install), [`completion`](#completion), [`help`](#help) |

---

## Start and check

### setup

```sh
./rvkit setup [--yes]
```

First-time setup, in five steps:

1. Checks Docker, Docker Compose v2, `openssl`, `python3`, `curl` and `perl`.
2. Creates `.env` from `.env.example` with fresh secrets and asks:
   - the folder for client code and engagements (default `~/riskvoid`, giving `~/riskvoid/projects` and
     `~/riskvoid/engagements`);
   - the organisation name on reports (default `RiskVoid`; any other name sets `ORG_NAME` and `REPORT_BRAND=plain`);
   - your OpenRouter API key (hidden input; Enter skips).

   If `.env` already exists, it is kept and these questions are skipped.
3. Starts the containers: pulls the published images for this version and builds any it can't pull.
4. Configures OpenHands: LLM profiles, MCP servers and the two agent profiles.
5. On a first run, asks which worker model to use: `colab` (default), `local`, `api` or `later`.

`setup` is safe to run again: it keeps your `.env`, starts anything that isn't running and re-applies the
OpenHands configuration. `init` is an alias.

Non-interactive defaults come from environment variables:

| Variable | Default | Question |
|---|---|---|
| `RVKIT_DATA_DIR` | `~/riskvoid` | data folder |
| `RVKIT_ORG` | `RiskVoid` | organisation name |
| `RVKIT_WORKER` | `colab` | worker (`colab`, `local`, `api`, `later`) |
| `RVKIT_BUILD` | unset | `1` builds every image from source instead of pulling (also for `up`) |

```sh
RVKIT_DATA_DIR=/data/riskvoid RVKIT_ORG="Acme Security" RVKIT_WORKER=later ./rvkit setup --yes
```

### up

```sh
./rvkit up
RVKIT_BUILD=1 ./rvkit up      # rebuild the kit's images from your working copy
```

Starts the stack (pulling published images first), waits for LiteLLM, then re-applies the OpenHands configuration
quietly. Run it after `git pull`, after editing `.env`, and after changing branding or `EGRESS_EXTRA_DOMAINS`.
Settings in `.env` are also migrated: settings added in newer versions get their defaults.

### down

```sh
./rvkit down
```

Stops and removes the containers (`docker compose down`). Volumes and your files are kept: conversations,
engagements, the audit log, the spend counter and caches all survive. See [operations.md](operations.md) for a
full reset.

### status

```sh
./rvkit status
```

One screen: how many services are running (and which aren't), lab targets that are up, whether the worker
endpoint answers, the fallback state, the planner model, OpenRouter spend against the daily budget, the number of
engagements (and halted ones), and pending approvals.

### doctor

```sh
./rvkit doctor [--models]
```

Checks everything and says what to fix. Each line is ✔ (fine), ! (warning) or ✘ (problem). Exits with status 1
if there is any problem.

| Section | Checks |
|---|---|
| Host | Docker running and version, Compose v2, `openssl`/`python3`/`curl`/`perl`, Docker memory (8 GB minimum, 16 GB recommended), CPU architecture, free disk where engagements live (25 GB recommended) |
| Settings | both data folders exist, OpenRouter key set, worker fallback on or off |
| Services | each of the 11 core services running, the OpenHands database-version error, LiteLLM and OpenHands answering, every MCP server reachable from OpenHands |
| Isolation | the Kali scope firewall is loaded, and the OpenHands container can't reach `example.com` directly |
| Models | the worker endpoint answers `/models` (no tokens spent); with `--models`, also one short planner call (a fraction of a cent) |

### quickstart

```sh
./rvkit quickstart
```

Starts the stack if needed, starts the [practice lab](lab-and-benchmarks.md), creates the engagement `lab-juice`
(scope `10.250.0.10`, tiers passive and active, client "Practice lab") if it doesn't exist, prints a ready-made
prompt and opens the UI. Walkthrough: [first-engagement.md](first-engagement.md).

### logs

```sh
./rvkit logs [service …]
```

The last 80 lines of logs from every service, or from the ones you name, for example `./rvkit logs kali-mcp
agent-canvas`. Service names are in [architecture.md](architecture.md#components).

---

## Models

See [models.md](models.md) for what each model does and what data it sees.

### connect

```sh
./rvkit connect <url> [key] [model]
```

Points the worker at a running Colab model. The Colab notebook prints this line for you. `/v1` is added to the
URL if missing. `key` defaults to `COLAB_API_KEY` from `.env`; `model` defaults to `qwen38-27b` (the abliterated
build is `qwen38-27b-obl`). Saves the URL as `COLAB_API_BASE`, recreates LiteLLM and sends a test prompt: it should
end with "Model reachable".

### worker

```sh
./rvkit worker [show]                                  # current endpoint, model and fallback state
./rvkit worker colab                                   # back to the last Colab URL (from connect)
./rvkit worker local [url] [model] [key]               # a server on this machine
./rvkit worker api <url> <model> [key]                 # any OpenAI-compatible endpoint
./rvkit worker fallback [show|on|off|<openrouter-model>]
```

- `local` without arguments finds a server on ports 11434 (Ollama), 1234 (LM Studio), 8080 (llama-server), 8001
  and 5000, and uses the first model it lists. Containers reach it as `http://host.docker.internal:<port>/v1`. On
  Linux the server must listen on an address containers can reach (Ollama: `OLLAMA_HOST=0.0.0.0`).
- `api` takes a base URL ending in `/v1` and the model name the server expects. The key defaults to `none`.
- `fallback on` lets worker calls go to an OpenRouter model while the endpoint is down (default model DeepSeek V4.1
  Flash). `fallback <model>` sets the model and turns it on; `fallback off` turns it off (the default). While the
  fallback is in use, **that model sees tool output and client code**.

Every change recreates LiteLLM and sends a test prompt.

### planner

```sh
./rvkit planner                                  # show
./rvkit planner <openrouter-model> [fallback]    # set, e.g. anthropic/claude-sonnet-5.5 openai/gpt-6.1-sol
```

Shows or sets the planner model and its fallback (OpenRouter ids; the `openrouter/` prefix is optional). Setting
recreates LiteLLM and sends a test prompt.

### budget

```sh
./rvkit budget          # the cap and what's spent in the current 24-hour period
./rvkit budget 50       # set the cap to $50 per day
```

The daily cap on OpenRouter spend (planner, plus the worker fallback when on). Over the cap, OpenRouter calls fail
until the period ends. The spend so far is kept when you change the cap.

### test

```sh
./rvkit test            # one short prompt to the worker (colab-qwen)
./rvkit test planner    # the same to the planner
```

Any LiteLLM model alias works, for example `./rvkit test private-llm`.

### key

```sh
./rvkit key [colab|litellm|openhands]
```

Prints one key from `.env`. `colab` (the default) is the key to paste into the Colab notebook's `API_KEY` field.
`litellm` is the LiteLLM master key (for calling `http://127.0.0.1:4000` yourself). `openhands` is the OpenHands
local API key.

### openhands

```sh
./rvkit openhands
```

Re-applies the OpenHands configuration and prints each step: LLM profiles (`colab-qwen`, `private-llm`,
`planner`), MCP servers (`web`, `kali`, `worker`, `findings`, `intel`), agent profiles (`riskvoid-planner`,
`riskvoid-local`) with the prompts from `prompts/`, and the defaults for new conversations. Then it checks that
every MCP server answers. `up` and `setup` run it too. Your own extra profiles and MCP servers are left alone.

---

## Engagements

Every engagement command also works as `./rvkit eng <command> …`. See [engagements.md](engagements.md) for the
full guide.

### new

```sh
./rvkit new [name]
```

Creates an engagement interactively. It asks for:

| Question | Default | Written to |
|---|---|---|
| Engagement name (letters, digits, `.` `_` `-`, up to 64 characters) | | folder name |
| Client name (shown on the report) | empty | `report/meta.txt` |
| Targets, one per line, empty line to finish | | `SCOPE.md` |
| Allowed tiers | `passive, active` | `RULES.md` |
| Max requests/packets per second | `100` | `RULES.md` |
| Network: `online` or `offline` | `online` | `RULES.md` |
| Keep tool output on the worker endpoint only | `n` | `RULES.md` (`Worker model: private`) |

It lists the code folders it finds in `PROJECTS_DIR` as `/src/<folder>`, checks each answer, writes the files and
activates them. It refuses a name that already has a `SCOPE.md`.

### engagement

```sh
./rvkit engagement <name> [--client "Client"] <target> [target …]
```

Creates (or re-scopes) an engagement without questions, with tiers `passive, active`, rate 100, online, and the
fallback allowed. `--client` must come right after the name.

```sh
./rvkit engagement acme-2026-11 --client "Acme Ltd" app.acme.com "*.acme.io" 203.0.113.0/28 /src/acme-repo
```

If the engagement exists, `SCOPE.md` is rewritten with the new targets and applied; `RULES.md` is kept.

### eng

```sh
./rvkit eng list                 # all engagements: tiers, network, targets, halted, pending approvals
./rvkit eng <command> …          # same as ./rvkit <command> …
```

`eng` alone is `eng list`. Sub-commands: `list new show scope approvals approve deny halt resume audit report close`.

### watch

```sh
./rvkit watch
```

Watches every engagement for intrusive commands waiting for approval. For each new one it shows a desktop
notification (macOS `osascript`, Linux `notify-send`), prints the engagement, approval id, tier and command, and
asks: `a` approve, `d` deny, `s` skip (default; it stays pending). After approving, tell the agent to run the
command again. Ctrl-C stops watching. Needs a terminal.

### approvals

```sh
./rvkit approvals [engagement] [--json]
```

Lists pending approvals: engagement, id, tier and command. Without an engagement, all of them.

### approve / deny

```sh
./rvkit approve <engagement> <id>
./rvkit deny <engagement> <id>
```

Decides one approval. An approval is for that exact command only, can be used once, and expires 24 hours after
you approve it.

### scope

```sh
./rvkit scope <engagement>          # show the diff between SCOPE.md / RULES.md and the active copy
./rvkit scope <engagement> --yes    # apply it
```

Applies your edits to `SCOPE.md` and `RULES.md`. Until you apply them, edits have no effect. Applying rebuilds the
firewall and DNS for all engagements and prints any scope entries that were ignored (with the reason).

### show

```sh
./rvkit show <engagement>
```

The active scope (networks, domains, code paths), rules (tiers, max rate, network, window, worker), halt state, the
engagement's sandbox user id and the infrastructure domains it may reach, as JSON.

### halt / resume

```sh
./rvkit halt <engagement>       # kill everything running for it and refuse new commands
./rvkit resume <engagement>     # allow commands again
```

### audit

```sh
./rvkit audit [engagement] [n]
```

The last `n` (default 20) entries of the authoritative audit log, one JSON object per line, optionally for one
engagement. Entries record each command (with its tier, exit code, duration and the hashes of files it wrote),
each refusal with its reason, approvals, halts, scope changes and close-out.

### report

```sh
./rvkit report <engagement>
```

Builds the report (`.docx` and `.pdf`) and the findings register (`.xlsx`) in `<engagement>/report/` and prints the
paths, `DRAFT` or `final`, and what keeps it a draft. Takes about a minute. See
[findings-and-reports.md](findings-and-reports.md).

### close

```sh
./rvkit close <engagement>
```

Close-out: writes `audit.jsonl` (this engagement's audit entries) and copies the active `SCOPE.md` / `RULES.md`
into the folder, writes `MANIFEST.sha256` of every file, archives the folder to
`<ENGAGEMENTS_DIR>/_archive/<engagement>-<UTC time>.tar.gz` with a `.sha256` next to it, and halts the engagement.

---

## Practice and tests

### lab

```sh
./rvkit lab up        # start the practice targets and prepare their databases
./rvkit lab status    # their state
./rvkit lab down      # stop and remove them (they start clean next time)
```

`lab` alone is `lab status`. Targets and addresses: [lab-and-benchmarks.md](lab-and-benchmarks.md).

### bench

```sh
./rvkit bench <name|all> [--agent riskvoid-planner|riskvoid-local] [--keep]
python3 evals/run_benchmark.py --history
```

Runs the real agent unattended against a known target and scores it. Names are the files in `evals/benchmarks/`.
Details: [lab-and-benchmarks.md](lab-and-benchmarks.md#benchmarks).

---

## Shell

### install

```sh
./rvkit install [dir]
```

Links `rvkit` into `dir` (default `~/.local/bin`) so you can run `rvkit` from anywhere, warns if that folder isn't
on your `PATH`, and prints the completion lines below.

### completion

```sh
./rvkit completion bash|zsh|fish
```

Prints a completion script: commands, `eng` / `worker` / `lab` sub-commands and engagement names.

```sh
echo 'eval "$(rvkit completion bash)"' >> ~/.bashrc
echo 'eval "$(rvkit completion zsh)"' >> ~/.zshrc
rvkit completion fish > ~/.config/fish/completions/rvkit.fish
```

### help

```sh
./rvkit help
```

`-h` and `--help` work too. An unknown command prints the help and exits with an error.

---

See also: [configuration.md](configuration.md) for every `.env` setting, [operations.md](operations.md) for
running the stack day to day.
