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
| Start and check | [`setup`](#setup), [`up`](#up), [`down`](#down), [`update`](#update), [`status`](#status), [`doctor`](#doctor), [`quickstart`](#quickstart), [`logs`](#logs) |
| Models | [`connect`](#connect), [`worker`](#worker), [`planner`](#planner), [`budget`](#budget), [`test`](#test), [`key`](#key), [`openhands`](#openhands) |
| Engagements | [`new`](#new), [`engagement`](#engagement), [`eng`](#eng), [`console`](#console), [`watch`](#watch), [`approvals`](#approvals), [`approve` / `deny`](#approve--deny), [`scope`](#scope), [`show`](#show), [`halt` / `resume`](#halt--resume), [`audit`](#audit), [`report`](#report), [`close`](#close), [`delete`](#delete) |
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

### update

```sh
./rvkit update
```

Updates the kit: `git pull --ff-only`, lists the new commits and any new optional settings in `.env.example`,
then runs the new version's `up` (pulls or builds its images, migrates `.env`, re-applies the OpenHands
configuration). It stops without changing anything if tracked files have local changes or the branch has
diverged. Your `.env` and data are never touched by the pull.

### status

```sh
./rvkit status
```

One screen: how many services are running (and which aren't), lab targets that are up, whether the worker
endpoint answers, the fallback state, the planner model, OpenRouter spend against the daily budget, failed model calls in the last hour (and how often
another model answered instead), the number of engagements (and halted ones), and pending approvals.

### doctor

```sh
./rvkit doctor [--models]
```

Checks everything and says what to fix. Each line is ✔ (fine), ! (warning) or ✘ (problem). Exits with status 1
if there is any problem. Failed model calls of the last 24 hours are listed as warnings, each with its fix.

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
URL if missing. `key` defaults to `COLAB_API_KEY` from `.env`; `model` defaults to `qwen38-27b-obl` (the mainstream
build is `qwen38-27b`). Saves the URL as `COLAB_API_BASE`, recreates LiteLLM and sends a test prompt: it should
end with "Model reachable".

### worker

```sh
./rvkit worker [show]                                  # current endpoint, model and fallback state
./rvkit worker colab                                   # back to the last Colab URL (from connect)
./rvkit worker local [url] [model] [key]               # a server on this machine
./rvkit worker api <url> <model> [key]                 # any OpenAI-compatible endpoint
./rvkit worker openrouter [model]                      # no GPU: a hosted model with your OpenRouter key
./rvkit worker fallback [show|on|off|<openrouter-model>]
```

- `local` without arguments finds a server on ports 11434 (Ollama), 1234 (LM Studio), 8080 (llama-server), 8001
  and 5000, and uses the first model it lists. Containers reach it as `http://host.docker.internal:<port>/v1`. On
  Linux the server must listen on an address containers can reach (Ollama: `OLLAMA_HOST=0.0.0.0`).
- `api` takes a base URL ending in `/v1` and the model name the server expects. The key defaults to `none`.
- `openrouter` makes the worker a hosted model on OpenRouter (default DeepSeek V4.1 Flash), with zero-data-retention
  providers and the daily budget. Tool output and client code then go to OpenRouter ([Models](models.md#option-4-no-gpu-at-all-a-hosted-model-on-openrouter)).
- `fallback on` lets worker calls go to an OpenRouter model while the endpoint is down (default model DeepSeek V4.1
  Flash). `fallback <model>` sets the model and turns it on; `fallback off` turns it off (the default). While the
  fallback is in use, **that model sees tool output and client code**.

Every change recreates LiteLLM and sends a test prompt.

### planner

```sh
./rvkit planner                                  # show
./rvkit planner <openrouter-model> [fallback]    # set, e.g. openai/gpt-6.1-sol deepseek/deepseek-v4-pro
./rvkit planner --direct anthropic/<model> [fallback]   # Anthropic or OpenAI directly, without OpenRouter
```

Shows or sets the planner model and its fallback (OpenRouter ids; the `openrouter/` prefix is optional). Setting
recreates LiteLLM and sends a test prompt. With `--direct`, ids start with `anthropic/`, `openai/` or
`openrouter/`, and the command asks for `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` if it isn't set
([Models](models.md#anthropic-or-openai-directly)).

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
./rvkit engagement <name> [options] <target> [target …]
```

Creates an engagement without questions. Options go between the name and the targets:

| Option | Default | Meaning |
|---|---|---|
| `--client "Name"` | none | client name for the report (`report/meta.txt`) |
| `--tiers passive,active` | `passive, active` | allowed tiers |
| `--rate N` | `100` | max requests or packets per second |
| `--network online\|offline` | `online` | whether package and vulnerability-database sites are reachable |
| `--private` | off | `Worker model: private`: never use the fallback model |
| `--replace` | off | replace the scope of an existing engagement (see below) |

The rule options apply only when `RULES.md` doesn't exist yet; an existing `RULES.md` is kept.

```sh
./rvkit engagement acme-2026-11 --client "Acme Ltd" app.acme.com "*.acme.io" 203.0.113.0/28 /src/acme-repo
```

If the engagement exists, the command refuses and changes nothing. To change a scope, edit `SCOPE.md` and run
[`scope`](#scope), which shows the diff first. To replace the whole scope with the targets you give, add
`--replace`: it rewrites `SCOPE.md`, prints the diff and applies it. `RULES.md` is kept.

### eng

```sh
./rvkit eng list                 # all engagements: tiers, network, targets, halted, pending approvals
./rvkit eng <command> …          # same as ./rvkit <command> …
```

`eng` alone is `eng list`. Sub-commands: `list new show scope approvals approve deny halt resume audit report close delete`.

### console

```sh
./rvkit console [--no-open]
```

Starts the RiskVoid Console on `http://127.0.0.1:<CONSOLE_PORT>/` (default 8100) and opens it signed in, or with
`--no-open` prints the sign-in link. Runs in the foreground; Ctrl-C stops it. See [console.md](console.md).

### watch

```sh
./rvkit watch
```

Watches every engagement for intrusive commands waiting for approval. For each new one it shows a desktop
notification (macOS `osascript`, Linux `notify-send`), prints the engagement, approval id, tier and command, and
asks: `a` approve, `d` deny, `s` skip (default; it stays pending). After approving, tell the agent to run the
command again. It also prints each failed model call with what to do (no credits, budget used up, worker
down, refusal, ...) and raises a desktop notification for it; calls another model recovered are printed only.
Ctrl-C stops watching. Needs a terminal.

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
you approve it. A worker task waiting for it continues by itself.

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

Halt also stops the engagement's worker tasks, pauses its bound conversations, and makes the model gateway refuse
their model calls.

### conversation

```sh
./rvkit conversation <engagement> new ["first message"]   # create an OpenHands conversation bound to it
./rvkit conversation <engagement> list                    # bound conversations (the default)
./rvkit conversation <engagement> bind <conversation-id>
./rvkit conversation <engagement> unbind <conversation-id>
```

A bound conversation's model calls follow the engagement's `Client data:` rule and halt. `new` uses
`riskvoid-planner`, or `riskvoid-local` when the rule doesn't allow the planner's route, and prints the link. See
[engagements.md](engagements.md#conversations).

### cred

```sh
./rvkit cred <engagement> list              # names only (the default)
./rvkit cred <engagement> set <NAME>        # asks for the value, hidden
./rvkit cred <engagement> rm <NAME>
```

Credentials the agent uses by reference (`$RV_CRED_<NAME>`, `{{cred:NAME}}`) without seeing them. Names are
letters, digits and `_`, starting with a letter. `set <NAME> --expires 2026-12-01` refuses the credential after
that date. Values are encrypted with the vault key. See [engagements.md](engagements.md#credentials).

### appmap

```sh
./rvkit appmap <engagement> </src/path> [--build-url URL] [--routes evidence/php/routes-<time>.json]
```

The Laravel application map, from the source (no code runs). See [laravel.md](laravel.md).

### php

```sh
./rvkit php <engagement> lint </src/path>      # parse check with PHP's parser; nothing runs
./rvkit php <engagement> routes </src/path>    # boot the app on a copy, export its routes (asks first)
```

The optional PHP profile: an isolated container with no network, built on first use. See
[laravel.md](laravel.md#php-profile-optional).

### vault

```sh
./rvkit vault rotate     # new vault key; every credential and identity session is re-encrypted
```

### identity

```sh
./rvkit identity <engagement> list
./rvkit identity <engagement> set <name> <spec.json>
./rvkit identity <engagement> check <name>     # the valid-session control (exit 4 when not valid)
./rvkit identity <engagement> revoke <name>
./rvkit identity <engagement> rm <name>
```

Test accounts for authenticated testing. The spec format: [authenticated-testing.md](authenticated-testing.md#the-spec).

### capture

```sh
./rvkit capture <engagement> list
./rvkit capture <engagement> import <file.har|burp.xml> [name]
./rvkit capture <engagement> show <id>         # the sanitized copy the agent sees
./rvkit capture <engagement> raw <id>          # the original (encrypted at rest, host only)
./rvkit capture <engagement> rm <id>
```

### authz

```sh
./rvkit authz <engagement> list
./rvkit authz <engagement> show <name>
./rvkit authz <engagement> approve <name>      # prints the matrix and asks; binds the approval to its digest
./rvkit authz <engagement> run <name>
```

Authorization matrices the agent proposes. See [authenticated-testing.md](authenticated-testing.md#authorization-matrices).

### task

```sh
./rvkit task cancel <task-id>    # stop a worker task and kill its running command
./rvkit task resume <task-id>    # continue an interrupted task from its last checkpoint
```

### audit

```sh
./rvkit audit [engagement] [n]
```

The last `n` (default 20) entries of the authoritative audit log, one JSON object per line, optionally for one
engagement. Entries record each command (with its tier, exit code, duration and the hashes of files it wrote),
each refusal with its reason, approvals, halts, scope changes and close-out, and changes to findings and report
details. Each entry names its actor: `cli:<login>` for `./rvkit`, `console:<login>` for the console, `agent:…` for
the agent.

### policy

```sh
./rvkit policy <engagement> [--json]
```

What the active scope and rules allow and exclude, the rules in force (with the time zone), stop conditions, what
the kit doesn't enforce, and the policy revision history (number, time, who applied it, digest). `--json` prints
the effective policy for scripts.

### finding

```sh
./rvkit finding <engagement> <F-001> status=confirmed [severity=high] [notes="..."] [title=...] [duplicate_of=F-002]
```

Changes a finding through the same operation as the console and the agent's tools, so the same checks apply. The
change is recorded in the audit log as yours (`cli:<login>`). Statuses: `candidate`, `confirmed`,
`false-positive`, `duplicate` (with `duplicate_of`), `fixed`, `accepted-risk`.

### report

```sh
./rvkit report <engagement>
./rvkit report <engagement> revisions
./rvkit report <engagement> except <check> "<rationale>"
./rvkit report <engagement> approve <R-id> ["<note>"]
./rvkit report <engagement> verify <R-id>
./rvkit report <engagement> rebuild <R-id>
./rvkit report <engagement> export [--draft]
./rvkit report <engagement> sent <R-id> "<to>" "<how>"
```

`report <engagement>` builds a new report revision (`.html`, `.docx`, `.pdf` and the findings register `.xlsx`) in
`<engagement>/report/revisions/<R-id>/`, copies it to `<engagement>/report/`, and prints its state and the
readiness checks that block delivery. Takes about a minute.

| Sub-command | What it does |
|---|---|
| `revisions` | every revision with its state and who approved it |
| `except <check> <rationale>` | records an exception for a methodology check (`coverage-plan`, `coverage-open`, `coverage-stale`, `fields:<F-id>`, `verification:<F-id>`, `retest:<F-id>`) in your name; generate again afterwards |
| `approve <R-id> [note]` | approves the latest, ready revision for client delivery; refused if anything changed since it was generated |
| `verify <R-id>` | re-hashes the revision's files; exits 1 if one is missing or modified |
| `rebuild <R-id>` | renders it again from its frozen inputs and compares the HTML |
| `export [--draft]` | `findings.json`, `findings.sarif` and `issues/<F-id>.md` from the approved revision (`--draft`: the latest) |
| `sent <R-id> <to> <how>` | records that an approved revision was sent; sends nothing |

See [findings-and-reports.md](findings-and-reports.md).

### close

```sh
./rvkit close <engagement>
```

Close-out: writes `audit.jsonl` (this engagement's audit entries) and copies the active `SCOPE.md` / `RULES.md`
into the folder, writes `MANIFEST.sha256` of every file, archives the folder to
`<ENGAGEMENTS_DIR>/_archive/<engagement>-<UTC time>.tar.gz` with a `.sha256` next to it, and halts the engagement.

### delete

```sh
./rvkit eng delete <engagement> [--force]
```

Unregisters a closed engagement (halted, with at least one archive): kills anything still running, removes its
scope, rules, approvals and firewall rules from the control volume, and frees its sandbox user for a new
engagement. Nothing on disk is removed: the folder is renamed to `_deleted-<engagement>-<UTC time>` in
`ENGAGEMENTS_DIR`, archives stay in `_archive/`, and the audit log keeps the engagement's history. The name can be
used again.

`--force` deletes an engagement that isn't closed (no archive or manifest) after asking you to confirm. Use it for
practice and test engagements.

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
