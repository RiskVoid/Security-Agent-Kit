# Models

This page covers the models the kit uses: the planner, the worker, the optional fallback, and how to run the
worker on Colab, your own GPU or any API endpoint. It also covers costs, budgets and where each model sends your
data.

## How the models fit together

All model calls go through LiteLLM (`127.0.0.1:4000`), which gives OpenHands and the worker one endpoint and
routes each model name to the right place:

| LiteLLM name | Points at | Used by | Falls back to |
|---|---|---|---|
| `planner` | `PLANNER_MODEL` on OpenRouter (default `openai/gpt-6.1-sol`) | the `riskvoid-planner` agent | `planner-fallback` on errors, outages, refusals and empty replies |
| `planner-fallback` | `PLANNER_FALLBACK_MODEL` on OpenRouter (default `deepseek/deepseek-v4-pro`) | | |
| `colab-qwen` | the worker endpoint (`WORKER_API_BASE`, `WORKER_MODEL_ID`) | `delegate_task` in the worker MCP server | `colab-qwen-fallback`, **only** when the fallback is on |
| `colab-qwen-fallback` | `WORKER_FALLBACK_MODEL` on OpenRouter (default `deepseek/deepseek-v4.1-flash`) | | |
| `private-llm` | the same worker endpoint as `colab-qwen` | the `riskvoid-local` agent, and `delegate_task` for engagements with `Worker model: private` | never |

`colab-qwen` keeps its name whichever endpoint you use: it may point at Colab, a local server or an API.

Every OpenRouter model is called with provider routing set to zero-data-retention providers only, with prompt
collection denied.

LiteLLM's config is a template (`litellm/config.yaml`). `./rvkit` renders it with your `.env` settings into
`.rvkit/litellm.yaml` and recreates the LiteLLM container whenever you change a model, the fallback or the
budget. Don't edit the rendered file by hand.

## Agent profiles

`./rvkit setup` and `./rvkit up` create two agents in OpenHands:

| Agent | LLM | Tools (MCP servers) | Instructions |
|---|---|---|---|
| `riskvoid-planner` (default) | `planner` | web, kali, worker, findings, intel | `prompts/planner.md` |
| `riskvoid-local` | `private-llm` | web, kali, findings, intel (no worker: it runs the tools itself) | `prompts/planner.md` + `prompts/local.md` |

Use `riskvoid-planner` for the best results. Use `riskvoid-local` when nothing may go to a cloud model: with a
local or self-hosted worker, the only traffic that leaves your setup is web searches and vulnerability-database
lookups. It needs no OpenRouter key.

Pick the agent when you start a conversation in the UI. A conversation keeps its agent and model, so start a new
conversation to switch.

## The worker

The worker carries out one focused task at a time for the planner: it runs Kali commands, reads code, searches,
fetches public pages and records candidate findings. It sees raw tool output and client code.

The kit is built and tested with **Qwen3.8-27B**. Any OpenAI-compatible model with good tool calling works, but
results vary.

```sh
./rvkit worker            # current endpoint, model and fallback state
./rvkit test              # send a short test prompt to the worker
```

### Option 1: Google Colab (default)

The worker runs on a Colab GPU, started per session. You need Colab Pro (or a plan with GPU compute units).

**With Claude Code** (one command):

```
/rv-start                 # auto profile, abliterated model, thinking off
/rv-start l4              # pick the profile
/rv-start a100-40 thinking
/rv-start qwen            # Qwen's unchanged weights (see Which model)
```

Claude Code opens Colab in your browser through the Colab MCP server and tells you what to click: sign in, pick
the GPU (Runtime → Change runtime type), approve the Google Drive popup. It uploads the launcher, starts the
model and runs `./rvkit connect` for you. `/rv-stop` releases the GPU. The full procedure is in
[AGENT_PLAYBOOK.md](../AGENT_PLAYBOOK.md#start-the-model).

**By hand:**

1. In Colab, **File → Upload notebook** → `colab/rvkit_model_server.ipynb`, then **File → Save a copy in Drive**.
2. Run `./rvkit key colab` and paste the result into the notebook's **API_KEY** field. Save the notebook: the key
   then stays the same every session. (Empty means a random key each time.)
3. Each session: **Runtime → Change runtime type → L4** (or A100), **Runtime → Run all**, approve the Google Drive
   popup.
4. The last cell prints a line like this. Run it on your computer:

   ```sh
   ./rvkit connect https://xxxx.trycloudflare.com/v1 rv-xxxx qwen38-27b-obl
   ```

   It should end with **Model reachable**.
5. When you're done: **Runtime → Disconnect and delete runtime** (or `/rv-stop`).

**Timing.** The first session takes about 25–30 minutes: llama.cpp is built once with CUDA and cached in your
Drive (`MyDrive/riskvoid-llm/`). Later sessions take 3–6 minutes, mostly the model download. Don't start the
launcher before Drive is mounted, or it rebuilds from scratch.

**Idle shutdown.** The launcher disconnects the runtime after **30 minutes** without requests, so a forgotten
session doesn't burn compute units.

**GPU profiles.** The launcher picks a profile from the GPU it finds (`auto`), or you choose one:

| Profile | GPU | Quantisation | Context | Needs |
|---|---|---|---|---|
| `l4` | L4 (recommended) | Q4_K_M | 32K | ~21 GB VRAM |
| `a100-40` | A100 40 GB | Q8_0 (near-full quality) | 64K | ~39 GB |
| `a100-80` | A100 80 GB, H100 | Q8_0 | 128K | ~78 GB |

**Thinking mode** (`/rv-start <profile> thinking`, or `THINKING` in the notebook) makes the model reason before
answering. It's slower and uses more compute units. Leave it off unless results are poor.

**Notebook settings.** The notebook form fields set these environment variables for `colab/serve.py`. You only need
the advanced ones for special cases:

| Variable | Default | Meaning |
|---|---|---|
| `RVKIT_PROFILE` | `auto` | `auto`, `l4`, `a100-40`, `a100-80` |
| `RVKIT_MODEL` | `abliterated` | `abliterated` (refusals removed) or `qwen` (mainstream) |
| `RVKIT_THINKING` | `0` | `1` for thinking mode |
| `RVKIT_API_KEY` | Colab secret `LLM_API_KEY`, else random | the endpoint's API key |
| `RVKIT_IDLE_MINUTES` | `30` | idle minutes before the runtime disconnects |
| `RVKIT_TUNNEL` | `auto` | `auto`, `cloudflare` or `ngrok` (`auto` uses ngrok when `NGROK_TOKEN` is set) |
| `RVKIT_DRIVE` | `1` | cache the llama.cpp build in Google Drive |
| `RVKIT_REBUILD` | | `1` forces a fresh llama.cpp build |
| `RVKIT_QUANT` | from the profile | e.g. `Q5_K_M` |
| `RVKIT_REPO`, `RVKIT_REVISION` | pinned | serve a different GGUF repo or revision |
| `RVKIT_LLAMA_TAG` | `b11840` | use another llama.cpp release |

**Tunnels.** By default the endpoint is published through a Cloudflare quick tunnel: no account needed, but the
URL changes every session, and Cloudflare cuts responses that take longer than about 100 seconds (error 524). For
long answers, or a URL that never changes, add Colab secrets `NGROK_TOKEN` (free ngrok account) and optionally
`NGROK_DOMAIN` (a free static domain). With a static domain, you only run `./rvkit connect` once.

The endpoint is on the internet, protected only by its API key. Keep the key secret and stop the runtime when
you're done.

`./rvkit connect <url> [key] [model]` remembers the Colab URL, key and model. After using another worker, `./rvkit
worker colab` switches back to the last Colab endpoint.

### Option 2: a local server on this machine

Run the model with Ollama, LM Studio, llama-server (llama.cpp) or vLLM, then:

```sh
./rvkit worker local
```

It looks for an OpenAI-compatible server on ports 11434 (Ollama), 1234 (LM Studio), 8080 (llama-server), 8001
and 5000, and uses the first model it finds. To set it yourself:

```sh
./rvkit worker local http://host.docker.internal:8080/v1 <model> [api-key]
```

- Use `host.docker.internal`, not `localhost`: LiteLLM runs in a container.
- **Linux:** the server must listen on an address containers can reach (`0.0.0.0` or the Docker bridge), not
  only `127.0.0.1`. For Ollama, set `OLLAMA_HOST=0.0.0.0`.
- Qwen3.8-27B needs about 24 GB of VRAM (or unified memory) at Q4. Give it at least 32K of context.

### Option 3: any OpenAI-compatible endpoint

For a GPU server, RunPod, Modal, vLLM or a hosted API with a fixed URL:

```sh
./rvkit worker api https://gpu.example.com/v1 <model-name> [api-key]
```

**Rented GPUs.** On RunPod, Vast.ai, Lambda or Modal, start a GPU (24 GB or more for Qwen3.8-27B) with vLLM,
llama.cpp's `llama-server` or Ollama, expose its OpenAI-compatible port with an API key, and point the worker at
it with the command above. Stop the GPU when you're done: these services bill by the hour.

### Option 4: no GPU at all (a hosted model on OpenRouter)

If you have no GPU and no Colab, the worker can be a hosted model through your OpenRouter key:

```sh
./rvkit worker openrouter                              # DeepSeek V4.1 Flash (the default)
./rvkit worker openrouter moonshotai/kimi-k2.6         # or another OpenRouter model
```

Like every OpenRouter call in the kit, it asks for zero-data-retention providers that don't collect prompts, and
its spend counts toward the daily budget (`./rvkit budget`). DeepSeek V4.1 Flash is cheap, uses tools well and
didn't refuse authorised pentest tasks in our tests; Kimi K2.6, Qwen3 235B and Mistral Large 4 also passed.

**The trade-off: tool output and client code then go to OpenRouter.** That includes engagements with
`Worker model: private` and the `riskvoid-local` agent: "private" means "only the worker you chose", and here
that worker is a cloud model. For work where nothing may leave your machine, use Option 2.

Every `worker` command recreates LiteLLM and sends a test prompt.

### Which model

| Choice | Served as | Weights | Notes |
|---|---|---|---|
| **Abliterated** (default, `abliterated`) | `qwen38-27b-obl` | `huihui-ai/Huihui-Qwen3.8-27B-abliterated-GGUF`, a community build with refusals removed | refuses fewer tasks; a third-party modification |
| **Qwen3.8-27B** (`qwen`) | `qwen38-27b` | `lmstudio-community/Qwen3.8-27B-GGUF`, Qwen's weights unchanged (Apache-2.0) | may refuse some offensive-security tasks |

Both repos are pinned to a commit, so a re-upload can't change what runs. The abliterated build will not refuse
harmful requests: you are responsible for how you use it ([SECURITY.md](../SECURITY.md#responsible-use)).

### Worker limits

| Limit | Value |
|---|---|
| Tasks at a time | one by default (`WORKER_PARALLEL_TASKS`): Colab handles one request at a time, so delegated tasks queue. Raise it for an endpoint that serves parallel requests |
| Tool calls per task | `max_steps`, 15 by default, 1–40 |
| Time per task | `timeout_min`, 30 by default, 1–180 minutes |
| Context | about 90,000 characters (~25K tokens, fits the L4 profile's 32K). Older tool outputs are shrunk to keep within it; each step's full output is saved in `/work/<engagement>/evidence/tasks/<task_id>/step-NN-<tool>.txt` |
| Tool output shown to the model | 6,000 characters per call; the rest is in the step file |

The planner sets `max_steps` and `timeout_min` per task. Each task's state is saved next to its evidence
(`evidence/tasks/<task_id>/task.json`), so results survive a `worker-mcp` restart. A task that was running during
the restart shows as `interrupted`, with its partial evidence kept.

## When the worker is down: the fallback

By default, worker calls fail while the worker endpoint is down (Colab stopped, tunnel expired). Nothing is sent
anywhere else, and the planner tells you to start the worker. For small checks, the planner can run the Kali
tools itself in the meantime.

If you turn the fallback on, worker calls go to an OpenRouter model instead while the endpoint is down:

```sh
./rvkit worker fallback on                         # DeepSeek V4.1 Flash (default)
./rvkit worker fallback moonshotai/kimi-k2.6       # turn it on with another OpenRouter model
./rvkit worker fallback off                        # back to the default
./rvkit worker show                                # endpoint and fallback state
```

**While the fallback is in use, that model sees tool output and client code.** Only zero-data-retention providers
are used, but check it against your client agreements before turning it on. DeepSeek V4.1 Flash is cheap, uses
tools well and didn't refuse authorised pentest tasks in our tests; Kimi K2.6, Qwen3 235B and Mistral Large 4
also passed. When a delegated task was served by the fallback, the task result names that model.

`./rvkit status` and `./rvkit doctor` show a warning while the fallback is on.

### Keeping one client off the fallback

To keep one client's data off cloud models even with the fallback on, answer **yes** to "Keep this client's tool
output on the worker endpoint only" in `./rvkit new`, or add this line to the engagement's `RULES.md` and apply it
with `./rvkit scope <engagement> --yes`:

```
- Worker model: private
```

Delegated tasks for that engagement then use `private-llm`, which never falls back: they fail instead. The
`riskvoid-local` agent never uses the fallback either.

## The planner

```sh
./rvkit planner                                             # show the planner and its fallback
./rvkit planner openai/gpt-6.1-sol                          # change the planner
./rvkit planner openai/gpt-6.1-sol deepseek/deepseek-v4-pro  # change both
./rvkit test planner                                        # send a test prompt
```

Models are OpenRouter ids; the `openrouter/` prefix is optional. The fallback is used when the planner errors (an
outage, a rate limit), refuses, or sends an empty reply. Choose a model that is good at long tool-using sessions
and doesn't refuse authorised security work. With the kit's planner prompt and a lab engagement brief, GPT-6.1,
DeepSeek V4 Pro and Gemini 3.1 Pro answered with a tool call, and Claude Sonnet 5.5 refused (November 2026). Check a
candidate with `python3 evals/planner_smoke.py`. The fallback should come from another vendor, so a rate limit on
one doesn't stop both.

Without `OPENROUTER_API_KEY` in `.env`, the planner doesn't work: use `riskvoid-local`, or add the key and run
`./rvkit up`.

### Anthropic or OpenAI directly

If you have an Anthropic or OpenAI API account and don't want OpenRouter in between:

```sh
./rvkit planner --direct anthropic/claude-opus-5-5                         # planner on Anthropic
./rvkit planner --direct anthropic/claude-opus-5-5 openai/gpt-6.1          # fallback on OpenAI
./rvkit planner --direct anthropic/claude-opus-5-5 openrouter/openai/gpt-6.1-sol   # mix: fallback on OpenRouter
```

Model ids use LiteLLM's names (`anthropic/<model>`, `openai/<model>`). If `ANTHROPIC_API_KEY` or `OPENAI_API_KEY`
isn't in `.env` yet, the command asks for it (hidden input). To go back to OpenRouter, run `./rvkit planner
<openrouter-model>` again.

What changes:

- **Data terms.** OpenRouter calls ask for zero-data-retention providers only. A direct call follows that
  provider's own API terms (for example, API data isn't used for training, but may be kept for a while for abuse
  monitoring). Zero retention needs an agreement with the provider. Check this against your client agreements.
- **Budget.** The daily budget (`./rvkit budget`) applies to each provider separately. Anthropic gets a provider
  budget. OpenAI gets a budget on each planner model instead, because the worker is also an OpenAI-style endpoint
  and a provider budget would block it too. `./rvkit budget` and the console show OpenRouter and Anthropic
  spend, but not spend on a direct OpenAI model.
- The worker and its fallback are unchanged.

## When a model call fails

OpenHands always streams model replies. A refusal arrives inside a reply that has already started, so LiteLLM's own
fallback can't catch it. The kit's LiteLLM callback (`litellm/rv_events.py`) closes that gap and makes failures
visible:

- **Refusals and empty replies use the fallback.** It holds back each streamed reply until real text or a tool call
  arrives. If the model refuses or sends nothing, the fallback model (`planner-fallback`, or `colab-qwen-fallback`
  when the worker fallback is on) answers instead. A rate-limited fallback is retried twice.
- **The reason shows in the chat.** When no model answers, the agent's reply is a short `[RiskVoid] ...` message
  that says what happened and what to do, instead of an empty reply. Errors reach OpenHands with the same kind of
  explanation:

  | Problem | What the message tells you to do |
  |---|---|
  | OpenRouter balance too low (402) | top up at openrouter.ai/settings/credits |
  | Daily budget used up | `./rvkit budget <usd>`, or wait for the next UTC day |
  | API key rejected | check the key in `.env`, then `./rvkit up`; for the worker, run the `./rvkit connect` line again |
  | Worker not reachable (Colab stopped, tunnel changed) | `/rv-start`, or `./rvkit worker` |
  | Rate limit, timeout | wait a minute and continue the conversation |
  | Context window full | start a new conversation for the next step |
  | Refused by the model and its fallback | rephrase with the engagement context, or `./rvkit planner <model> [fallback]` |

- **Every problem is logged** to `.rvkit/events/model-events.jsonl` on this machine. These show it:
  - the console's **Model log**: each engagement's tab, and a page with every call. The kit matches a call to an
    engagement from the engagement its tool calls name, or from the brief;
  - `./rvkit status` (the last hour);
  - `./rvkit doctor` (the last 24 hours);
  - `./rvkit watch`, which also raises a desktop notification.

  To read the log yourself: `python3 scripts/model_events.py --since 3600`. A problem another model recovered from is
  marked "recovered".

## Costs and budget

**OpenRouter.** Spend on OpenRouter (the planner, plus the worker fallback when it's on) is capped per 24 hours.
The default is **$20**. The same cap applies separately to Anthropic or OpenAI when the planner uses them
directly ([above](#anthropic-or-openai-directly)).

```sh
./rvkit budget            # the cap and what's been spent in the current period
./rvkit budget 50         # change the cap
```

Over the cap, OpenRouter calls fail with a budget error until the period ends. The spend counter is kept in the
`redis` service on a volume, so restarting the stack or changing models doesn't reset it. `./rvkit status` shows
spend against the cap. To see what a typical run costs with your models, run a benchmark (`./rvkit bench
smoke`): it reports the OpenRouter cost ([Lab and benchmarks](lab-and-benchmarks.md)).

`./rvkit doctor` doesn't call the planner (it costs a fraction of a cent); `./rvkit doctor --models` does.

**Colab.**

| GPU | Model quality | Speed | Compute units/hour* | Hours from 200 units |
|---|---|---|---|---|
| **L4** (recommended) | Q4, 32K context | ~15–20 tok/s | ~1.7 | ~115 |
| A100 40 GB | Q8 (near-full quality), 64K | ~35–50 tok/s | ~5.4 | ~37 |
| A100 80 GB | Q8, 128K | fast | ~7.5 | ~27 |

\*Community measurements (March 2026). Check Colab's usage meter during your first session.

To save units: stop the runtime when you're done (or let the 30-minute idle shutdown do it), keep thinking mode
off, and use the L4 unless you need the longer context.

## Where your data goes

| Part | Sees | Where it runs |
|---|---|---|
| Worker model (`colab-qwen`, `private-llm`) | tool output, client code, evidence | **Colab** (default): processed by Google on your Colab account. **Local / your own endpoint**: stays with you |
| Worker fallback (off by default) | the same as the worker, while the endpoint is down | OpenRouter, zero-data-retention providers only |
| Planner (`riskvoid-planner` agent) | task descriptions, the worker's redacted summaries, findings, files it chooses to open | OpenRouter, zero-data-retention providers only; or Anthropic / OpenAI directly under their API terms (`--direct`) |
| Web search and page fetch (`web` tool) | search queries, public URLs | SearXNG's upstream search engines; the public site |
| Vulnerability intel, package installs | CVE and package ids, package names | NVD, EPSS, CISA KEV, OSV; package registries (through the egress proxy) |
| Everything else (findings, evidence, audit log, reports) | everything | your machine |

For work where nothing may leave your machine: run the worker on a local or self-hosted endpoint (`./rvkit worker
local|api`), use the `riskvoid-local` agent, keep the fallback off, and set the engagement to `offline` if package
and vulnerability-database lookups must not happen either.

The planner can open any file it chooses, including client code, so "the planner never sees client code" is not a
guarantee with `riskvoid-planner`. Secret redaction in the worker's summaries is pattern-based: treat it as a safety
net, not a guarantee.

## See also

[Getting started](getting-started.md) · [Configuration](configuration.md) · [Architecture](architecture.md) ·
[Troubleshooting](troubleshooting.md)
