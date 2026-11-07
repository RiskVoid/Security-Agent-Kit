# Troubleshooting and FAQ

Start with **`./rvkit doctor`**. It checks Docker, memory, disk, settings, every service, the MCP servers, the
sandbox firewall, the agent's network lockdown and the worker endpoint, and says what to fix. Then look up the
symptom below.

## Setup and the stack

| Symptom | Cause and fix |
|---|---|
| `Docker is not running` / `Docker Compose v2 is missing` | Start Docker Desktop, OrbStack or Docker Engine; update Docker if `docker compose version` fails. |
| `port is already allocated` | Another app uses 8000, 4000 or 8888. Set `GATEWAY_PORT`, `LITELLM_PORT` or `SEARXNG_PORT` in `.env` and run `./rvkit up` ([operations.md](operations.md#ports)). |
| `setup` is slow the first time | It pulls about 18 GB of images, or builds them (about 10 minutes) if they aren't published for your version. Later starts take seconds. |
| A service keeps restarting | `./rvkit logs <service>`. For `kali-mcp`, check that Docker allows `NET_ADMIN` / `SYS_ADMIN` (rootless Docker and some Linux security policies don't). |
| OpenHands doesn't start; its log says `Can't locate revision` | Its data volume was used by a newer OpenHands. Set `AGENT_CANVAS_TAG` in `.env` to that version, then `./rvkit up`. |
| `OpenHands configuration failed` | Run `./rvkit openhands` to see the error. Usually OpenHands wasn't up yet: run it again a minute later. |
| `MCP servers: <name>: …` in doctor | That server is down or slow to start: `./rvkit logs <name>-mcp`, then `./rvkit up`. |
| `Kali scope firewall not loaded` | `./rvkit logs kali-mcp`. The container needs `NET_ADMIN`. Restart it: `docker compose restart kali-mcp`. |
| `OpenHands container reached example.com` | The egress lockdown isn't working. Don't use the kit for client work until it's fixed; report it ([SECURITY.md](../SECURITY.md)). |
| The UI opens OpenHands' own onboarding | Open http://localhost:8000/ (the start page), not a deeper link. It marks the onboarding as done. |
| Docker memory warning | Give Docker 16 GB if you can (Docker Desktop / OrbStack settings). Joern and ZAP need memory. |

## Models

| Symptom | Cause and fix |
|---|---|
| `Worker model not reachable` | Colab: the session ended or the URL changed. Start it again (`/rv-start`, or the notebook) and run the `./rvkit connect …` line it prints. Local / API: `./rvkit worker` shows the endpoint; check the server is running. |
| Worker tasks fail with "worker model unreachable" | Same as above. The planner can still use the `kali` tool directly for small checks. |
| Colab says "No GPU" or the GPU is too small | Runtime → Change runtime type → L4 or A100, then run it again. A100s are sometimes unavailable. |
| The first Colab run takes 25–30 minutes | It builds llama.cpp once and caches it in your Drive. Approve the Drive popup, or every run rebuilds. Later runs take 3–6 minutes. |
| Error 524 or timeouts on long answers | Cloudflare quick tunnels cut responses that take over about 100 s. Use ngrok: add the Colab secret `NGROK_TOKEN` (free account) and optionally `NGROK_DOMAIN` (a free static domain, so the URL never changes). |
| `worker local` finds nothing | Start the server first. It looks on ports 11434, 1234, 8080, 8001 and 5000; otherwise give the URL: `./rvkit worker local http://host.docker.internal:<port>/v1 <model>`. On Linux the server must listen on `0.0.0.0`. |
| Planner calls fail with "crossed budget" | The daily OpenRouter budget is used up: `./rvkit budget <usd>`, or wait for the period to end. |
| Planner calls fail with "requires more credits" | Top up your OpenRouter balance. |
| `Model 'planner' not reachable` | Check `OPENROUTER_API_KEY` in `.env` (then `./rvkit up`) and `./rvkit logs litellm`. |
| The worker refuses an authorised task | The mainstream model sometimes refuses offensive-security steps. Rephrase the goal with the engagement context, let the planner use the `kali` tool directly, or (your call) use the abliterated build: `/rv-start abliterated` ([models.md](models.md)). |

## The agent

| Symptom | Cause and fix |
|---|---|
| The agent chats but doesn't use tools | `./rvkit openhands` (it tests every tool server), then start a **new** conversation. Check the agent selected is `riskvoid-planner` or `riskvoid-local`. |
| A conversation shows connection errors after a restart | Start a new conversation for the same engagement. Its plan, findings and evidence are on disk ([running-the-agent.md](running-the-agent.md)). |
| `unknown engagement` | The engagement wasn't created with `./rvkit new` / `engagement`, or the name is misspelt. `./rvkit eng list`. |
| `REFUSED: targets not in scope` | The target isn't in the engagement's active scope. Add it to `SCOPE.md`, then `./rvkit scope <eng>` and `--yes`. Editing the file alone has no effect. |
| `REFUSED: this command is tier 'X', RULES.md allows only …` | Raise the allowed tiers in `RULES.md` and apply with `./rvkit scope <eng> --yes`, or ask for a lower-tier approach. |
| `APPROVAL REQUIRED` | Approve with `./rvkit watch` or `./rvkit approve <eng> <id>`, then tell the agent to run it again with the approval id. |
| `approval was for a different command` | The agent changed the command. Approvals match the exact text; approve the new request instead. |
| `approval expired (24 h)` | Approvals must be used within 24 hours. Ask the agent to request it again. |
| `engagement is halted` | `./rvkit resume <eng>` (closed engagements are halted too). |
| `outside the testing window` | `Window (UTC)` in `RULES.md` doesn't include now. Times are UTC. |
| `exceeds the engagement max rate` | The command set a rate above `Max rate` in `RULES.md`. Remove the flag (the kit adds the max) or raise the limit. |
| A Kali command can't resolve or reach a host that is in scope | Check `./rvkit show <eng>` (was the entry ignored? IPv6 isn't supported). Domains resolve through the engagement's own DNS; hosts reached only by IP need the IP or CIDR in scope. |
| Package downloads fail inside a Kali command | The engagement is `Network: offline`, or the site isn't an infrastructure domain ([configuration.md](configuration.md#other-files-you-can-change)). |
| The agent can't install a package in its own terminal | Its container has no direct internet. Add the domain to `EGRESS_EXTRA_DOMAINS` in `.env`, then `./rvkit up`. |
| `fetch` refuses a URL | The web tool never fetches engagement targets or private addresses. Test targets with the `kali` tool. |
| The agent can't write a file in `/work` | Its workspace sees `/work` read-only by design. It writes plan, notes and report text with the findings `write_file` tool; tool output comes from Kali commands. |
| Output was cut off | Kali output over 30,000 characters is saved to `out-<time>.txt` in the engagement folder; the agent should read that file. |
| `TIMEOUT after 600s` | Long scans need a longer `timeout_s` (up to 3600) or a smaller scope per command. |

## Reports

| Symptom | Cause and fix |
|---|---|
| The report says **DRAFT** | Its first page lists why: no executive summary, untriaged candidates, missing client name, or evidence that is missing, modified or not produced by an audited Kali command. Fix those and regenerate ([findings-and-reports.md](findings-and-reports.md)). |
| `PDF conversion failed` | The `.docx` is fine; LibreOffice failed. `./rvkit logs findings-mcp`, then try `./rvkit report <eng>` again. |
| A brand error stops the report | `REPORT_BRAND=custom` needs a valid `brand.json` in `REPORT_BRAND_FOLDER`; the message says what to fix. |
| "Prepared by" shows the old name | `report/meta.txt` is created on the first report with the brand's name. Edit it. |
| `generate_report` times out in the agent | It takes about a minute. Run `./rvkit report <eng>` yourself. |

## FAQ

**Can I use it without a GPU?**
Yes. Without a worker the planner runs Kali tools itself (the `kali` tool), which works for small engagements and
the practice lab. You can also point the worker at a hosted OpenAI-compatible endpoint (`./rvkit worker api`) or
turn on the OpenRouter fallback, keeping in mind that model then sees tool output and code ([models.md](models.md)).

**Can I use it without OpenRouter?**
Yes: use the `riskvoid-local` agent, which runs everything on your worker model. Results are weaker with a 27B
model than with a frontier planner.

**Does client data leave my machine?**
It depends on your model choices: see the data table in [models.md](models.md). For "nothing leaves", use a local
worker, the `riskvoid-local` agent, the fallback off, and `Network: offline` engagements.

**Can the agent attack something that isn't in scope?**
Kali commands can only reach what's in the engagement's active scope (firewall plus per-engagement DNS), and only
you can change the scope. The agent's own container has no direct internet. Known gaps are listed in
[SECURITY.md](../SECURITY.md#known-limitations); the main one is that scripts (passive tier) and `curl`
(active tier) can send intrusive traffic without approval, against in-scope hosts only.

**Can I run several engagements at the same time?**
Yes. Each has its own sandbox user, firewall chain and DNS. Worker tasks run one at a time by default, so parallel
conversations queue on the worker (`WORKER_PARALLEL_TASKS` raises it for endpoints that allow it).

**Can several people use one installation?**
It's built for one operator: the UI and ports are on `127.0.0.1`, there are no user accounts, and approvals don't
record who approved. Each consultant should run their own copy.

**Can I use another agent UI instead of OpenHands?**
The tools are standard MCP servers on the internal network, so another MCP client inside that network could use
them, but only OpenHands is configured and tested.

**Where are my conversations?**
In the `openhands-data` Docker volume. The engagement folder holds what matters for the record: plan, notes,
findings, evidence, audit extract and report.

**How do I report a vulnerability in the kit?**
Privately, through GitHub: [SECURITY.md](../SECURITY.md#reporting-a-vulnerability).

---

See also: [operations.md](operations.md), [cli-reference.md](cli-reference.md).
