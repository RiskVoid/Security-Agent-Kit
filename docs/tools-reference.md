# Tools reference

Everything the agents can call: the five MCP servers and their tools, the worker model's own tools, the Kali
toolbox with each program's tier, the kit's own helpers, and the methodology playbooks. Use it to understand what
the agent did, to write better task prompts, or to extend the kit.

## MCP servers at a glance

| Server | Container, port | Who uses it | For |
|---|---|---|---|
| `kali` | `kali-mcp:8090` | planner, worker, report generator | running tools in the engagement sandbox; scope, activity and evidence checks |
| `worker` | `worker-mcp:8091` | planner (`riskvoid-planner` only) | handing focused tool work to the worker model |
| `findings` | `findings-mcp:8092` | planner | findings, playbooks, writing engagement files, the report |
| `intel` | `intel-mcp:8093` | planner, worker | vulnerability intelligence (OSV, NVD, EPSS, CISA KEV) |
| `web` | `web-mcp:8094` | planner | web search and public page fetch |

`riskvoid-local` gets every server except `worker`. All of them are configured in OpenHands by
`./rvkit openhands` (see [architecture.md](architecture.md#configuration-plumbing)).

## `kali`: the Kali sandbox

| Tool | Parameters | What it does |
|---|---|---|
| `list_engagements` | none | Every registered engagement with its active scope (networks, domains, code paths), rules (tiers, max rate, network, testing window) and `HALTED` flag. The planner calls it first. |
| `engagement_info` | `engagement` | The same for one engagement as JSON, plus its uid and the infrastructure domains it may reach (online engagements). |
| `all_scopes` | none | The union of every engagement's networks and domains. `web-mcp` uses it to refuse fetching targets. |
| `run` | `command`, `engagement`, `timeout_s` (default 600, max 3600), `approval_id` | Runs a shell command in the engagement's sandbox. Returns `exit=<code> tier=<tier>` and the output, or `REFUSED: <reason>`, or `APPROVAL REQUIRED` with an approval id. |
| `evidence_provenance` | `engagement`, `paths` | For each evidence file: current SHA-256 and status: `verified` (with the producing command, time, tier, exit code), `MODIFIED after it was produced`, `not produced by an audited kali command`, `missing`, or `not an engagement file` (a path outside the engagement folder). |
| `engagement_activity` | `engagement` | Summary of the audit log: time range, commands run and refused, counts per tier and per tool, evidence files, approvals, halts and scope changes. The report's methodology section uses it. |

What `run` does, in order: refuses if the engagement is halted or outside its testing window; classifies the
tier and refuses it if `RULES.md` doesn't allow it; refuses obvious out-of-scope hosts in network-tool commands;
asks for approval if the command is intrusive; adds the rate flag; runs the command sandboxed as the engagement's
user; hashes every file it created or changed. Details: [architecture.md](architecture.md#how-one-task-flows)
and [engagements.md](engagements.md).

Output notes:

- The working directory is `/work/<engagement>/`. Client code in scope is at `/src/<repo>/`, read-only.
- The result starts with `exit=<code> tier=<tier>`. If the rate flag was added, the next line is
  `[rate limit applied: <final command>]`.
- With `timeout_s` over 1,800, call it through the worker: OpenHands stops waiting for a direct kali call after
  30 minutes.
- Files the command wrote are listed at the end: `[evidence recorded: …]`.
- The full output is always saved and hashed as `/work/<engagement>/evidence/runs/<time>-<program>-<id>.txt`; the
  last line is `[output saved as verified evidence: <path>]`. Cite that path as evidence.
- Output over 30,000 characters is cut in the result; the saved file has all of it.
- A command that runs past `timeout_s` is killed and returns `TIMEOUT after <n>s` with the last output.

## `worker`: delegation to the worker model

| Tool | Parameters | What it does |
|---|---|---|
| `delegate_task` | `goal`, `engagement`, `tier` (`passive` default, `active`, `intrusive`), `max_steps` (default 15, 1–40), `timeout_min` (default 30, 1–180), `wait_s` (default 240, max 600) | Starts one focused task on the worker model. Refuses if the engagement is halted or the tier isn't allowed by `RULES.md`. Returns the result, or a `task_id` with a note if it's still running after `wait_s`. |
| `get_task` | `task_id`, `wait_s` (default 240, max 600) | Waits for a task and returns its result. |
| `list_tasks` | `engagement` (optional) | Saved tasks, newest first (up to 50), including those from before a worker restart. |

A result has: `task_id`, `status` (`queued`, `running`, `done`, `error`, `interrupted`), `elapsed_s`, the `commands` it ran, the
`candidate_findings` it recorded, the `evidence_dir`, the `model` that served it (shows when the fallback model
was used) and `result` (`summary`, `observations`, `open_questions`, `confidence`). Secrets are redacted from it.

Things to know:

- **One task at a time** by default: Colab handles one request at a time, so later tasks queue. Raise
  `WORKER_PARALLEL_TASKS` in `.env` for an endpoint that serves parallel requests.
- **Tasks survive restarts.** Each task's state is saved in `/work/<engagement>/evidence/tasks/<task_id>/task.json`,
  next to every step's full output (`step-NN-<tool>.txt`) and the whole exchange (`transcript.jsonl`). A task that
  was running when `worker-mcp` restarted shows as `interrupted`; delegate it again to finish it.
  `list_tasks(engagement)` lists one engagement's tasks, newest first.
- **Private engagements.** With `Worker model: private` in `RULES.md`, the task runs on `private-llm`, which
  never falls back to OpenRouter. See [models.md](models.md).
- If the worker model can't be reached, the task ends with `error: worker model unreachable …`. The planner then
  tells you to start it, or runs small checks with the `kali` tool itself.

### The worker model's own tools

Inside a task, the worker model has these tools (they aren't MCP tools; `worker-mcp` implements them):

| Tool | What it does |
|---|---|
| `kali_run` | `command`, `timeout_s` (default 600, max 3600): calls the kali `run` tool for the task's engagement. Same checks, same audit log. An intrusive command makes it stop and report the approval id. |
| `vuln_intel` | `ids`: ranks up to 50 vulnerability ids with the intel `prioritize` tool. |
| `web_search` | `query`: SearXNG search through `web-mcp`, 8 results. |
| `fetch_url` | `url`: reads a public page as text through `web-mcp`. Refuses every engagement's targets and non-public addresses, on every redirect too. |
| `read_file` | `path`, `start` (default 1), `lines` (default 200, max 500): numbered lines of a file under the engagement's in-scope code paths or its engagement folder. Nothing else. |
| `record_candidate` | `title`, `severity`, `asset`, `description`, `evidence`, `cwe`: stores a **candidate** finding (source `worker:<task_id>`). Only the planner can confirm it. |
| `finish` | `summary`, `observations`, `open_questions`, `confidence`: ends the task. |

Each tool output is cut to 6,000 characters in the model's context (the full output is in the step file), and the
oldest outputs are shrunk when the conversation passes about 90,000 characters, so a task fits the 32K context of
the L4 profile.

## `findings`: findings, playbooks, files and the report

| Tool | Parameters | What it does |
|---|---|---|
| `record_finding` | `engagement`, `title`, `severity`, `asset`, `description`, and optional `impact`, `reproduction`, `remediation`, `evidence` (list of paths), `cvss_vector`, `cvss_score`, `cwe`, `status` (`candidate` by default; any of the five statuses is accepted), `notes` | Stores a finding and returns it with its id (`F-001`, `F-002`, …). Severity: `critical`, `high`, `medium`, `low`, `info`. |
| `update_finding` | `engagement`, `finding_id`, then any field to change, including `status` | Changes only the fields given. Statuses: `candidate`, `confirmed`, `false-positive` (reason in `notes`), `duplicate` (needs `duplicate_of`: the finding to keep), `fixed`, `accepted-risk`. |
| `list_findings` | `engagement`, optional `status`, `severity` | Findings, most severe first: id, title, severity, status, asset, source. |
| `get_finding` | `engagement`, `finding_id` | One finding with every field. |
| `write_file` | `engagement`, `path`, `content`, `append` (default false) | Writes one of: `PLAN.md`, `NOTES.md`, `notes/<name>.md` or `.txt`, `report/executive-summary.md`, `report/methodology.md`, `report/conclusion.md`, `report/meta.txt`. Anything else, or content over 1 MB, is refused. |
| `list_playbooks` | none | Each playbook's name, title, standard and tiers. |
| `get_playbook` | `name` | The full text of one playbook. |
| `generate_report` | `engagement` | Builds the `.docx`, PDF and findings register `.xlsx` in `/work/<engagement>/report/`. Returns the paths, `DRAFT` or `final`, the issues that keep it a draft, and how many findings were included and left out. Takes about a minute. |

Findings are stored per engagement in `/work/<engagement>/findings.db` (SQLite). The report includes `confirmed`,
`fixed` and `accepted-risk` findings. More: [findings-and-reports.md](findings-and-reports.md).

## `intel`: vulnerability intelligence

| Tool | Parameters | What it does |
|---|---|---|
| `vuln_lookup` | `ids` (up to 25: CVE, GHSA, PYSEC or any OSV id) | Summary, aliases, fixed versions (OSV), CVSS vector, score, severity and CWE (NVD), EPSS probability and percentile, CISA KEV status, date added, ransomware use and required action. |
| `prioritize` | `ids` (up to 50) | The same ids ranked by real-world risk: known exploited (KEV) first, then EPSS, then CVSS. Aliases of the same CVE are merged. |
| `package_vulns` | `ecosystem`, `name`, `version` | Known vulnerabilities of one package version from OSV, with fixed versions. Ecosystems: `PyPI`, `npm`, `Go`, `Maven`, `RubyGems`, `crates.io`, `NuGet`, `Packagist`, `Debian`, `Alpine`, … |
| `kev_search` | `query` | CISA KEV entries matching a vendor, product or keyword, newest first (up to 30). |

Only vulnerability ids and package names and versions leave your machine. Responses are cached for 24 hours (the
KEV feed for 12). Set `NVD_API_KEY` in `.env` to raise NVD's rate limit ([configuration.md](configuration.md)).

## `web`: search and fetch

| Tool | Parameters | What it does |
|---|---|---|
| `web_search` | `query`, `max_results` (default 8, 1–20) | Searches through the kit's own SearXNG. Returns title, URL and snippet per result. |
| `fetch` | `url`, `start` (default 0), `max_chars` (default 20,000, 500–100,000) | Reads a public `http(s)` page as text (HTML stripped). For long pages it says how to continue with `start`. |

`fetch` refuses any host in any engagement's scope and any host that resolves to a non-public address (the kit's
services, the lab, cloud metadata), and checks again on every redirect. If it can't read the engagement scopes from
`kali-mcp`, it refuses everything. Its requests aren't in the audit log. Test targets with the `kali` tool instead.

## The Kali toolbox

Every program below is installed in the `kali-mcp` image and runs through `run`. **Tier** is what `run` assigns
from the program name; a command line with several programs gets the highest tier among them. Programs not listed
as active or intrusive are passive. **Rate flag** is the option `run` adds with the engagement's max rate when
the command doesn't set it; a command that sets a higher value is refused.

### Recon

| Program | Tier | Rate flag |
|---|---|---|
| `nmap` | active; intrusive with `--script` matching `brute`, `dos`, `exploit`, `intrusive` or `vuln` | `--max-rate` |
| `naabu` | active | `-rate` |
| `amass` | active | |
| `katana` | active | `-rl` |
| `httpx-toolkit` | active | `-rl` |
| `whatweb` | active | |
| `gowitness` (with Chromium) | active | |
| `nc`, `ping` | active | |
| `dnsx`, `subfinder`, `dig`, `whois` | passive | |

### Web

| Program | Tier | Rate flag |
|---|---|---|
| `nuclei` (templates in `~/nuclei-templates`) | active; intrusive with `-tags` / `-itags` / `-t` naming `intrusive`, `dos`, `fuzz` or `brute`, or with `-dast` / `-fuzz` | `-rl` |
| `nikto`, `wafw00f`, `wpscan`, `arjun`, `crlfuzz` | active | |
| `ffuf` | active | `-rate` |
| `feroxbuster` | active | `--rate-limit` |
| `gobuster` | active | |
| `testssl`, `sslscan` | active | |
| `zaproxy` | intrusive (spider and active scan send attack payloads) | |
| `sqlmap`, `commix`, `dalfox` | intrusive | |
| `curl`, `wget` | active | |

### API

| Program | Tier | Rate flag |
|---|---|---|
| `schemathesis` / `st` | intrusive (sends malformed and state-changing requests) | `--rate-limit <n>/s`, after `run` |
| `jwt_tool` | passive offline (decode, crack, forge); active with `-t <url>`; intrusive with `-t` plus `-X`, `-I`, `-S` or `-M` | |
| `graphw00f`, `graphql-cop`, `clairvoyance` | active | |

### AI, LLM and MCP

| Program | Tier | Rate flag |
|---|---|---|
| `rv-llm probe`, `rv-llm mcp-call` | intrusive | `--rate` (probe only) |
| `rv-llm ask`, `rv-llm mcp` | active | |
| `rv-llm payloads`, `rv-llm list`, `rv-llm help` | passive | |
| `garak` | intrusive | |

### Code and secrets

| Program | Tier |
|---|---|
| `semgrep` (registry configs such as `p/python` when online; local rules in `/opt/semgrep-rules`) | passive |
| `bandit`, `gitleaks`, `trufflehog` | passive |
| `rv-joern` (Joern data-flow analysis) | passive |

### Supply chain

| Program | Tier |
|---|---|
| `osv-scanner`, `pip-audit`, `trivy` (fs, config, secret), `syft` (SBOM), `grype` | passive |

Also available: `python3`, `git`, `jq`, `curl`, `wget`, `unzip` and the usual shell tools. Scripts and
interpreters are classified by program name too, so `python3 exploit.py` runs at the passive tier and a `curl`
with a payload at the active tier, without approval. The firewall still limits them to the scope. This is a known
limitation: [SECURITY.md](../SECURITY.md#known-limitations).

### Data in the image

| Path | Contents |
|---|---|
| `/usr/share/seclists` | SecLists wordlists |
| `~/nuclei-templates` | nuclei community templates, pinned to release `v10.5.1` (a link in each engagement's home) |
| `/opt/semgrep-rules` | Semgrep community rules at a pinned commit, downloaded on first start of `kali-mcp` (not in the image, for licence reasons). Use them for offline engagements: `semgrep --config /opt/semgrep-rules/<lang>` |

Online engagements may also reach the infrastructure domains in `kali-mcp/infra_domains.txt` (rule packs,
package registries, vulnerability databases) on TCP 80/443. Offline engagements reach none of them, so tools that
download databases on first use (`grype`, `trivy`, registry configs of `semgrep`) won't work there.

## The kit's own helpers

### `rv-llm`: LLM applications, agents and MCP servers

A standard-library Python tool for testing chatbots, RAG apps, agents and MCP servers. `rv-llm help` prints the
full usage.

| Command | Tier | What it does |
|---|---|---|
| `rv-llm probe <target> [--suite S[,S]] [--rate N] [--out F.jsonl]` | intrusive | Runs the probe library. Suites: `injection`, `leak`, `jailbreak`, `output`, `exfil`, `tools`, `dos` (default: all except `dos`). |
| `rv-llm ask <target> "prompt" [--repeat N]` | active | One prompt; `--repeat` checks consistency. |
| `rv-llm mcp <url> [--header …]` | active | Enumerates and audits an MCP server (streamable HTTP or SSE). |
| `rv-llm mcp-call <url> <tool> '<json-args>' [--header …]` | intrusive | Calls one MCP tool. |
| `rv-llm payloads [--canary C] [--exfil-url U]` | passive | Indirect prompt-injection payloads to plant in content the target reads. |
| `rv-llm list` | passive | The probes with their OWASP LLM Top 10 ids. |

Targets for `probe` and `ask`:

- `--openai URL --model NAME [--key-env VAR]`: an OpenAI-compatible chat API (URL is the base, e.g. `http://h/v1`);
- `--http URL --body JSON [--reply PATH]`: any JSON chat endpoint. `{{prompt}}` in `--body` is replaced by the
  probe; `--reply` is the dotted path to the answer (e.g. `data.reply`);
- `--header "K: V"` (repeatable) for cookies and tokens, and `--system-file F` with the app's system prompt if you
  have it (better leak checks).

Every probe carries a random canary. Verdicts: `HIT` (canary or leak marker found), `REVIEW` (suspicious, judge it
yourself), `MISS`. A HIT is a lead, not a finding: confirm it by hand and record the evidence file.

### `rv-joern`: data-flow analysis

| Command | What it does |
|---|---|
| `rv-joern taint <src-dir> [out.json]` | Traces flows from untrusted input (HTTP parameters and bodies, environment, argv) to dangerous sinks (SQL, shell, deserialisation, eval, templates, files, HTTP, redirects). Writes them with the full path to `joern-flows.json` in the current directory. Heuristic: review every flow in the code. |
| `rv-joern scan <src-dir> [args]` | Joern's built-in query database (strongest for C/C++ and Java). |
| `rv-joern script <file.sc> [--param k=v …]` | Runs a custom Joern script. |

Languages are detected automatically: Python, Java, JavaScript/TypeScript, Go, C/C++, PHP, C#, Ruby, Kotlin, Swift,
Rust. Joern uses up to 4 GB of memory by default (`JAVA_OPTS`). The planner uses `taint` to confirm or rule out
injection candidates from semgrep.

### `jwt_tool`

The upstream `ticarpi/jwt_tool` at a pinned commit, started through a small wrapper so it runs on Python 3.13+.
Its behaviour is unchanged. The tier depends on the flags (see [API](#api)).

## Playbooks

Playbooks are the methodology the planner follows. It calls `list_playbooks`, reads every playbook that matches
the scope with `get_playbook`, copies their checklists into `PLAN.md` adapted to the targets, ticks items off as
it goes (marking skipped ones with the reason), and treats each playbook's **Done when** section as the exit bar.

| Name | Title | Standard | Tiers |
|---|---|---|---|
| `code-review` | Source code security review | OWASP ASVS 5.0 (level 2 by default; level 3 if the client asks) | passive |
| `web-app` | Web application test | OWASP WSTG 4.2 | passive, active; intrusive steps need approval |
| `api-security` | API security test (REST, GraphQL) | OWASP API Security Top 10 2023, OWASP WSTG (APIT) | passive, active; fuzzing and exploitation are intrusive (approval) |
| `ai-llm` | AI application, agent and MCP security test | OWASP Top 10 for LLM Applications 2025, OWASP Agentic AI threats, MITRE ATLAS | passive, active; adversarial prompts and tool calls are intrusive (approval) |
| `external-network` | External network assessment | PTES (intelligence gathering, vulnerability analysis); CIS-style service hardening | passive, active; intrusive steps need approval |
| `supply-chain` | Dependency and supply-chain review | OWASP Top 10 A06 (vulnerable components), SLSA / OpenSSF Scorecard concepts | passive |
| `secrets-review` | Secrets review | OWASP ASVS V13.3 (secret management), CWE-798 | passive |

You can steer the choice in your prompt ("follow the api-security playbook, GraphQL parts only"). See
[running-the-agent.md](running-the-agent.md).

### Adding your own playbook

1. Write `harness/playbooks/<name>.md` with front matter and numbered phases:

   ```markdown
   ---
   title: Mobile backend review
   standard: OWASP MASVS (network and backend parts)
   tiers: passive, active
   ---
   # Mobile backend review

   ## 1. Discovery (active)
   - [ ] `httpx-toolkit -l hosts.txt -json -o httpx.json`
   ...

   ## Findings
   How to group and write up findings for this kind of test.

   ## Done when
   What must be true before this part is finished.
   ```

   `list_playbooks` reads `title`, `standard` and `tiers` from the front matter. Give exact commands as they run
   in the sandbox, and check every flag against the installed tool version.
2. The playbooks are copied into the `findings-mcp` image, not mounted, so rebuild it:

   ```sh
   RVKIT_BUILD=1 ./rvkit up
   ```

   (`docker compose up -d --build findings-mcp` rebuilds only that service.)
3. Start a new conversation: the planner sees the new playbook in `list_playbooks`. Add it to the planner
   prompt's list in `prompts/planner.md` too (then `./rvkit openhands`) so it's considered by name.

[CONTRIBUTING.md](../CONTRIBUTING.md#adding-a-playbook) has the full conventions.

## Adding a Kali tool

In short (details in [CONTRIBUTING.md](../CONTRIBUTING.md#adding-a-tool-to-the-kali-image)):

1. Install it in `kali-mcp/Dockerfile`, pinned, readable by the engagement users and linked into `/usr/local/bin`.
2. Put its program name in `INTRUSIVE` or `ACTIVE` in `kali-mcp/core.py` (otherwise it's **passive**), add its
   rate flag to `RATE_FLAGS`, and add `SUBCOMMAND_TIERS` rules if its risk depends on a subcommand or flag.
3. Describe it in the `run` tool's docstring in `kali-mcp/server.py` (what the planner reads) and in the
   `kali_run` description in `harness/worker.py` (what the worker reads).
4. Add a check to `evals/tools_smoke.sh`, and any download hosts to `kali-mcp/infra_domains.txt`.
5. Rebuild with `RVKIT_BUILD=1 ./rvkit up`, then run `evals/tools_smoke.sh` and `evals/phase3_policy_test.sh`.

See also: [architecture.md](architecture.md) · [engagements.md](engagements.md) ·
[running-the-agent.md](running-the-agent.md) · [lab-and-benchmarks.md](lab-and-benchmarks.md)
