# Tools reference

Everything the agents can call: the five MCP servers and their tools, the worker model's own tools, the Kali
toolbox with each program's tier, the kit's own helpers, and the methodology playbooks. Use it to understand what
the agent did, to write better task prompts, or to extend the kit.

## MCP servers at a glance

| Server | Container, port | Who uses it | For |
|---|---|---|---|
| `kali` | `kali-mcp:8090` | planner, worker, report generator | running tools in the engagement sandbox; scope, activity and evidence checks |
| `worker` | `worker-mcp:8091` | planner (`riskvoid-planner` only) | handing focused tool work to the worker model |
| `findings` | `findings-mcp:8092` | planner | findings, playbooks, writing engagement files, the report, the research records (briefing, recall, queue, conclusions, methods) |
| `intel` | `intel-mcp:8093` | planner, worker | vulnerability intelligence (OSV, NVD, EPSS, CISA KEV) |
| `web` | `web-mcp:8094` | planner | web search and public page fetch |

`riskvoid-local` gets every server except `worker`. All of them are configured in OpenHands by
`./rvkit openhands` (see [architecture.md](architecture.md#configuration-plumbing)).

## `kali`: the Kali sandbox

| Tool | Parameters | What it does |
|---|---|---|
| `list_engagements` | none | Every registered engagement with its policy revision, what the scope allows and excludes, rules (tiers, max rate, network, execution, window, dates, days, time zone), stop conditions, what the kit doesn't enforce, `NOT NOW` when outside the testing time, and `HALTED`. The planner calls it first. |
| `engagement_info` | `engagement` | The same for one engagement as JSON: effective policy, rules, budget use, uid and the infrastructure domains it may reach (online engagements). |
| `all_scopes` | none | The union of every engagement's networks and domains. `web-mcp` uses it to refuse fetching targets. |
| `run` | `command`, `engagement`, `timeout_s` (default 600, max 3600), `approval_id`, `max_tier`, `task` | Runs a shell command in the engagement's sandbox. Returns `exit=<code> tier=<tier>` and the output, or `REFUSED: <reason>`, or `APPROVAL REQUIRED` with an approval id. `max_tier` limits the command to a task's tier (the worker sets it). |
| `http_request` | `engagement`, `method`, `url`, `headers`, `body`, `approval_id`, `max_tier`, `task`, `body_base64`, `identity` | Sends one HTTP request from kali-mcp to an in-scope URL: the only way to reach hosts whose scope is a URL path. Checks every URL and redirect against the policy, connects to the address it checked, counts against `Max requests`, saves request and response in `evidence/http/`. GET/HEAD/OPTIONS are active; other methods intrusive (approval). |
| `analyze_source` | `engagement`, `tool` (semgrep, gitleaks, trufflehog, bandit), `path`, `rulesets`, `task` | Runs a source-analysis tool on in-scope code in the sandbox with no network at all; the JSON report goes to `evidence/source/`. |
| `evidence_provenance` | `engagement`, `paths` | For each evidence file: current SHA-256 and status: `verified` (with the producing command, time, tier, exit code), `MODIFIED after it was produced`, `not produced by an audited kali command`, `missing`, or `not an engagement file` (a path outside the engagement folder). |
| `engagement_activity` | `engagement` | Summary of the audit log: time range, commands run and refused, counts per tier and per tool, evidence files, approvals, halts and scope changes. The report's methodology section uses it. |
| `approval_status` | `engagement`, `approval_id` | Where an approval stands: `pending`, `approved`, `denied`, `used` or `stale` (the scope or rules changed), as JSON. |
| `list_credentials` | `engagement` | The names of the credentials stored for the engagement (never the values). Use one as `$RV_CRED_<NAME>` in `run`, or `{{cred:NAME}}` in an `http_request` URL, header or body. See [engagements.md](engagements.md#credentials). |
| `laravel_map` | `engagement`, `path`, `build_url`, `routes_file`, `max_tier`, `task` | Maps a Laravel application from its source without running it: routes with effective middleware, controllers, models (mass assignment, tenant scopes), policies, views and sinks; leads, controls and gaps; the source digest compared with the deployment's build. Evidence in `evidence/appmap/`. See [laravel.md](laravel.md). |
| `recon_map` | `engagement`, `url`, `depth` (1-5, default 2), `crawl_seconds` (default 120), `probe` (default true), `max_tier`, `task`, `identity`, `max_scripts`, `max_probes` | Maps a web target before testing: a katana crawl in the sandbox (links, JavaScript, robots, sitemap), content discovery (ffuf over the common wordlist for paths the crawl never named), the API paths its scripts name (source maps, GraphQL operations embedded in client JS, a gitleaks secrets pass over the fetched scripts), its OpenAPI / Swagger schema at the usual paths, a GraphQL schema by a read-only introspection GET (clairvoyance when introspection is off), hidden GET parameters (arjun), and one GET without credentials to each path not yet fetched (401, 403 or a login redirect: authentication required). `identity` runs an authenticated pass after the unauthenticated one, with an engagement identity (`list_identities`): the surface behind login enters the map, tagged `seen_by`; an identity that isn't valid is skipped with a note, never silently. `max_scripts` / `max_probes` raise the script and probe caps for a large app. Only in-scope URLs are kept; every request goes through the brokers and the audit log. Evidence in `evidence/map/`. `get_map` merges it with the other sources. |
| `probe_map` | `engagement`, `matrix`, `max_requests` (default 400), `checks` (subset, default all), `task`, `identity` | The kit's fixed checks against the recon map (run `recon_map` first): `injection` (an error probe and a boolean true/false pair on every parameter of every read, path parameters included; a hit only when the answers differ the way the probe predicts), `redos` (string fields whose malformed value gets a validation error receive inputs of growing length, timed, stopping at the first clear growth), `jwt` (every JWT seen is cracked offline against common secrets; a forged token is tried against an authenticated endpoint), `mass-assignment` (every object-creating POST with a JSON body registers a throwaway account carrying one privileged field and reads it back logged in as it, against a control), `cors` (an Origin-probe matrix, a foreign origin and the null origin, on entries a browser can call; a hit names whether credentials are allowed too), `headers` (the security-header checklist on pages: CSP, nosniff, framing, HSTS over https; what is missing is named). `identity` runs the reads as an engagement identity, so the checks reach the surface behind login; an entry no identity can reach is skipped with a note, not silently. Reads run immediately; the writes are proposed as ONE authorization matrix (`./rvkit authz <eng> approve <name>`), and a second call with `matrix=<name>` runs only what that approval covers. Every request goes through the same scope, tier, rate and budget checks; the request count is capped; what it created is listed. Hits go to `evidence/sweep/` and import as observations (`import_observations`): leads with the exact requests, not findings until confirmed. The coverage cells a sweep hit covers count as tested. |
| `race_request` | `engagement`, `method`, `url`, `n` (2-25, default 10), `headers`, `body`, `identity`, `approval_id`, `task` | The brokered race (W4): the SAME state-changing request sent N times, as simultaneously as the kit can - the test for race conditions where something that must happen once happens twice (a one-shot voucher, the last item in stock, a balance transfer). ONE approval covers the exact request x N: its text names N and the rate exemption (a race is simultaneous by definition, so Max rate doesn't apply to the burst; N is capped at 25, and the request budget pays for every shot). The approval binds N: a race with a different N is refused. Returns each shot's status and one evidence file (`evidence/race/`) with every response. The decision is an oracle's afterwards - read back what changed or run `response_diff`; if more than one shot succeeded where the operation must happen once, that is the finding to verify. |
| `list_identities` | `engagement` | The engagement's test identities: name, role, tenant, hosts, tiers, effects, fixtures (with markers) and session status. Never a secret. See [authenticated-testing.md](authenticated-testing.md#identities). |
| `check_identity` | `engagement`, `identity` | The valid-session control: `valid`, `expired`, `challenge`, `denied`, `error` or `revoked`, with the reason. Logs a `form`/`json` identity in again once when its session expired. |
| `list_captures` | `engagement`, `capture` | Imported HAR / Burp captures, sanitized. Without `capture`: the list; with an id: its requests (method, URL, in scope, status, excerpt). |
| `replay_request` | `engagement`, `capture`, `entry`, `identity`, `changes`, `markers`, `approval_id`, `max_tier`, `task` | Sends a captured request again through the request broker, as an identity, optionally changed, and compares the response with the captured one (status, size, similarity, JSON fields, markers, diff). Evidence in `evidence/replay/`. |
| `browse` | `engagement`, `url`, `steps`, `identity`, `mask`, `approval_id`, `max_tier`, `task`, `timeout_s` | Headless Chromium in the engagement's sandbox; every request is checked against the scope. Reading is active and read-only; `click`, `fill`, `press` are intrusive (approval). Evidence in `evidence/browser/<run>/`. |
| `propose_authz_matrix` | `engagement`, `name`, `operations`, `identities`, `expect`, `purpose`, `allow_writes`, `max_writes`, `cleanup`, `no_cleanup_reason` | Proposes an authorization matrix for the researcher to approve (bound to its digest and the policy revision). |
| `run_authz_matrix` | `engagement`, `name`, `task` | Runs an approved matrix: identities checked first, each operation as each identity, verdicts `pass`, `FAIL`, `unexpected-deny`, `blocked`. Results in `evidence/authz/`. |
| `verify` | `engagement`, `oracle` (`marker`, `identity_difference`, `read_back`, `browser_xss`, `timing`, `oob_callback`, `response_diff`, `persistence`), `request` (`method`, `url`, `headers`, `body`, `identity`; `{{marker}}` where a fresh canary goes), `marker`, `expect`, `identities` (`[attacker, owner]`), `check` (the read-back request), `control`, `approval_id`, `finding`, `task`, `samples`, `min_delay`, `timeout` | Decides a finding with a deterministic oracle and a negative control: `marker` (the canary comes back; control: the same request with another token), `identity_difference` (the attacker gets the owner's fixture marker; controls: the owner gets it, the request without an identity doesn't), `read_back` (a separate check finds what the proof wrote; control: the check before the proof), `browser_xss` (the page opens in the sandboxed browser and passes only if script calling `rvMarker('{{marker}}')` or `alert` actually ran; control: another token), `timing` (`samples` of the probe and of a `control` request, interleaved; passes when every probe is slower than every control and the difference beats `min_delay` and three times the spread), `oob_callback` (a blind issue: `{{marker}}` goes where the target's callback URL goes — the `url` argument it fetches, or the host/path it connects to — and the oracle passes only when that token arrives at the kit's own catcher within `timeout` seconds and the control's does not; needs `Out-of-band callbacks: on` in the engagement's RULES.md, and the rules line names the catcher URL), `response_diff` (two request specs and `expect`, the text only the probe's answer may contain: debug detail, verbose errors, hidden functionality; the control must not contain it), `persistence` (a write stores `{{marker}}` in a form the page executes, then `check` reads the stored location back in the sandboxed browser; the page before the write runs nothing of the marker). Result `pass` (holds, control clean), `fail` or `inconclusive`. Each run is saved as a verification record in `evidence/verify/` and audited; a callback that arrived is evidence under `evidence/oob/` with its own audit entry. Requests go through the same checks as `http_request`; a write needs an approval (call again with the same `marker` and the `approval_id`). A finding confirmed with `method=oracle` must cite a record that passed. |
| `list_authz_matrices` | `engagement` | Proposed matrices and whether each is approved, or changed since. |
| `cancel_task` | `engagement`, `task` | Kills the commands a worker task is running now. `worker-mcp` calls it when a task is cancelled or halted. |

What `run` does, in order: refuses if the engagement is halted or outside its testing window, dates or days;
classifies the tier and refuses it if `RULES.md` or the task's `max_tier` doesn't allow it; refuses out-of-scope,
excluded and request-tool-only hosts in network-tool commands; refuses when `Max parallel` network commands are
already running; asks for approval if the command is intrusive (bound to the command, its programs, its input
files and the policy revision); adds the rate flag (its share of `Max rate`); counts it against `Max commands`;
runs the command sandboxed as the engagement's user (with no network for passive commands under `Execution:
controlled`); hashes every file it created or changed. Details: [architecture.md](architecture.md#how-one-task-flows)
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
| `delegate_task` | `goal`, `engagement`, `tier` (`passive` default, `active`, `intrusive`), `max_steps` (default 15, 1–40), `timeout_min` (default 30, 1–180), `wait_s` (default 240, max 600), `depends_on` (task ids), `done_when` (the result that ends the task), `stop_when` (conditions to stop and report), `inputs` (evidence paths or finding ids to start from), `plan_item` (the coverage plan item the task tests), `independent_reproduction` (default false) | Starts one focused task on the worker model. Refuses if the engagement is halted or the tier isn't allowed by `RULES.md`. With `depends_on`, it waits until those tasks are done (and is `blocked` if one fails). The contract fields go into the worker's instructions, and every tool result the worker sees ends with the steps left and the `done_when`. A `stop_when` that names an approval ends the task as `blocked` at the first approval, with the approval in `needs`, instead of pausing. With a `plan_item` whose refs name one vulnerability class and one recon map entry or route group, the worker is told to test only that cell, and the task starts from the [research packet](#what-a-task-starts-from). A duplicate is refused: when another task holds the same work, or an experiment already answered the question, the reply names that task or experiment (`X-...`) instead of starting a second run. `independent_reproduction=true` runs it anyway; the run is recorded as a reproduction on its experiment, never as a second confirmation. Returns the result, or a `task_id` with a note if it's still running after `wait_s`. |
| `get_task` | `task_id`, `wait_s` (default 240, max 600) | Waits for a task and returns its result. |
| `cancel_task` | `task_id` | Stops a task; a running command is killed. |
| `resume_task` | `task_id`, `wait_s` | Continues an interrupted task from its last checkpoint, after checking the engagement's policy again. An action that was in flight is not repeated: the model is told its result is unknown. |
| `list_tasks` | `engagement` (optional) | Saved tasks, newest first (up to 50), including those from before a worker restart, with their approval and recovery decision. |

A result has the typed fields first: `task_id`, `status` (`queued`, `waiting`, `running`, `awaiting_approval`,
`done`, `error`, `blocked`, `cancelled`, `halted`, `interrupted`), `outcome` (`completed`, `partial`, `blocked`,
`out_of_scope` from the worker; `budget_used`, `model_refused`, `tool_failure`, `provider_error`, `stalled` from the
harness), `candidates` (each with `title`, `state` `hypothesis` or `reproduced`, `evidence` and `check`; a
reproduced candidate must cite an evidence file of the engagement or `finish` is refused), `needs`, `errors` and
the `recorded_findings` ids. Then `elapsed_s`, the `commands` it ran, `run_evidence` (the verified-evidence files
its commands produced: cite these), `transcripts_dir` (the step transcripts: records of the run, not evidence), the
`contract`, the `model` that served it (shows when the fallback model was used), `worker_summary` and
`worker_notes` (the worker's prose, marked as written by a model that read target content; the notes are what it
wrote outside `finish`, or where its reasoning had got to when it stalled) and `result` (`confidence`,
`open_questions`, the worker's proposed `conclusions`). Depending on the task, it also carries `packet_ids` (the
record ids the task started from, pointers that survive a context summary), `experiment` (the `X-...` record the
task left), `packet_repeat` (the cell was already tried and that result stands), `notes` (the worker's `note`s,
its own words), `ledger` (how often the ledger pointed at earlier work or answered from it) and `captured_facts`
(observations its calls captured, for the planner to triage). A `plan_item` that isn't one class on one mapped
endpoint doesn't refuse the task: it runs on its goal, and `contract.plan_item_note` says so. Secrets are redacted
from it. Task files from before these fields load as before; a finished one counts as `completed`.

Things to know:

- **One task at a time** by default: Colab handles one request at a time, so later tasks queue. Raise
  `WORKER_PARALLEL_TASKS` in `.env` for an endpoint that serves parallel requests.
- **Tasks survive restarts.** Each task's state and checkpoints are saved in
  `/work/<engagement>/evidence/tasks/<task_id>/task.json` (the conversation so far in `messages.json`), next to
  every step's full output (`step-NN-<tool>.txt`) and the whole exchange (`transcript.jsonl`). A task that was
  running when `worker-mcp` restarted shows as `interrupted` with a recovery decision; `resume_task` continues it.
  See [engagements.md](engagements.md#worker-tasks).
- **Approvals pause the task.** An action that needs approval sets the task to `awaiting_approval` (with the
  approval id) without holding the worker model; it continues by itself once you decide.
- **The worker's model calls carry the engagement**, so the model gateway applies its `Client data:` rule and
  halt to them.
- **Private engagements.** With `Worker model: private` in `RULES.md`, the task runs on `private-llm`, which
  never falls back to OpenRouter. See [models.md](models.md).
- If the worker model can't be reached, the task ends with `error: worker model unreachable …`. The planner then
  tells you to start it, or runs small checks with the `kali` tool itself.

### What a task starts from

A task bound to a `plan_item` starts from the **research packet**: what the engagement's records already say about
that coverage cell. It holds the map entries, the observations and findings with their states, earlier tasks for
the same cell with their typed result (negative and inconclusive ones too), the item's hypothesis and blockers,
conclusions (stale ones marked stale) and the [methods](#methods-and-related-surfaces) that match the cell. It is
built from the records by stable id, with no model call, in a fixed character budget (`WORKER_PACKET_CHARS`,
default 4,000). When a task resumes, the packet is rebuilt and only a material change is added. The planner sees
the same packet with `get_briefing`. `WORKER_PACKET=0` turns it off.

Inside a long task, what the worker writes down with `note` is kept in a pinned "established so far" block, with
its recorded candidates and the identities it checked. Shrinking old tool results never shrinks that block.

**The call ledger.** After a command or request runs (it always runs: a target can answer differently), the reply
carries the ledger entry of an earlier equivalent call in the same engagement, so the model sees what is new. This
covers the planner's own kali calls and the worker's. A worker `read_file` of an unchanged file and a repeated
`vuln_intel` lookup are answered from the ledger with no new call; `fresh=true` runs them anyway. A stale entry is
shown as stale and never reused. `RV_LEDGER=0` turns the ledger off.

**Facts are captured at every call.** After each worker call, and for the planner's own kali calls from the audit
log, the kit's parsers store what they extract as `new` observations, with the task or conversation, call,
identity, policy revision and evidence path they came from. The parsers read the JSON of semgrep, OSV-Scanner,
pip-audit, bandit and gitleaks, and the text of nmap (open ports), sqlmap (injection verdicts), nuclei (matches)
and `check_identity`. A repeated call adds no new
row. A call with no parser leaves only its ledger entry. The planner triages captured observations like imported
ones.

**Duplicates are refused.** The work key of a task is the current build, the coverage cell, the method and the
identity. A second `delegate_task` with the same key gets the task that holds the work, or the experiment that
already answered the question. Claims are kept in the engagement's database, so they survive a worker restart, and
any ending of the task releases them. A stale answer never blocks a re-test.

**Conclusions at the end of a task.** When a task bound to a plan item ends, the harness writes its experiment
record (`X-...`) and draws conclusions by rule where it can. For what the rules can't decide, one model call
proposes conclusions; each must quote its evidence, and a quote that isn't found leaves the conclusion unresolved.
`WORKER_CONCLUSION_SUMMARY=0` turns that call off. How the records fit together:
[architecture.md](architecture.md#the-record-chain-and-the-research-loop-schema-8-epic-77).

### The worker model's own tools

Inside a task, the worker model has these tools (they aren't MCP tools; `worker-mcp` implements them):

| Tool | What it does |
|---|---|
| `kali_run` | `command`, `timeout_s` (default 600, max 3600): calls the kali `run` tool for the task's engagement with the task's tier as `max_tier`. Same checks, same audit log. An intrusive command pauses the task until you decide; the model then gets the result or the denial. |
| `http_request` | `method`, `url`, `headers`, `body`: calls the kali `http_request` tool with the task's tier as `max_tier`. |
| `analyze_source` | `tool`, `path`, `rulesets`: calls the kali `analyze_source` tool (no network). |
| `vuln_intel` | `ids`, `fresh` (default false): ranks up to 50 vulnerability ids with the intel `prioritize` tool. A lookup the engagement already made is answered from the call ledger; `fresh=true` asks again. |
| `web_search` | `query`: SearXNG search through `web-mcp`, 8 results. |
| `fetch_url` | `url`, `start` (default 0): reads a public page as text through `web-mcp`, in parts of 100,000 characters from `start`. When more follows, the reply ends with the `start` of the next part, and the model calls `fetch_url` again with it. The model sees the head and the tail of a part; the whole part is in the step file, which it can read with `read_file`. Refuses every engagement's targets and non-public addresses, on every redirect too. |
| `read_file` | `path`, `start` (default 1), `lines` (default 200, max 500), `fresh` (default false): numbered lines of a file under the engagement's in-scope code paths or its engagement folder. Nothing else. A read of a file whose hash hasn't changed since an earlier read is answered from the call ledger; `fresh=true` reads it again. |
| `record_candidate` | `title`, `severity`, `asset`, `description`, `evidence`, `cwe`: stores a **candidate** finding (source `worker:<task_id>`). Only the planner can confirm it. |
| `finish` | `status` (`completed`, `partial`, `blocked`, `out_of_scope`), `summary` (1–5 sentences), `candidates`, `errors`, `needs`, `open_questions`, `conclusions` (each a `claim`, its `state` `supported`, `refuted` or `unresolved`, the exact `conditions` and the `evidence` file), `confidence`: ends the task. A `reproduced` candidate without an evidence file of the engagement is refused and the model is asked again. |
| `note` | `fact`, `evidence`: writes down one short fact the task established (a session that works, a parameter that reflects input), with the evidence path or call it rests on. Notes stay in the pinned "established so far" block, go back to the planner in the result, and reach later tasks through the packet and `recall` as agent notes: the worker's words, not verified facts. A note without evidence is kept and marked unsupported. |
| `read_record` | `id`: one record of this engagement in full, by the id the packet names: an observation (`O-...`), a finding (`F-...`), a plan item (`P-...`), a recon map entry (`E-...`), a method (`M-...`) or an earlier task. Bounded head and tail, read-only; `read_file` opens the evidence it names. |
| `recall` | `query`, `kind` (`observation`, `finding`, `plan`, `map`, `task`, `ledger`), `state`: one search across what this engagement knows, one line per hit with its state and age. `read_record` opens a hit. Same engagement only. |

In the model's context, a long tool output keeps its first 4,000 and last 2,000 characters, or a digest for the
tools the kit reads (the full output is in the step file). The oldest outputs are shrunk when the conversation
passes about 90,000 characters (`WORKER_CONTEXT_CHARS`), so a task fits the 32K context of the L4 profile. The
latest packet stays whole (older ones shrink to their id list), and the "established so far" block is rebuilt from
the task record each time.

## `findings`: findings, playbooks, files and the report

| Tool | Parameters | What it does |
|---|---|---|
| `record_finding` | `engagement`, `title`, `severity`, `asset`, `description`, and optional `impact`, `reproduction`, `remediation`, `evidence` (list of paths), `cvss_vector`, `cvss_score`, `cwe`, `status` (`candidate` by default; any of the five statuses is accepted), `notes` | Stores a finding and returns it with its id (`F-001`, `F-002`, …). Severity: `critical`, `high`, `medium`, `low`, `info`. |
| `update_finding` | `engagement`, `finding_id`, then any field to change, including `status`, `priority` (`P1`-`P4`), `prerequisites`, `root_cause`; `reason`; `method` | Changes only the fields given. Statuses: `candidate`, `confirmed` (with `method`: how it was verified), `false-positive`, `duplicate` (needs `duplicate_of`: the finding to keep), `fixed`, `accepted-risk`. `reason` is required for `false-positive`, `accepted-risk`, a severity change and a change of a set priority; refused without it (`REFUSED: ...`). |

**Quotes are compared with the evidence.** When the planner confirms a finding (`record_finding` or
`update_finding` with `status=confirmed`), text in backticks and code-block lines of its description and
reproduction counts as quoted and is looked up in the cited evidence files and the `/src` files it cites. Quotes
that are not there are listed in the reply (`quotes.not_in_evidence`), in `get_finding` and as a warning before
delivery; the finding is confirmed all the same. Until 16 November 2026 they refused the confirmation: in 48
saved benchmark runs that happened 79 times, and the texts were example attack inputs, protections named as
missing and lines of code cited by another file. Whether the evidence shows what the finding says is the
[validator's](#the-validator) call. One thing still refuses: a `/src/<file>:<line>` in the text that points at a
file or a line that doesn't exist. Not counted as quotes: commands and scripts, names, paths and URLs on their
own, `file:line` references, placeholders (`<id>`, `...`) and spans under 6 characters. Matching ignores
whitespace, HTML entities and URL encoding. A quote of several words also matches when its words appear in order
close together; a single token (a hash, a flag) must match exactly. `[REDACTED ...]` and `{{cred:NAME}}` match
any value. People confirming in the console or with `./rvkit` are not checked.
`python3 harness/quotecheck.py <engagements dir>` lists the confirmed findings of past engagements with quotes
that are not in their evidence.

<a id="the-validator"></a>**The validator tries to disprove each confirmation.** When the planner confirms a finding,
a separate model call (`validator`: `VALIDATOR_MODEL`, a different model from the planner) gets only the finding,
its cited evidence files, its oracle records with the responses they judged, and how each oracle works: not the
conversation. It also gets the source lines the finding refers to (`/src/<repo>/<file>:<line>`, 25 lines each
side), and a long evidence file is shown around the text the finding quotes (`VALIDATOR_FILE_CHARS`). Its only job
is to disprove the finding. It answers `stands` or `disproved` with a reason tied to one of the cited files; a
disproval that names no cited file counts as `unclear`. A disproved finding stays confirmed and is flagged: the
tool result gives the planner the reason, the console and the report show it, and the report can't be delivered
until the finding is corrected, marked false-positive or excepted by a person (readiness check `review:<id>`).
With `VALIDATOR_DISPROVE=demote` a disproved finding goes back to `candidate` instead. When the
engagement's Client data rule refuses the validator's model, the same call goes to `planner` in a fresh context;
when no model can be used, the verdict is `not_run` and the confirmation stands. Evidence is given as data, never
as instructions. The console shows the verdict on the finding and in its history, the report shows it as
"Independent review", and benchmarks count what survived and what was caught. `VALIDATOR=0` turns it off.
People confirming in the console or with `./rvkit` are not sent to it.

| Tool | Parameters | What it does |
|---|---|---|
| `validate_finding` | `engagement`, `finding_id` | Runs the validator again on a confirmed finding (it runs on its own on each confirmation). Returns the verdict, reason, evidence file and model. |
| `list_findings` | `engagement`, optional `status`, `severity` | Findings, most severe first: id, title, severity, status, asset, source. |
| `get_finding` | `engagement`, `finding_id`, `history` (default false) | One finding with every field; with `history`, every revision and decision with its reason. |
| `import_observations` | `engagement`, `path` (a file of the engagement, such as `semgrep.json` or `evidence/authz/...`), optional `tool` | Turns a Semgrep, osv-scanner, pip-audit, bandit or gitleaks JSON, an authorization-matrix run, an app map or an HTTP exchange into observations. Re-importing doesn't duplicate; parser errors and limitations are returned. |
| `add_observation` | `engagement`, `title`, `location`, optional `detail`, `severity`, `evidence` | Records something noticed by hand. |
| `list_observations` | `engagement`, `status` (default `new`), optional `tool` | Observations, the imports with their errors, and grouping suggestions. |
| `triage_observations` | `engagement`, `ids`, `action` (`link` with `finding_id`, `duplicate` with `of`, `dismiss` with `reason`, `reopen`) | Decides about observations; linked ones become the finding's instances and evidence. |
| `plan_tests` | `engagement`, `playbook` or `items` | Adds planned tests: one per checklist line of a playbook (once), or the given items with their standard references. |
| `update_coverage` | `engagement`, `item`, `state`, and `evidence`, `finding_id` or `rationale` as the state needs; optional `build`, `policy_revision`. Or, for several items, `updates`: a list of objects with those fields (`[{"item": "P-001", "state": "tested", "evidence": [...]}, ...]`) | Records a planned test's outcome: `tested` (evidence), `failed` (finding), `blocked`, `excluded`, `not-applicable` (rationale). With `updates`, each item is checked and saved by itself, as if sent alone: a refused one doesn't stop the others, and a revision conflict refuses only that item. The reply has one line per item, its state or `REFUSED: <reason>`, under a head line (`saved 3 of 3:` or `REFUSED 1 of 3 (...)`). A batch of one replies as the single form does; an empty list, an entry without `item` or `state`, or an unknown key is refused before anything is saved. |
| `get_coverage` | `engagement`, optional `state`, `matrix` | Planned tests, counts per state and per standard, stale and blocked items. With `matrix=true`, the coverage matrix: each recon map entry x each vulnerability class that applies to it (access-control, authentication, injection, xss, ssrf, open-redirect, mass-assignment, file-upload, user-enumeration, rate-limit, information-disclosure, redos, csrf, nosql-injection, cors-misconfig, security-headers, graphql-depth, graphql-batching, graphql-field-suggestions, oauth: by the entry's method, parameters, path and authentication), the plan items covering each cell, the cells a sweep tested, and the gaps no item or sweep covers. Plan items show as ready or waiting, with the reason (what a `requires` link still waits for). |
| `skip_coverage_cells` | `engagement`, `cells` (`[{entry, class}]`), `state` (`not-applicable` or `excluded`), `rationale` | Records matrix cells that won't be tested, with the reason, as plan items with that outcome (the gap-fill pass). |
| `get_map` | `engagement`, optional `host`, `path`, `auth`, `limit` | The recon map, merged from `recon_map`, `laravel_map`, imported captures and the agent's own requests: one entry per method and path template (numbers, UUIDs and `{params}` are one segment), with parameters, authentication (`required`, `none`, `unknown`, and the basis), the identities that saw it behind login (`seen_by`, from `recon_map` with an `identity`), statuses, sources, evidence and the classes that apply. Entry ids (`E-xxxxxx`) don't change when the map is rebuilt; plan items reference them in `refs`, and a reference to an id that isn't in the map is refused. The report readiness check lists matrix gaps (`coverage-gaps`, exceptable). |
| `set_objective` | `engagement`, `text` | What the engagement must answer. |
| `get_handover` | `engagement` | Where the investigation stands, built from the records: objective, findings, observations to triage, coverage, blocked and stale tests, pending decisions, the next useful actions, and the **board**: one row per open question with its last result, its blocker, the budget it used, its `queue_rank` and the next decision. Plus the researcher's note. The planner reads it when it resumes, including after a context summary. |
| `get_briefing` | `engagement`, `plan_item`, `goal` | The [research packet](#what-a-task-starts-from) for one cell: the same packet a worker task with this goal and plan item would start from, with no model call. For use before delegating a cell or testing it, and again after a context summary. Every line keeps its state; summaries and agent notes are their writers' words, not verified facts. Not offered to the planner in 0.2.0 (see the CHANGELOG's known issues). |
| `recall` | `engagement`, `query`, optional `kind` (`observation`, `finding`, `plan`, `map`, `task`, `ledger`), `state`, `limit` (default 20, max 50) | One search across what this engagement knows: observations, findings, plan items, map entries, earlier worker task results with their agent notes, and the call ledger. One line per hit with its state and age; ids match first, then the route group or path, then words. Same engagement only. Not offered to the planner in 0.2.0 (see the CHANGELOG's known issues). |
| `get_queue` | `engagement`, `limit` (default 20) | The engagement's open questions, ranked with the reason for each position: readiness, whether a standing conclusion already answers it, the class's weight, how many experiments ran. A share of the top slots is kept for hard, high-impact classes (authorization, tenant isolation, authentication). Advisory: the planner still decides. Also returns the last 20 entries of the dispatch log (every `delegate_task` with a plan item records the rank it dispatched against) and the `proposals` from [methods](#methods-and-related-surfaces). Computed from the records, with no model. |
| `record_conclusion` | `engagement`, `claim`, `state` (`supported`, `refuted`, `unresolved`), optional `conditions`, `evidence`, `plan_item`, `experiment` | Records a conclusion with the exact conditions it holds under ("rejected for identity A on build B", never widened). Name the experiment (`X-...`) it came from when there is one; the evidence file is pinned by hash. Its origin is `agent:planner`, so the records show it as the planner's own words. Not offered to the planner in 0.2.0 (see the CHANGELOG's known issues). |
| `link_records` | `engagement`, `src`, `dst`, `kind` (`supports`, `contradicts`, `requires`, `next`), optional `note` | Links two records among plan items (`P-...`), experiments (`X-...`), conclusions (`C-...`), observations (`O-...`) and findings (`F-...`). Both ends must exist. A `requires` link on a plan item names what the question waits for (`identity:alice`, `build:<digest>`, an observation id, `conclusion:P-002:supported`, `capability:intrusive`); readiness is computed from it, so the question becomes ready by itself when that appears. Not offered to the planner in 0.2.0 (see the CHANGELOG's known issues). |
| `report_build` | `engagement`, `build` | Records the target's current build (a source digest, a deployed build id) when the planner can establish one. A build change marks conclusions recorded against another build, and plan items tested on it, stale for re-testing; nothing is deleted. Not offered to the planner in 0.2.0 (see the CHANGELOG's known issues). |
| `list_methods` | `engagement`, optional `vclass` | The methods this engagement has proved: what worked, under which conditions, the access each needs, its procedure and negative control, and the related surfaces each hasn't been proven on. |
| `record_method` | `engagement`, `title`, `vclass`, `procedure`, optional `assumes`, `access`, `groups` (route groups it was proven on), `expect`, `control` (the negative control), `finding`, `experiment`; `id` and `expected_revision` to correct one | Adds a method the harness couldn't derive, or corrects one it did. A correction based on an older revision is refused with a conflict. |
| `record_instance` | `engagement`, `finding_id`, `where`, optional `evidence` (list), `experiment`, `note` | Records a confirmed result at a related surface as an instance of the finding that owns the root cause, instead of a second finding. `get_finding` and the report show every instance. |
| `write_file` | `engagement`, `path`, `content`, `append` (default false) | Writes one of: `PLAN.md`, `NOTES.md`, `notes/<name>.md` or `.txt`, `report/executive-summary.md`, `report/methodology.md`, `report/conclusion.md`, `report/meta.txt`. Anything else, or content over 1 MB, is refused. |
| `list_playbooks` | none | Each playbook's name, title, standard and tiers. |
| `get_playbook` | `name` | The full text of one playbook. |
| `generate_report` | `engagement` | Builds a new report revision (`.html`, `.docx`, PDF and findings register `.xlsx`) in `/work/<engagement>/report/revisions/<R-id>/` and copies it to `report/`. Returns the revision, its state (`generated`, or `ready` when nothing blocks delivery), the readiness checks, `DRAFT` or `final`, and how many findings were included and left out. Approval is the researcher's, not the agent's. Takes about a minute. |
| `report_readiness` | `engagement` | What blocks delivery now, what a person excepted and why, the warnings, and the revisions with their states. |
| `record_retest` | `engagement`, `finding_id`, `retest_build`, `outcome` (`resolved`, `partial`, `unresolved`), `cases` (`[{name, after: [evidence], result, before, detail}]`), optional `reauthorization`, `note` | Records a retest. Resolved (every case passes) marks the finding fixed in a new revision; the others keep it confirmed. The history keeps the original. |
| `cleanup` | `engagement`, `action` (`add` with `kind` and `what`; `update` with `item`, `state=done` and `note`; `list`) | Cleanup obligations to finish before close-out. Waiving one is the researcher's decision. |
| `prepare_notice` | `engagement`, `finding_id` | Drafts a notice about a confirmed critical or high finding in `report/notices/`, for the researcher to review. Sends nothing. |
| `export_findings` | `engagement`, `draft` (default false) | `findings.json`, `findings.sarif` and `issues/<id>.md` from the approved report revision (or the latest, marked DRAFT). Sends nothing. |

### Methods and related surfaces

When the planner confirms a finding with a passing [oracle](#kali-the-kali-sandbox) (`verify`), the harness derives a
**method** record (`M-...`) from what backs the finding: the oracle's procedure and negative control, the evidence
to expect and the access it needs. The plan link adds the route group, or the source files the map names, that it
was proven on. Methods stay in the engagement's own database: nothing reads another engagement's methods, and
there is no export.

A method proposes the related surfaces it hasn't been proven on: the same route group, or the operations the map
puts behind the same source code. Each proposal in `get_queue` is the plan item to add and the `delegate_task`
goal to send. The method transfers, the result doesn't: each proposed test runs its own negative control at the
new surface. A confirmed sibling becomes an instance of the original finding (`record_instance`), and a correctly
protected sibling is recorded as refuted with its conditions, not as a finding. A task whose cell matches a method
gets one line about it in its packet; the worker opens it with `read_record`.

Findings are stored per engagement in `/work/<engagement>/.rv/findings.db` (SQLite). The report includes `confirmed`,
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
limitation: [SECURITY.md](../SECURITY.md#known-limitations). With `Strict tiers: on` in `RULES.md`, both count as
intrusive ([engagements.md](engagements.md#rulesmd)).

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
2. Put its program name under `intrusive` or `active` in `kali-mcp/tiers.yaml` (otherwise it's **passive**), add
   its rate flag under `rate_flags`, and add `subcommands` rules if its risk depends on a subcommand or flag.
3. Describe it in the `run` tool's docstring in `kali-mcp/server.py` (what the planner reads) and in the
   `kali_run` description in `harness/worker.py` (what the worker reads).
4. Add a check to `evals/tools_smoke.sh`, and any download hosts to `kali-mcp/infra_domains.txt`.
5. Run `python3 evals/unit_test.py` (it checks `tiers.yaml`), rebuild with `RVKIT_BUILD=1 ./rvkit up`, then run
   `evals/tools_smoke.sh` and `evals/phase3_policy_test.sh`.

See also: [architecture.md](architecture.md) · [engagements.md](engagements.md) ·
[running-the-agent.md](running-the-agent.md) · [lab-and-benchmarks.md](lab-and-benchmarks.md)
