# Changelog

All notable changes to the kit. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
versions follow [Semantic Versioning](https://semver.org/). Before 1.0, a minor version may change commands,
settings or the findings database; `./rvkit update` migrates existing installs and engagements.

## [Unreleased]

The harness engineering epic: how the worker keeps its context, what the planner and the worker hand each other,
how a finding gets verified, how testing covers the target, how the kit holds up against hostile targets, and how
changes to the harness are measured.

### Worker and planner
- Long tool output keeps its head and its tail, with a digest for tools the kit reads (sqlmap's injection points,
  nmap's open ports, nuclei's matches); the full output stays in the evidence file.
- Malformed tool calls go back to the worker model as an error and never run.
- Stall and repeat detection: a worker task that repeats itself or makes no progress is nudged, then asks the
  planner for advice (at most twice, `WORKER_ADVISOR=0` turns it off), then stops.
- Worker context: recent results stay whole, older ones shrink once to one line with their digest and evidence
  path.
- `delegate_task` takes a contract (done when, stop when, inputs, one coverage cell), and the worker's `finish`
  returns a typed status and candidates with their proof.
- The planner sees the engagement's rules that tools can't enforce restated on every Kali action result.
- `./rvkit doctor --models` checks that the worker model makes well-formed tool calls.
- `record_finding` and `update_finding` read a `method` without `status` as a confirmation attempt, with the same
  checks as `status="confirmed"`. When the checks fail, the finding and the other fields are saved and the reply
  says why it is still a candidate. Before, the finding was recorded as a candidate without a word.

### Verification
- A confirmed finding's quotes are compared with its evidence files. Quotes that are not there are listed in the
  reply, in `get_finding` and as a warning before delivery. A `/src/<file>:<line>` that doesn't exist refuses the
  confirmation.
- Oracles prove a finding with a check the kit runs itself: a response marker, the difference between two
  identities, a read-back, script execution in the sandboxed browser, and timing. Each runs a negative control, and
  the report shows the oracle and its control for each verified finding.
- A sixth oracle, `oob_callback`, proves a blind issue (SSRF, blind XXE, blind command injection): the probe
  embeds the kit's own callback catcher where the target's fetch goes, and passes only when a token unique to the
  verification arrives and the control's does not (`{{marker}}` is the token). The catcher is kit-operated, on the
  lab network at `10.250.0.2:8080`, never an agent-run listener, and off unless the engagement's RULES.md says
  `Out-of-band callbacks: on` — a host decision like an identity, and the rules line the agent sees names the
  catcher URL. The firewall drops every engagement user's traffic to the catcher on any local address, so an agent
  command cannot forge a callback: the token can only come from the target, and each expected callback is recorded
  as timestamped evidence with an audit entry. Lab-verified with a negative control on the hostile lab's SSRF and
  on DVGA's `importPaste` mutation (`evals/oracle_test.sh`, which now also runs in CI; the DVGA probe is a POST,
  so it needs an approval like any write).

### Harness-run checks
- `probe_map` (kali) runs the kit's fixed checks over the recon map, so the finding of known classes stops
  depending on the model thinking of every test: `injection` (an error probe and a boolean true/false pair on
  every parameter of every read, path parameters included — the class the error analysis showed the model
  skipping on VAmPI), `jwt` (every token seen cracked offline against common secrets, a forged token tried
  against an authenticated endpoint), `mass-assignment` (a throwaway account carrying one privileged field,
  read back logged in as it, against a control), and `redos` (validated string fields timed with inputs of
  growing length, stopping at the first clear growth, never at the sizes that stop the target). Reads run
  immediately; the writes are proposed as ONE authorization matrix and run only after it is approved, touching
  only the sweep's own throwaway accounts. Every request goes through the same scope, tier, rate and budget
  checks; hits go to `evidence/sweep/`, import as observations with the exact requests, and are leads until the
  planner confirms them. `evals/sweep_test.sh` (no model, in CI) shows all four checks hitting on VAmPI with
  clean controls, one approval, and the ladder stopping before impact.
- Coverage-matrix gaps now count as open work everywhere: a sweep hit fills the cell it tested (with its
  evidence file), the report's readiness warning names the remaining cells, an unattended benchmark run is
  nudged with them, and marking a plan item `tested` is refused when it references no map entry (it would cover
  no cell) — only when a map exists, since a source review has no entries to reference.
- A validator on a separate model (`VALIDATOR_MODEL`) tries to disprove each confirmed finding from its evidence
  and the source lines it cites. A finding it disproves stays confirmed and is flagged: the report can't be
  delivered until the finding is corrected, withdrawn or excepted by a person (`VALIDATOR_DISPROVE=demote` sends
  it back to candidate instead). The console and the report show its verdict as "Independent review";
  `VALIDATOR=0` turns it off.
- The evidence a finding cites is recorded by content when it is confirmed. If the file is moved later, the
  finding is pointed at its new place.

### Coverage
- `recon_map` builds a map of the target before testing: crawled pages and scripts, API schemas, GraphQL, and
  unauthenticated probes. Plan items cite its entries.
- The coverage matrix lists every map entry against the test classes that apply to it. Worker tasks are narrowed
  to one cell, and cells can be skipped with a reason. Untested cells are flagged before delivery.
- The matrix knows the classes the benchmarks score that used to be invisible to it: user enumeration, rate
  limits, information disclosure (debug, verbose, status, metrics, GraphiQL routes), ReDoS (search and filter
  parameters, and path parameters: a validation regex may run on them), CSRF on page-form writes, NoSQL
  injection in bodies, CORS and security headers on browser pages, and GraphQL depth, batching and field
  suggestions. VAmPI's login enumeration and brute-force surface, its `_debug` route and its per-user email
  validation, DVGA's batching/depth and Juice Shop's `/metrics` now have cells the planner can be held to,
  where before the coverage-driven method couldn't see them at all. Every expected issue of the black-box
  benchmarks maps to at least one class; each predicate has unit tests, and the eventual recall effect is
  judged as a proposal when a benchmark budget exists.

### Hostile targets
- Approvals show where each argument came from: the scope and rules, the task, the agent, or the target's own
  content (with the file it was read from). The console and `./rvkit approvals` highlight arguments taken from
  target content.
- With `Target content approval: on` in RULES.md, an active call to a path or host that only target content named
  needs an approval.
- Listeners, reverse shells, piped downloads, download-then-run, and uploads (scp, sftp, ftp, tftp, rsync) are
  intrusive by default, whatever tool runs them.
- Lab: a hostile practice target with injected instructions, decoys and fake flags (`web-hostile` benchmark).

### Operation
- `./rvkit tracing on` exports OpenTelemetry traces of worker tasks, model calls and tool calls to a bundled
  Jaeger. Content goes into spans only when switched on, and then only for engagements whose Client data rule
  allows it.
- Intel lookups retry the public vulnerability sources and name the ones that didn't answer.
- Amazon Bedrock as a model provider, so AWS credits can pay for the models: `./rvkit planner --direct
  bedrock/<model>` for the planner, `./rvkit worker bedrock [model]` for the worker. It takes a Bedrock API key,
  has its own daily budget, and `bedrock` is a destination in an engagement's Client data rule.
- The integration suites run on every pull request that changes code they cover. Docs-only pull requests still
  skip them, and the `full-ci` label still starts a run.

### Console and operation
- Console: an **Agent** section shows a conversation bound to the engagement, read-only, in the console's own
  design: messages, and each tool call as a typed line with its tier and result, refusals and approvals marked,
  and the findings it recorded.
- Console: message the planner from the **Agent** section, and pause or resume the conversation. A halted
  engagement takes no message. Each one is in the audit log with who did it.

### Benchmarks
- Repeated runs (`--repeat N`): per expected finding, found in k of n runs; pass^k and pass@k; every mean with its
  standard error. `--compare A B` pairs two labelled sets of runs with a 95% interval.
- Clean runs (`--clean`) limit lookups to vendor documentation and vulnerability records and flag any lookup of a
  write-up of the target. `--agent riskvoid-plain` runs a plain agent on the same model as a baseline.
- Every result records the operator load: approvals, questions to the user, worker task outcomes, tool-call errors
  and cost per verified finding.
- `./rvkit bench --improve`: error analysis from failure records, one proposal per cause, and a judge that keeps a
  change only when its cause shrinks, held-out benchmarks don't fall beyond the spread, and no safety cause rises.
  Kept and dropped changes go into `docs/harness-changelog.md`.
- The improvement loop's judge counts a drop on the held-out benchmarks as a fall only when the per-item interval
  and the run-level permutation test both say so, as `--compare` does. The judgement says which test decided,
  with p. Before, one collapsed run could decide the verdict through the interval alone.
- Every benchmark run keeps its failures (missed and weakly proven findings, unexpected ones, refused and failed
  tool calls, early stops, worker tasks that didn't finish), each with a cause built from fixed rules.
  `./rvkit bench --failures` groups them by cause across runs; `--rebuild` derives them from saved runs.
- `./rvkit failures` does the same for engagements, from what the kit and the operator recorded (decisions a
  person overruled, denied approvals, refused and failed commands, worker tasks, model calls). It keeps ids, counts
  and causes only, and `./rvkit close` collects once more before sealing.
- Console: a **Failures** page shows both, by cause, with what is behind each one.
- Scores count expected issues that were recorded as a candidate and never confirmed on their own ("left as a
  candidate", and recorded recall), so a run that detected an issue and failed to confirm it doesn't read as a run
  that missed it. `./rvkit bench --rescore` adds the count to saved runs.
- Every benchmark result counts tokens for the planner, the worker, the advisor and the validator, with their
  total. `--history` prints the total and `--compare` shows it next to the cost. Runs saved before show `n/a`.
- Each benchmark result says how often the gateway's loop limit acted (`loop_limit`: note, withhold, cut).
  `evals/loop_limit_test.sh` checks each stage through LiteLLM with a scripted model, with no model spend.
- `code-node` moved from the held-out to the tuning benchmarks. Its runs were read while fixing the harness, so it
  no longer tests a change on failures nobody read. P-001 and P-003 keep their recorded verdicts, which used it as
  held out.

### Fixed
- Worker delegation didn't work with a reasoning model as the worker. A model call was capped at 2,048 output
  tokens, reasoning included, so the model spent the whole reply thinking and returned neither a tool call nor an
  answer; the worker dropped the reasoning, charged a step and asked again, up to the task's step limit. The cap is
  now 8,192 (`WORKER_MAX_TOKENS`), such a reply keeps its notes and costs no step, three in a row end the task as
  `stalled`, and the result returns what the worker had worked out (`worker_notes`).
- `delegate_task` refused a `plan_item` that had no recon map entry, which is every plan item of a source review.
  The task now runs on its goal and the result says the plan item set no scope limit.
- The planner prompt told the planner to delegate tool work and, two paragraphs later, to call the Kali tools
  itself for small checks. One planner model took the second as the rule and delegated in 1 of 34 runs. The prompt
  now says which work goes to the worker (scanner and review runs, also on a small target) and which stays.
- The validator disproved real findings: 40 of its 41 disproves in the saved benchmark runs. It saw at most 6,000
  characters of each cited file and none of the source files a source review cites. It now gets the cited source
  lines and up to 30,000 characters per file, shown around the text the finding quotes, and it is told to judge a
  finding by its verification method.
- A planner model that repeats a tool call that was turned down no longer reads its own repeats. From the third
  identical call in a row, the model gateway leaves those turns out of the request and puts one note in their
  place (`litellm/rv_repeats.py`, `REPEAT_COLLAPSE=0` turns it off). Replayed at a point where the model had sent a
  call 20 times, it sent it again in 5 of 5 tries with the history as it was, and in 4 of 15 with the note.
- A repeated tool call now has a hard limit. When the planner has read that note and sends the call a fourth
  time, the gateway leaves that tool out of its next request, so it can't send it; the tool is back after any
  other call. Replayed at the fourth call of four saved loops, the model made a different call in 12 of 12
  tries. At a sixth identical call the gateway answers the request itself with a `[RiskVoid] Loop stopped` text
  and calls no model, which ends the planner's turn at no cost; the text says how to go on (a message in the
  conversation, or `./rvkit conversation <engagement> new`). A user message or a text reply between two
  identical calls no longer starts the count again.
- The benchmark scorer counted an evidence entry with a note after a colon (`semgrep.json: rule x at app.py:13`)
  as a missing file. It takes the path the way the tools do.
- A benchmark run whose turn the gateway ended, or that OpenHands stopped as stuck a second time, goes on in a
  new conversation that starts from the engagement's records (`get_handover`, `get_coverage`), at most twice per
  run. The result lists them under `conversations` and `restarts`, and the saved conversation holds the events
  of all of them.
- An evidence entry with a note after the path (`evidence/runs/x.txt (no WAF)`) or a line number was refused with
  "no such file". The path is now taken from it, also when the note follows a colon (`x.txt: no WAF`).
- A quote that is not in the cited evidence no longer refuses a confirmation. In 48 saved benchmark runs that
  refusal came 79 times, in 23 of the runs, for example attack inputs, protections named as missing and lines of
  code cited by another file; one run that scored 0 of 6 had 25 of them. The texts are now listed in the reply
  (`quotes.not_in_evidence`), in `get_finding` and as a delivery warning, and the validator judges whether the
  evidence shows what the finding says. Replayed, all 79 refused calls confirm.
- `update_coverage` refused a source file as the evidence of a planned test ("not a tool output of this
  engagement"). In a source review the code is the evidence: `/src/<repo>/<file>`, with or without a line or a
  line range, is accepted when the file and the lines exist. Replayed over the saved runs, 29 of 75 refused
  evidence entries are accepted; the other 46 name files that are not in the engagement folder.
- A `cvss_score` that differed from the score of its CVSS 3.1 vector was refused. The score is computed from the
  vector.
- `record_finding`, `update_finding` and `update_coverage` returned the whole row after every write, which made
  up a third of the planner's context. They return the row's state and the fields the call sent; `get_finding`
  returns everything.
- The planner's context carried OpenHands' public skills catalogue (about 6,500 tokens) and 14 browser tools on
  every model call. Both are off in the kit's agent profiles.
- nmap failed in the sandbox with "Operation not permitted": Kali's nmap ships with file capabilities beyond the
  `CAP_NET_RAW` the sandbox allows, so Linux refused to start it. The Kali image now strips file capabilities, and
  `evals/tools_smoke.sh` checks that nmap starts with the sandbox's privileges.
- After the validator disproved a finding, the planner could loop re-confirming it with `update_finding` calls that
  gave a method but no `status=confirmed`: each call changed nothing, and one benchmark run repeated it about 80
  times until its budget ran out. Such a call is now refused with what to send instead.
- The agent could confirm findings without reproduction steps, and in a benchmark run it stopped writing them after
  one refusal. Confirming a finding through the agent's tools now needs reproduction steps; the console and the CLI
  are not held to this.
- Benchmark scoring could credit an expected issue to the wrong finding when two findings matched two issues (an
  unsafe YAML load and the PyYAML dependency both mention "yaml"), which failed the location check and capped
  code-flask's strict recall at 83%. Each issue now goes to the finding that fits it best.
- `--compare` could call a difference real from an error estimate over only two benchmarks. The verdict now also
  needs a run-level permutation test to agree.
- A call to `update_finding` with a method, other fields and no `status` on an unconfirmed finding was refused in
  full, so its priority, root cause or evidence were lost and the planner resent it dozens of times. The other
  fields are now saved, and the reply says the method is kept only with `status="confirmed"` (P-002).
- `jwt_tool` did nothing in the sandbox. Each command gets a fresh home folder, and on its first run `jwt_tool` only
  writes its config and exits, so a crack (`-C`) printed the setup message and stopped. Weak signing keys were found
  only when a command happened to run it twice. The wrapper now writes the config first, and
  `evals/tools_smoke.sh` checks that a crack works on the first run.
- The scope pre-check read a JWT on the command line as a host name, because it contains dots, and refused
  `jwt_tool <token>` and `curl -H 'Authorization: Bearer <token>'` as out of scope. JWT-shaped tokens are no longer
  read as targets.
- Saved benchmark scores went stale when the scorer changed, and the failure records and the improvement loop's
  judge read them. `./rvkit bench --rescore` scores every saved run again from the engagement it kept, keeps the old
  score in `score_at_run`, and rebuilds the failure records.
- A sandboxed DNS lookup that happened to reuse the source port of one of kali-mcp's own recent lookups was
  answered by Docker's resolver, not the engagement's, so a name the scope excludes could resolve. The firewall now
  checks an engagement's loopback traffic on every packet, and the policy suite tests this case on purpose.
- The model gateway's loop limit also catches a planner that makes two or three calls in turn, each ending the
  same way: the note comes at the third round, the tools are withheld at the fourth and the turn is ended at the
  sixth.
- `update_coverage` takes several plan items in one call (`updates=[...]`): each is checked and saved by itself,
  and the reply names each item with its state or its refusal. Failure mining counts each refused item of such a
  reply as its own cause.
- The worker's `fetch_url` takes `start`, so it can read a long page past the first 100,000 characters. The hint
  at the end of each part names `fetch_url`.
- A benchmark run health-checks its lab target before spending anything on it: one HTTP probe from inside the
  kit, and a container that is up but wedged is restarted once and the run is skipped with a message if it still
  doesn't answer. A dead target no longer produces a run that measures nothing (the DVGA incident).
- Planning docs carry no calendar dates any more: the ROADMAP's "Now" states the active work in order
  (first-user fixes, then the harness-run checks epic #76 and the research loop epic #77), and release and launch
  sequencing is stated as readiness gates rather than target days.
- Docs now match the code on releases, IPv6 scope entries (an error, not ignored), approval attribution, the
  testing window's time zone, Amazon Bedrock as a model option, the arm64 release check, the optional services
  and lab targets, and the six verification oracles.

## [0.1.0]

First public release.

### Agent and models
- A planner model (OpenRouter, or Anthropic or OpenAI directly) plans, triages and writes the report. A separate
  worker model runs the tools and reads the client's code, so raw tool output and source code stay with it.
- The worker runs on your own GPU, a rented GPU, Google Colab, any OpenAI-compatible API, or a hosted
  zero-data-retention model with no GPU at all. `./rvkit worker` switches between them.
- A daily spend cap that survives restarts. The worker fallback to a hosted model is off by default.
- Client data routes are enforced at the model gateway: an engagement marked offline or local can't reach a cloud
  model, whatever the conversation asks.
- The default planner is GLM-5.3 (`z-ai/glm-5.3`), with DeepSeek V4 Pro as its fallback. In the lab runs it had no
  planner calls refused, where GPT-6.1 had refusals in every black-box run, and it costs less per token.
  `./rvkit planner` changes it.
- When the planner's provider refuses a request, also with an error inside the stream, the fallback answers. An
  empty reply is retried once on the same model first.

### Scope and safety
- A Kali Linux sandbox per command, with a per-engagement firewall that only reaches the targets in scope. The
  findings database (with approvals, exceptions and review history) is read-only to commands, each command gets a
  fresh home folder, and a command receives only the credentials it names.
- Versioned scope and rules: exact hosts and wildcards, ports, exclusions, URL limits, testing windows.
- Passive, active and intrusive tiers (`kali-mcp/tiers.yaml`), with an optional strict mode for scripts and
  data-sending requests.
- Approvals bound to one exact action, its inputs and the policy revision, usable once. Budgets and rate caps.
- A halt switch that stops commands, worker tasks, browsers and model calls.
- An audit log the agent can't write to; SHA-256 on every piece of evidence; a sealed close-out archive.
- The agent's own terminal and browser sit on an internal network behind an allowlisting egress proxy.

### Testing work
- Playbooks for source code review, secrets, supply chain, web applications, APIs (REST and GraphQL), AI
  applications and MCP servers, external networks, and Laravel.
- 45+ tools, including Semgrep, Joern, Gitleaks, TruffleHog, OSV-Scanner, Grype, Syft, Nuclei, ZAP, ffuf,
  sqlmap, Schemathesis, jwt_tool, garak and `rv-llm`.
- Authenticated testing: encrypted credentials and role/tenant identities, HAR and proxy capture import with
  controlled replay, a sandboxed browser, and authorization matrices that compare owner, other-tenant and
  anonymous access.
- Laravel reference workflow: an application map from source (routes, middleware, policies, tenant scopes, raw
  SQL and unescaped Blade sinks), build identity checks against staging, and an optional isolated PHP/Composer
  profile.

### Investigation and delivery
- Findings database with revisions, actors and conflict detection; observations imported from scanner output;
  coverage plans and outcomes; duplicates linked to their original.
- The agent can't record a finding as confirmed without naming how it was verified, and without an evidence file
  for the methods that produce output.
- Report revisions with frozen inputs and hashes, readiness checks, human-only exceptions and delivery approval.
  Reports as a web page, Word document, PDF and Excel register, in RiskVoid branding or your own.
- Retests against a fixed build, cleanup obligations, reviewed client notices, and exports as JSON, SARIF and
  issue text.

### Console and operation
- RiskVoid Console: a local web UI on 127.0.0.1, out of the agent's reach, for engagements, scope, approvals,
  the live run, worker tasks, findings and reports.
- `./rvkit` for setup, doctor, engagements, approvals, the lab, benchmarks and updates; works from Claude Code,
  Codex, Cursor and other coding agents.
- An isolated practice lab: OWASP Juice Shop, DVWA, VAmPI, DVGA, a RiskVoid LLM lab and Ledgerly (Laravel, with
  a fixed build).
- Benchmarks scored on evidence: the exact asset, evidence, verification and reproduction, clean controls, tool
  outcomes, repeats and provenance.
- Each benchmark run has a spend cap the harness enforces from the key's OpenRouter usage
  (`./rvkit bench --budget USD` lowers it), and keeps its engagement folder and whole conversation in
  `evals/results/bench/<name>-<UTC>/`, so reports can be rebuilt later.
- Precision counts real findings outside the expected list (a second instance of an expected issue, or a known
  issue of the lab listed under `also_valid`); they never count for recall. `precision_expected_only` keeps the
  stricter figure.
- An unattended run that stops with planned tests open, or that OpenHands stops as stuck, is sent back to work, at
  most three times, while time and budget remain.
- Results per model pair, including GLM-5.3 with GLM-5.3 Flash, are in `docs/capability-baselines.md`.
- An open conversation keeps its tools when a tool server restarts (`./rvkit update`).

[Unreleased]: https://github.com/RiskVoid/Security-Agent-Kit/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/RiskVoid/Security-Agent-Kit/releases/tag/v0.1.0
