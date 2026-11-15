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

### Verification
- A confirmed finding's quotes must appear in its evidence files.
- Oracles prove a finding with a check the kit runs itself: a response marker, the difference between two
  identities, a read-back, script execution in the sandboxed browser, and timing. Each runs a negative control, and
  the report shows the oracle and its control for each verified finding.
- A validator on a separate model (`VALIDATOR_MODEL`) tries to disprove each confirmed finding from its evidence
  alone. A finding it disproves goes back to candidate. The console and the report show its verdict as
  "Independent review"; `VALIDATOR=0` turns it off.

### Coverage
- `recon_map` builds a map of the target before testing: crawled pages and scripts, API schemas, GraphQL, and
  unauthenticated probes. Plan items cite its entries.
- The coverage matrix lists every map entry against the test classes that apply to it. Worker tasks are narrowed
  to one cell, and cells can be skipped with a reason. Untested cells are flagged before delivery.

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
- Every benchmark run keeps its failures (missed and weakly proven findings, unexpected ones, refused and failed
  tool calls, early stops, worker tasks that didn't finish), each with a cause built from fixed rules.
  `./rvkit bench --failures` groups them by cause across runs; `--rebuild` derives them from saved runs.
- `./rvkit failures` does the same for engagements, from what the kit and the operator recorded (decisions a
  person overruled, denied approvals, refused and failed commands, worker tasks, model calls). It keeps ids, counts
  and causes only, and `./rvkit close` collects once more before sealing.
- Console: a **Failures** page shows both, by cause, with what is behind each one.

### Fixed
- nmap failed in the sandbox with "Operation not permitted": Kali's nmap ships with file capabilities beyond the
  `CAP_NET_RAW` the sandbox allows, so Linux refused to start it. The Kali image now strips file capabilities, and
  `evals/tools_smoke.sh` checks that nmap starts with the sandbox's privileges.

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
