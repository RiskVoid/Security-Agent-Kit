# Changelog

All notable changes to the kit. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
versions follow [Semantic Versioning](https://semver.org/). Before 1.0, a minor version may change commands,
settings or the findings database; `./rvkit update` migrates existing installs and engagements.

## [Unreleased]

### Console and operation
- Console: an **Agent** section shows a conversation bound to the engagement, read-only, in the console's own
  design: messages, and each tool call as a typed line with its tier and result, refusals and approvals marked,
  and the findings it recorded. Sending a message still happens in the OpenHands UI.

### Benchmarks
- Every benchmark run keeps its failures (missed and weakly proven findings, unexpected ones, refused and failed
  tool calls, early stops, worker tasks that didn't finish), each with a cause built from fixed rules.
  `./rvkit bench --failures` groups them by cause across runs; `--rebuild` derives them from saved runs.
- `./rvkit failures` does the same for engagements, from what the kit and the operator recorded (decisions a
  person overruled, denied approvals, refused and failed commands, worker tasks, model calls). It keeps ids, counts
  and causes only, and `./rvkit close` collects once more before sealing.
- Console: a **Failures** page shows both, by cause, with what is behind each one.

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
