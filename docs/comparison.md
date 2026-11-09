# How the kit compares

Other open-source AI agents also run security tools. This page says how they differ from the kit, so you can
pick the right one. Each project's own README is the source. The projects change fast, so check their pages
before you decide.

**Checked on 2026-11-08** against each project's README. Star counts are from that day.

## The short version

The others lead with autonomy: give the agent a target and let it run. The kit is built for work you have to
answer for, such as a client engagement:
- the agent can only reach what you authorised, enforced by a firewall rather than by the prompt
- risky steps wait for a person
- every artefact is hashed
- the report goes through a human approval before delivery

If you want the most autonomous agent for a CTF or your own lab, one of the others may suit you better.

## At a glance

| Project | Licence | What it is | Safety controls stated in its README | Reports in the free version |
|---|---|---|---|---|
| **RiskVoid Security Agent Kit** | Apache-2.0 | A planner and a worker model, 45+ tools in a Kali sandbox, a local console | Network-enforced scope per engagement; passive, active and intrusive tiers; single-use approvals bound to the exact action and policy revision; halt; audit log out of the agent's reach; SHA-256 on every artefact; human report approval | HTML, Word, PDF and Excel register; JSON, SARIF and issue exports |
| [Strix](https://github.com/usestrix/strix) (74k stars) | Apache-2.0 | Autonomous agents in a Docker sandbox with Caido and Playwright; validates findings with proof-of-concept exploits; Cloud and Enterprise editions | Authorised-use warning; budgets. No scope enforcement, approvals, tiers or audit log mentioned | Local viewer; compliance reports in Enterprise |
| [Shannon](https://github.com/KeygraphHQ/shannon) (51k stars) | AGPL-3.0 | White-box: reads the source, exploits the running app ("no exploit, no report"); Playwright; Pro edition | Warnings, read-only source mount, rules-of-engagement config; audit logs in Pro | PDF, Markdown, JSON, SARIF; signed auditor report in Pro |
| [PentAGI](https://github.com/vxcontrol/pentagi) (34k stars) | MIT | Multi-agent system with a Kali container per flow, 20+ tools, Ollama, Grafana and Langfuse; Enterprise edition | Turn limits, repeated-call detection, sandbox. No scope enforcement, approvals, tiers or audit log mentioned | Markdown and PDF; DOCX templates in Enterprise |
| [PentestGPT](https://github.com/GreyDGL/PentestGPT) (16k stars) | MIT | Drives Claude Code or Codex CLI; research paper at USENIX Security 2024 | Human in the loop in legacy mode; none stated for autonomous mode | Not stated |
| [HexStrike AI](https://github.com/0x4m4/hexstrike-ai) (13k stars) | MIT | An MCP server exposing 150+ tools over an HTTP API | None built in; the README advises adding oversight and authentication yourself | Vulnerability cards |

## Where the kit is different

- **Scope is enforced by the network, not the prompt.** Each engagement gets its own firewall rules, so a tool
  can't reach a host outside the scope even if the model tries. See [Engagements and scope](engagements.md).
- **People make the risky decisions.** An approval covers one exact command or request, once, under one policy
  revision. Report delivery, exceptions and waivers need a person, and the agent can't make them. See
  [Regression matrix](regression-matrix.md) for the tests that guard each rule.
- **Evidence you can defend.** Every command's output is hashed and linked to the audited command that produced
  it. A report revision freezes its inputs, so a tampered or outdated revision can't be approved or exported.
- **Client code and raw tool output stay with the worker.** The planner sees redacted summaries. Run the worker on
  your own GPU and nothing leaves your machine. See [Models](models.md#where-your-data-goes).
- **Results measured on evidence.** Benchmarks count a finding only when it names the right place and has the
  required evidence, and they also check that clean controls stay clean. See
  [Capability baselines](capability-baselines.md).
- **Nothing gated.** Everything above is in the Apache-2.0 code; there is no paid edition of the kit.

## Where others are ahead today

- **Exploit validation.** Strix and Shannon only report a finding with a working proof of concept. The kit hashes
  evidence and supports retests, but proving exploitability is left to the researcher. It's next on the
  [roadmap](../ROADMAP.md).
- **Install.** Several of the others install with one package command. The kit needs Docker, 16 GB of RAM
  (8 GB minimum), about 25 GB of disk and an OpenRouter key.
- **Autonomy.** Approvals pause the run by design. If you want an agent that never stops to ask, the kit isn't
  built for that.
- **Coverage.** No Active Directory, cloud account, Kubernetes or mobile playbooks yet. See
  [Capability baselines](capability-baselines.md#not-supported-as-complete-workflows).
- **Teams.** The kit is for one operator on one machine; there are no accounts or roles yet.

Found something out of date here? Open an issue or a pull request with a link to the source.
