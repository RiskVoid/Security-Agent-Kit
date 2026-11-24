# Roadmap

What we plan to build next, in order. Dates aren't promised; the order is. Ideas and votes are welcome in
[Discussions](https://github.com/RiskVoid/Security-Agent-Kit/discussions), and the
[open issues](https://github.com/RiskVoid/Security-Agent-Kit/issues) show what's being worked on.
The single index for all of it is [the roadmap issue (#145)](https://github.com/RiskVoid/Security-Agent-Kit/issues/145):
one place that links every epic and issue below, refreshed as the picture changes.

The kit competes on trust, not on autonomy: each item below extends scope enforcement, approvals, hashed evidence
and human decisions rather than working around them. What the kit is tested and measured for today is in
[docs/capability-baselines.md](docs/capability-baselines.md).

Independent validation: the November 2026 GTIG report on [agentic threat activity](https://cloud.google.com/blog/topics/threat-intelligence/agentic-threat-activity-crosses-a-significant-threshold) names the leading tradecraft — multi-agent frameworks, differential patch analysis, machine-readable attack recipes — and separately warns that LLM-generated exploits "claimed to work but don't" are flooding defenders, which is exactly the verification gap the kit's deterministic oracles answer. Items 8–10 below turn the transferable techniques into governed capability; the evasion and full-autonomy parts are deliberately not adopted.

## Now (0.2.x): measure the research loop, then parity

0.2.0 shipped the research loop: the planner and the worker work from the engagement's records instead of their
context. Two fronts now, one stance: every new capability is measured before it is relied on, and the kit gains
the reach of the most capable autonomous frameworks as governed packs with per-action approvals and
deterministic verification, so the reach never costs the moat.

1. **The research loop, measured** ([epic #77](https://github.com/RiskVoid/Security-Agent-Kit/issues/77)):
   research packets, facts at every tool call, experiments and conclusions, a queue over open work with work
   keys, and engagement-local method reuse have landed (phases A to D, with capacity from phase E pulled
   forward). Two runs on it are in the [baselines](docs/capability-baselines.md#the-research-loop-first-runs).
   What's left: the fresh shared baseline (#82) and the measurement of each phase against it (#88, #94, #101,
   #105, #109); then an escalation ladder with parking and reopening on record (#97), task profiles for bounded
   reconnaissance and assumption review (#99, #108), replanning on events (#100), and playbook search (#103).
   Whether the queue may dispatch on its own is decided by #101's numbers, not before.
2. **Offensive parity** ([epic #144](https://github.com/RiskVoid/Security-Agent-Kit/issues/144)): the capability
   gaps against the leading autonomous pentest agents, each shipped as a governed pack. Authenticated recon and
   the sweep with an identity (#135, #136, #137) and the OAuth lab target (#138) have landed; still to come are
   an exploit pack with lockout-aware brute force (#139), the Active Directory pack (#140), the cloud pack
   (#141), approval bundles (#142) and the unattended-mode contract (#143).
3. **Published detection numbers** (⏸ blocked on a model budget): repeated runs on a fixed model pair, then a
   nightly run, outside benchmarks next to our own, a public results page with every run, and a matrix of
   planner and worker models. A documented method so anyone can compare other tools. Until then the free-tier
   model pair is the measured floor: the whole suite at $0, one run each.

Done since 0.1.0: the harness engineering epic (#52: worker context, the task contract, verification oracles,
the validator, failure mining, the improvement loop), the harness-run checks (#76: deterministic sweeps over the
recon map, eight verification oracles with negative controls, an unforgeable out-of-band catcher, a brokered
race action, coverage gaps as open work), most of the web-workflow epic (#168: the sweep fused into the recon
pass, every identity swept, gaps offered as pre-shaped tasks), and the research loop's phases A to D (#77). All
lab-verified with no model and running in CI. [CHANGELOG](CHANGELOG.md) has the detail.

## Next

4. **Lighter onboarding.** The kit as one MCP server for the coding agent you already use; a smaller core image
   with the web tools pulled only when needed; a code-only mode with no Kali container; a hosted default worker
   so setup asks fewer questions; a Codespaces template to try the lab in the browser.
5. **A GitHub Action.** Scan a pull request's code, or test its deploy preview with that URL as the whole scope.
   Scope as code in the repository, a baseline of accepted findings, SARIF in code scanning, and a build that
   fails only on verified findings above a severity you choose.
6. **Separation of duties.** Console accounts and roles (lead, tester, reviewer, read-only client), a named
   person on every approval and exception, and four-eyes rules: whoever confirmed a finding can't approve the
   report that contains it. Remote access after a published threat model.
7. **More framework packs: Django and FastAPI first, then Spring, Rails and Go**, on the Laravel pattern. A pack
   is only claimed when it has a playbook, tiers, a lab target, a benchmark with clean controls and a measured
   row.
8. **n-day research** (epic [#153](https://github.com/RiskVoid/Security-Agent-Kit/issues/153)): differential
   patch analysis and governed weaponization — diff a patched and unpatched version to find the flaw a fix
   closed, map it to its CVE and affected range, and decide whether a client's build is exposed. Passive and
   offline; anything that runs against a target stays in the exploit pack (#139).
9. **AI-agent supply chain** (epic [#154](https://github.com/RiskVoid/Security-Agent-Kit/issues/154)): the
   report's agent-config and startup vectors — attacker-modified `.claude/settings.json`/MCP registrations that
   drop a backdoor on startup, and LLMJacking. Adds the TTP to the ai-llm playbook and a lab target, and hardens
   the kit's own `.claude/` and MCP trust model.
10. **Executable attack recipes** (epic [#155](https://github.com/RiskVoid/Security-Agent-Kit/issues/155)): a
    machine-readable form of the playbooks the worker follows step by step, with per-step evidence and the normal
    approvals. Complements the Markdown playbooks; no new orchestrator.
11. **Web workflow: the kit checks first** (epic [#168](https://github.com/RiskVoid/Security-Agent-Kit/issues/168)):
    the fixed sweeps are now the default phase of web testing (`probe_map` as the second half of the recon
    pass, every identity swept, gaps offered as pre-shaped `delegate_task` calls, blind-SSRF payloads
    approval-tiered, coverage refusals that teach their shape). What's left is the measured before-and-after
    for each phase (#175).

## Later

Windows (WSL2), IPv6 targets, adaptive AI red teaming with an attacker and judge model, offline vulnerability
databases, mobile applications.
