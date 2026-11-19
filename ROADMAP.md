# Roadmap

What we plan to build next, in order. Dates aren't promised; the order is. Ideas and votes are welcome in
[Discussions](https://github.com/RiskVoid/Security-Agent-Kit/discussions), and the
[open issues](https://github.com/RiskVoid/Security-Agent-Kit/issues) show what's being worked on.
The single index for all of it is [the roadmap issue (#145)](https://github.com/RiskVoid/Security-Agent-Kit/issues/145):
one place that links every epic and issue below, refreshed as the picture changes.

The kit competes on trust, not on autonomy: each item below extends scope enforcement, approvals, hashed evidence
and human decisions rather than working around them. What the kit is tested and measured for today is in
[docs/capability-baselines.md](docs/capability-baselines.md).

## Now (0.1.x): parity and proof

Three fronts, one stance: the kit gains the offensive reach of the most capable autonomous frameworks —
authenticated recon, governed exploitation, Active Directory and cloud — as packs with per-action approvals and
deterministic verification, so the reach never costs the moat.

1. **Offensive parity** ([epic #144](https://github.com/RiskVoid/Security-Agent-Kit/issues/144)): the capability
   gaps against the leading autonomous pentest agents, each shipped as a governed pack — identity-driven crawl
   (#135), JS analysis and feedback loops into the map (#136), the sweep on form-login targets (#137), an
   exploit pack with lockout-aware brute force (#139), the Active Directory pack (#140), the cloud pack (#141),
   approval bundles (#142) and the unattended-mode contract (#143), with the OAuth lab target (#138) owed by
   the sweep era.
2. **The research loop** ([epic #77](https://github.com/RiskVoid/Security-Agent-Kit/issues/77)): research
   packets, evidence links, a queue over open work and engagement-local method reuse — the planner and the worker
   stop repeating what the engagement already knows. Its phase-0 fixtures are landed (#81); it begins when the
   shared baseline (#82) runs.
3. **Published detection numbers** (⏸ blocked on a model budget): the one batch measurement of the
   harness-run checks (#75) and the fresh shared baseline it rides on (#82), then a nightly run, outside
   benchmarks next to our own, a public results page with every run, and a matrix of planner and worker models.
   A documented method so anyone can compare other tools.

The harness-run checks era that this follows is done: deterministic sweeps over the recon map (injection on
every parameter, JWT keys, mass assignment, ReDoS, CORS, headers), eight verification oracles with negative
controls, an unforgeable out-of-band catcher, a brokered race action, and coverage gaps that count as open
work — all lab-verified with no model, running in CI. [CHANGELOG](CHANGELOG.md) has the detail.

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

## Later

Windows (WSL2), IPv6 targets, adaptive AI red teaming with an attacker and judge model, offline vulnerability
databases, mobile applications.
