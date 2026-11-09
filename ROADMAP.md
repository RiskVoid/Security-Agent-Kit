# Roadmap

What we plan to build next, in order. Dates aren't promised; the order is. Ideas and votes are welcome in
[Discussions](https://github.com/RiskVoid/Security-Agent-Kit/discussions), and the
[open issues](https://github.com/RiskVoid/Security-Agent-Kit/issues) show what's being worked on.

The kit competes on trust, not on autonomy: each item below extends scope enforcement, approvals, hashed evidence
and human decisions rather than working around them. What the kit is tested and measured for today is in
[docs/capability-baselines.md](docs/capability-baselines.md).

## Now: the first public release (0.1.x)

- Published benchmark baselines for every lab target, with the method and the spread across runs.
- Fixes from the first users on Linux and macOS.

## Next

1. **Published detection numbers, kept current.** A nightly benchmark run, outside benchmarks next to our own
   (XBOW's validation benchmarks, the OWASP Benchmark, the Juice Shop challenges), a public results page with
   every run, and a matrix of planner and worker models. A documented method so anyone can compare other tools.
2. **Verified findings.** A finding's proof of concept stored as an exact, replayable action that runs inside the
   engagement's scope and approvals. Deterministic checks decide whether it worked (a canary, a difference
   between identities, a timing difference, an out-of-band callback), and negative controls (the fixed build,
   another identity, a harmless payload) must stay clean. Retests replay the same proof automatically.
3. **Lighter onboarding.** The kit as one MCP server for the coding agent you already use; a smaller core image
   with the web tools pulled only when needed; a code-only mode with no Kali container; a hosted default worker
   so setup asks fewer questions; a Codespaces template to try the lab in the browser.
4. **A GitHub Action.** Scan a pull request's code, or test its deploy preview with that URL as the whole scope.
   Scope as code in the repository, a baseline of accepted findings, SARIF in code scanning, and a build that
   fails only on verified findings above a severity you choose.
5. **Separation of duties.** Console accounts and roles (lead, tester, reviewer, read-only client), a named
   person on every approval and exception, and four-eyes rules: whoever confirmed a finding can't approve the
   report that contains it. Remote access after a published threat model.
6. **Coverage packs: Kubernetes, then cloud, then Active Directory.** A pack is only claimed when it has a
   playbook, tiers, a lab target, a benchmark with clean controls and a measured result.

## Later

Windows (WSL2), IPv6 targets, adaptive AI red teaming with an attacker and judge model, offline vulnerability
databases, mobile applications, more framework packs (Django, FastAPI, Spring, Rails, Go) on the Laravel
pattern.
