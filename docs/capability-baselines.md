# Capability baselines

What the kit can do for each kind of target, as four separate claims that are easy to blur:

| Claim | Means | Doesn't mean |
|---|---|---|
| **Executable available** | the tool starts in the Kali container | its output is parsed, correct, or safe in every mode |
| **Method implemented** | the kit has a playbook, a tool integration or a parser for the work | the method finds the issues it targets |
| **Lab-verified** | a test in `evals/` runs the method against a seeded lab target, with protected controls, and passes in CI | a model running the method unattended finds the same issues |
| **Measured model result** | a saved benchmark run of the real agent, scored as in [lab-and-benchmarks.md](lab-and-benchmarks.md#how-runs-are-scored) | the same result on other code, other models, or another run |

Last checked 2026-11-09. Re-check after changing the Kali image, a playbook or a
benchmark: `./rvkit bench --history` for measured results, the tests in
[regression-matrix.md](regression-matrix.md) for the lab-verified methods.

---

## Measured model results

One saved run exists. Nothing larger has been measured, and no paid benchmark run was made for this page.

| Date | Benchmark | Agent | Planner / worker | Result | Cost |
|---|---|---|---|---|---|
| 2026-11-07 | `smoke` (one file, 2 seeded issues) | `riskvoid-local` | Claude Sonnet 5.5 via OpenRouter / Qwen 3.7 Flash via OpenRouter | finished; 2 of 2 found, precision 1.0 (keyword and CWE scoring; the evidence-based strict score didn't exist yet) | $0.04 |

`riskvoid-local` names the agent profile, not where the model ran: that run's worker was a hosted endpoint, so it
shows neither local hardware nor a private data path. A two-issue fixture checks that the loop works; it says
nothing about coverage.

The benchmarks defined but not yet run with the current scoring: `code-flask`, `code-node`, `laravel-ledgerly`,
`web-juice-shop`, `web-dvwa`, `api-vampi`, `api-graphql-dvga`, `ai-llm-lab`. To measure one, run it several
times, since model output varies:

```sh
./rvkit lab up                                  # lab benchmarks only
./rvkit bench laravel-ledgerly --repeat 3
```

---

## Per stack

### PHP Laravel (the reference workflow: source plus staging)

| Claim | State |
|---|---|
| Executable available | Semgrep (PHP rules, offline), Gitleaks, TruffleHog, OSV-Scanner (`composer.lock`), Syft/Grype, the HTTP and browser tools. **No PHP or Composer in the Kali container**; the optional PHP profile is a separate pinned container (PHP 8.4, Composer 2.8) started only by `./rvkit php`. Joern can't analyse PHP without a PHP binary, so the kit makes no PHP data-flow claims |
| Method implemented | `laravel` playbook (version 1); application map from source (routes, middleware, policies, tenant scopes, mass-assignable columns, raw SQL and unescaped Blade sinks) with build identity; identities, captures, the sandboxed browser and authorization matrices; reports with readiness, approval and retests |
| Lab-verified | `laravel_test.sh` (31 checks): the map flags every seeded flaw in Ledgerly as a lead and none on the fixed build. `authn_test.sh` (36 checks): sign-in with CSRF, the seeded cross-tenant read FAILs, the fixed build and the protected payment route pass, no pass or fail without a valid session. Semgrep alone **misses** the raw SQL, the unescaped Blade output, the mass assignment and the cross-tenant reads ([laravel.md](laravel.md#pattern-and-data-flow-tools-on-php)) |
| Measured model result | none yet: `laravel-ledgerly` is defined (6 issues with asset and evidence requirements, the fixed build as a clean control) |

The operator workflow, end to end:

```sh
./rvkit engagement acme --client "Acme Ltd" --tiers passive,active staging.acme.test /src/acme-app
./rvkit appmap acme /src/acme-app --build-url https://staging.acme.test/version   # MATCHES or DOES NOT MATCH
./rvkit php acme routes /src/acme-app            # optional: runtime route export (asks before booting the app)
./rvkit identity acme set alice alice.json        # one identity per role and tenant; secrets by reference
./rvkit identity acme check alice
./rvkit conversation acme new "Follow the laravel playbook"
./rvkit authz acme list                           # review and approve the matrices the agent proposes
./rvkit authz acme approve <name>
./rvkit report acme                               # a revision with its readiness checks
./rvkit report acme approve R-001                 # a person approves delivery
```

Details: [laravel.md](laravel.md), [authenticated-testing.md](authenticated-testing.md),
[findings-and-reports.md](findings-and-reports.md).

### Python Flask

| Claim | State |
|---|---|
| Executable available | Semgrep (Python and Flask rules, offline), Bandit, Joern, pip-audit, OSV-Scanner, Gitleaks, TruffleHog, Syft/Grype |
| Method implemented | `code-review`, `secrets-review` and `supply-chain` playbooks; observation parsers for Semgrep and Bandit output |
| Lab-verified | `tools_smoke.sh`: the Flask Semgrep rules find the injection sinks in `rv-demo-app`; `phase5_e2e.sh` (40 checks): Bandit, Semgrep, Joern and pip-audit outputs hashed as evidence, findings confirmed by source review, a final report with every evidence file verified. No fixed build of the Flask target, so no clean control |
| Measured model result | none yet: `code-flask` is defined (6 issues; the injection and deserialisation items require the exact file and line, and evidence) |

### JavaScript and TypeScript (Express)

| Claim | State |
|---|---|
| Executable available | Semgrep, Joern, OSV-Scanner (`package-lock.json`), Gitleaks, TruffleHog, Syft/Grype, the HTTP and API tools. **No Node or npm in the Kali container**: the kit reads the code and lockfile but doesn't install or run the project |
| Method implemented | `code-review`, `api-security`, `secrets-review` and `supply-chain` playbooks |
| Lab-verified | no Express-specific test: the generic source tools are covered by `tools_smoke.sh` on other targets |
| Measured model result | none yet: `code-node` is defined (`rv-node-api`, 9 issues, keyword and CWE matching only) |

### Web applications and APIs (black box)

| Claim | State |
|---|---|
| Executable available | Nmap, Naabu, dnsx, Subfinder, Katana, httpx-toolkit, Nuclei, Nikto, FFUF, Feroxbuster, sqlmap, Dalfox, ZAP, testssl, sslscan, Schemathesis, jwt_tool, graphw00f, Chromium |
| Method implemented | `web-app`, `api-security` and `external-network` playbooks; the request tool (scope-checked, saved as verified evidence); approvals for intrusive commands |
| Lab-verified | `lab_test.sh` (18 checks): only the engagement with a lab target in scope reaches it; `policy_test.sh` (42 checks) and `phase3_policy_test.sh` (51 checks): scope, firewall, tiers, rate caps, approvals, halt. These verify the controls, not detection |
| Measured model result | none yet: `web-juice-shop`, `web-dvwa`, `api-vampi`, `api-graphql-dvga` are defined |

### AI applications and MCP servers

| Claim | State |
|---|---|
| Executable available | `rv-llm`, garak |
| Method implemented | `ai-llm` playbook |
| Lab-verified | `tools_smoke.sh` starts both tools; no test runs the method against the LLM lab |
| Measured model result | none yet: `ai-llm-lab` is defined (10 issues); its lab assistant is deterministic, so differences between runs come from the agent |

### Not supported as complete workflows

Django and FastAPI, Symfony, Spring and other JVM frameworks, ASP.NET, Go, Rails, native code, live cloud
accounts, Kubernetes, Active Directory, mobile applications and out-of-band callbacks. The generic tools may still
contribute to such an engagement, but no playbook, lab target or measured result backs a claim about them.

See also: [lab-and-benchmarks.md](lab-and-benchmarks.md) · [regression-matrix.md](regression-matrix.md) ·
[laravel.md](laravel.md)
