# Capability baselines

What the kit can do for each kind of target, as four separate claims that are easy to blur:

| Claim | Means | Doesn't mean |
|---|---|---|
| **Executable available** | the tool starts in the Kali container | its output is parsed, correct, or safe in every mode |
| **Method implemented** | the kit has a playbook, a tool integration or a parser for the work | the method finds the issues it targets |
| **Lab-verified** | a test in `evals/` runs the method against a seeded lab target, with protected controls, and passes in CI | a model running the method unattended finds the same issues |
| **Measured model result** | a saved benchmark run of the real agent, scored as in [lab-and-benchmarks.md](lab-and-benchmarks.md#how-runs-are-scored) | the same result on other code, other models, or another run |

Last checked 2026-11-10. Re-check after changing the Kali image, a playbook or a
benchmark: `./rvkit bench --history` for measured results, the tests in
[regression-matrix.md](regression-matrix.md) for the lab-verified methods.

---

## Measured model results

First baselines, measured on 2026-11-10: **one run of each benchmark, capped in spend**. Model output varies
between runs, so treat each row as one sample, not an average. Scoring is strict, as described in
[lab-and-benchmarks.md](lab-and-benchmarks.md#how-runs-are-scored):
- **found** counts expected issues reported as confirmed findings
- **with evidence** counts only those that also name the right asset and have every required piece of evidence
- **precision** is confirmed findings that match an expected issue, out of all confirmed findings; unmatched ones
  may still be real issues the benchmark doesn't list
- **clean** counts reports against a protected control (a fixed build or a safe pattern); 0 is the goal

Agent `riskvoid-planner`. Planner GPT-6.1 (`openai/gpt-6.1-sol`) with DeepSeek V4 Pro as its fallback; worker
DeepSeek V4.1 Flash (`deepseek/deepseek-v4.1-flash`), all through OpenRouter. Cost is the OpenRouter usage of the
key during the run (planner, fallback and worker together).

| Benchmark | Found | With evidence | Precision | Clean | Minutes | Cost | Planner calls refused, answered by the fallback |
|---|---|---|---|---|---|---|---|
| `code-flask` (Flask service) | 6 of 6 | 6 of 6 | 0.67 | 0 | 15 | $1.16 | 0 |
| `code-node` (Express API) | 9 of 9 | 6 of 9 | 0.50 | 0 | 16 | $1.48 | 0 |
| `laravel-ledgerly` (source plus staging, unattended) | 1 of 6 | 1 of 6 | 1.00 | 0 | 19 | $1.10 | 0 |
| `ai-llm-lab` (LLM app and MCP server) | 8 of 10 | 6 of 10 | 1.00 | 0 | 31 | $1.10 | 28 |
| `web-dvwa` | 8 of 8 | 8 of 8 | 0.40 | 0 | 62 | $3.13 | 77 |
| `web-juice-shop` | 3 of 7 | 2 of 7 | 0.25 | 0 | 30 | $1.85 | 15 |
| `api-graphql-dvga` | 3 of 9 | 3 of 9 | 0.75 | 0 | 36 | $1.01 | 28 |
| `api-vampi` (second run; the first stopped at once on a refused planner call, before the fix) | 3 of 9 | 2 of 9 | 1.00 | 0 | 10 | $0.52 | 4 |
| `smoke` (2-issue loop check) | 2 of 2 | 2 of 2 | 1.00 | 0 | 4 | $0.28 | 0 |

What the numbers say:
- **Source review is the strongest part.** On the two code targets the agent found every seeded issue. Its extra
  findings (dependency advisories, a possible XSS, unhandled async errors) need review rather than counting as
  wrong.
- **Black-box web and API testing is uneven.** DVWA was complete; Juice Shop, DVGA and VAmPI found a third to a
  half, and fewer with full evidence.
- **The unattended Laravel run is weak.** It ran without the intrusive tier and found one of six, and the scope
  pre-check refused two of its logins because it read the email address as a target (fixed after the run). The attended
  [release acceptance run](#release-acceptance-run) on the same lab, with a person approving the authorization
  matrix and the intrusive checks, confirmed three with evidence.
- **The default planner refuses some offensive work.** OpenAI's cyber-policy filter refused planner calls in
  every black-box lab run, and DeepSeek V4 Pro answered them, so those rows measure the two planners together.
  Before 2026-11-10 such a refusal stopped the conversation instead; see the CHANGELOG.
- **Two runs went over their cap.** The cap wasn't enforced until the `laravel-ledgerly` run: OpenHands' own
  per-conversation budget can't price the gateway's model alias. The harness now pauses a run at its cap.

Every run's data is kept: the engagement folder (findings database, evidence, report revisions with their frozen
inputs) and the whole conversation, in `evals/results/bench/<name>-<UTC>/`. Reports can be rebuilt from it.

### GLM as planner and worker

On 2026-11-11 four of the benchmarks ran with another model pair: planner GLM-5.3 (`z-ai/glm-5.3`) with DeepSeek
V4 Pro as its fallback, worker GLM-5.3 Flash (`z-ai/glm-5.3-flash`), through OpenRouter. Agent
`riskvoid-planner`, **one run each, capped at $1.20**. `code-flask`, `code-node`, `ai-llm-lab`, `web-dvwa` and
`smoke` have not run with this pair.

These runs are not a like-for-like comparison with the table above. They used a newer harness: the task now
requires a test plan with an outcome for every planned test, and precision also counts real issues of the lab
that are outside the expected list (a second instance of an expected issue, or a known issue listed under
`also_valid` in the benchmark). The table gives precision both ways; **expected only** is the figure the first
baselines used.

| Benchmark | Found | With evidence | Precision, expected only | Precision, with known lab issues | Clean | Minutes | Cost | Planner calls refused |
|---|---|---|---|---|---|---|---|---|
| `api-vampi` | 8 of 9 | 0 of 9 | 0.53 | 0.93 | 0 | 14 | $0.56 | 0 |
| `laravel-ledgerly` (source plus staging, unattended) | 5 of 6 | 0 of 6 | 1.00 | 1.00 | 0 | 7 | $0.28 | 0 |
| `web-juice-shop` (stopped at the spend cap) | 5 of 7 | 3 of 7 | 0.36 | 0.86 | 0 | 24 | $1.22 | 0 |
| `api-graphql-dvga` | not measured | | | | | 76 | $0.27 | 0 |

What the numbers say:
- **GLM found more of the seeded issues, for less.** VAmPI went from 3 to 8 of 9, Ledgerly from 1 to 5 of 6 and
  Juice Shop from 3 to 5 of 7, at about the same cost or lower. The harness change above may account for part
  of that.
- **It did not record the proof the strict score needs.** No finding on VAmPI or Ledgerly had a verification
  method, and the VAmPI findings linked no evidence files, so neither run has a finding that counts as "with
  evidence". Juice Shop had three.
- **No planner call was refused.** The gateway logged no refusal and no fallback during the four runs, so these
  rows measure GLM alone.
- **The DVGA run measured nothing.** The agent reported that the target accepted connections but never answered
  an HTTP request during the whole run, and it recorded no findings. Restart the lab and run it again before
  reading anything into it.
- **Juice Shop stopped at the cap** with every finding triaged; a higher cap would give it more time.

**After the confirmation rule.** The missing proof had a cause in the kit: `record_finding` took no verification
method, so a finding recorded as confirmed in one call had none. The agent's tools now refuse a confirmed finding
without a method, and without an evidence file for the methods that produce output. Two runs later the same day
with that change, same models, capped at $0.90:

| Benchmark | Found | With evidence | Precision, expected only | Precision, with known lab issues | Clean | Minutes | Cost | Planner calls refused |
|---|---|---|---|---|---|---|---|---|
| `api-vampi` (stopped at the spend cap) | 8 of 9 | 7 of 9 | 0.73 | 0.91 | 0 | 8 | $0.96 | 0 |
| `laravel-ledgerly` (stopped by OpenHands as stuck) | 0 of 6 | 0 of 6 | n/a | n/a | 0 | 9 | $0.48 | 0 |

- **VAmPI went from 0 to 7 of 9 with evidence**, and every confirmed finding has a method. The eighth names a
  different endpoint than the benchmark expects.
- **The Ledgerly run failed before it recorded anything.** The planner repeated one refused `update_coverage`
  call (a blocked test without a rationale) until OpenHands stopped the conversation as stuck. The run the night
  before finished, so this is one bad run in two, not a measure of the rule. It does show a weakness of this
  planner: it can repeat a refused call instead of reading the refusal.

### Release acceptance run

On 2026-11-10 the kit ran its release acceptance scenario on the Ledgerly lab, with the same models and a person
in the console. The scenario covers one engagement end to end: map and plan, source and baseline checks, an
approved authorization matrix, an approved intrusive check, a service restart, triage against the fixed build,
coverage, report approval, and retests. It was recorded; the
[README](../README.md) shows a cut, and the reports it produced are in [samples](samples/).

| Measure | Result |
|---|---|
| Confirmed with evidence | 3 of 6 seeded issues: cross-tenant invoices, mass assignment, search SQL injection; cross-tenant documents were grouped into the invoice finding |
| False confirmations on clean controls | 0 (the fixed build was tested and each finding says whether it is affected) |
| Approvals | 1 authorization matrix (12 requests, 5 identities) and 7 intrusive actions, each approved once in the console |
| Resume after approval without a chat message | yes, 21 seconds after the first approval |
| Recovery after a service restart | partial: findings, evidence and decisions were intact, but OpenHands did not reconnect to the restarted tool server until it was restarted itself. Fixed after the run: the tool servers no longer keep sessions, so an open conversation continues after a restart |
| Report | 4 revisions; R-003 approved for delivery; a later revision left it unchanged |
| Defects found and fixed during the run | 3: report provenance for HTTP evidence, the planner fallback on in-stream refusals, a browser download ending the run (see the CHANGELOG) |
| Time and cost | about 30 minutes, $1.44 |

---

## Per stack

### PHP Laravel (the reference workflow: source plus staging)

| Claim | State |
|---|---|
| Executable available | Semgrep (PHP rules, offline), Gitleaks, TruffleHog, OSV-Scanner (`composer.lock`), Syft/Grype, the HTTP and browser tools. **No PHP or Composer in the Kali container**; the optional PHP profile is a separate pinned container (PHP 8.4, Composer 2.8) started only by `./rvkit php`. Joern can't analyse PHP without a PHP binary, so the kit makes no PHP data-flow claims |
| Method implemented | `laravel` playbook (version 1); application map from source (routes, middleware, policies, tenant scopes, mass-assignable columns, raw SQL and unescaped Blade sinks) with build identity; identities, captures, the sandboxed browser and authorization matrices; reports with readiness, approval and retests |
| Lab-verified | `laravel_test.sh` (31 checks): the map flags every seeded flaw in Ledgerly as a lead and none on the fixed build. `authn_test.sh` (36 checks): sign-in with CSRF, the seeded cross-tenant read FAILs, the fixed build and the protected payment route pass, no pass or fail without a valid session. Semgrep alone **misses** the raw SQL, the unescaped Blade output, the mass assignment and the cross-tenant reads ([laravel.md](laravel.md#pattern-and-data-flow-tools-on-php)) |
| Measured model result | `laravel-ledgerly`, unattended: 1 of 6 with evidence. Attended acceptance run: 3 of 6, no clean-control violations ([above](#release-acceptance-run)) |

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
| Measured model result | `code-flask`: 6 of 6 with evidence, precision 0.67 ([above](#measured-model-results)) |

### JavaScript and TypeScript (Express)

| Claim | State |
|---|---|
| Executable available | Semgrep, Joern, OSV-Scanner (`package-lock.json`), Gitleaks, TruffleHog, Syft/Grype, the HTTP and API tools. **No Node or npm in the Kali container**: the kit reads the code and lockfile but doesn't install or run the project |
| Method implemented | `code-review`, `api-security`, `secrets-review` and `supply-chain` playbooks |
| Lab-verified | no Express-specific test: the generic source tools are covered by `tools_smoke.sh` on other targets |
| Measured model result | `code-node`: 9 of 9 found, 6 with evidence, precision 0.50 ([above](#measured-model-results)) |

### Web applications and APIs (black box)

| Claim | State |
|---|---|
| Executable available | Nmap, Naabu, dnsx, Subfinder, Katana, httpx-toolkit, Nuclei, Nikto, FFUF, Feroxbuster, sqlmap, Dalfox, ZAP, testssl, sslscan, Schemathesis, jwt_tool, graphw00f, Chromium |
| Method implemented | `web-app`, `api-security` and `external-network` playbooks; the request tool (scope-checked, saved as verified evidence); approvals for intrusive commands |
| Lab-verified | `lab_test.sh` (18 checks): only the engagement with a lab target in scope reaches it; `policy_test.sh` (42 checks) and `phase3_policy_test.sh` (51 checks): scope, firewall, tiers, rate caps, approvals, halt. These verify the controls, not detection |
| Measured model result | `web-dvwa` 8 of 8, `web-juice-shop` 2 of 7, `api-graphql-dvga` 3 of 9, `api-vampi` 2 of 9, with evidence ([above](#measured-model-results)) |

### AI applications and MCP servers

| Claim | State |
|---|---|
| Executable available | `rv-llm`, garak |
| Method implemented | `ai-llm` playbook |
| Lab-verified | `tools_smoke.sh` starts both tools; no test runs the method against the LLM lab |
| Measured model result | `ai-llm-lab`: 8 of 10 found, 6 with evidence, precision 1.0 ([above](#measured-model-results)); its lab assistant is deterministic, so differences between runs come from the agent |

### Not supported as complete workflows

Django and FastAPI, Symfony, Spring and other JVM frameworks, ASP.NET, Go, Rails, native code, live cloud
accounts, Kubernetes, Active Directory, mobile applications and out-of-band callbacks. The generic tools may still
contribute to such an engagement, but no playbook, lab target or measured result backs a claim about them.

See also: [lab-and-benchmarks.md](lab-and-benchmarks.md) · [regression-matrix.md](regression-matrix.md) ·
[laravel.md](laravel.md)
