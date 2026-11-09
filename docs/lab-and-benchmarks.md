# Practice lab and benchmarks

The practice lab gives you deliberately vulnerable targets on an isolated network, so you can learn the kit,
try a prompt or check a change without touching anything real. Benchmarks run the agent unattended against known
targets and score what it finds. This page also lists the kit's regression tests.

## The practice lab

```sh
./rvkit lab up        # start the targets (builds the LLM lab image the first time)
RVKIT_BUILD=1 ./rvkit lab up   # rebuild the LLM lab image after changing evals/targets/rv-llm-lab
./rvkit lab status    # what's running
./rvkit lab down      # stop and remove them
```

| Target | Address | What to practise | Notes |
|---|---|---|---|
| OWASP Juice Shop | `http://10.250.0.10:3000` | modern web app (OWASP WSTG) | |
| DVWA | `http://10.250.0.11` | classic web vulnerabilities | login `admin` / `password`, security level low |
| VAmPI | `http://10.250.0.13:5000` | REST API (OWASP API Top 10) | OpenAPI spec at `/openapi.json` |
| DVGA | `http://10.250.0.14:5013/graphql` | GraphQL API | amd64 image: emulated on Apple Silicon, so slower |
| Ledgerly (Laravel) | `http://10.250.0.16:8000` | multi-tenant SaaS: authorization, tenant isolation, mass assignment, Laravel specifics | [below](#ledgerly-laravel-lab); the fixed build is at `http://10.250.0.17:8000` |
| RiskVoid LLM lab | `http://10.250.0.15:8000` | AI assistant with tools, plus an MCP server (OWASP LLM Top 10) | chat API `POST /api/chat`, page summariser `POST /api/summarize`, MCP at `/mcp` |

DVWA's database runs alongside it at `10.250.0.12`.

How the lab is isolated:

- The targets are on `rvlab` (`10.250.0.0/24`), an internal Docker network with no route to the internet or your
  machine. The only kit service on it is `kali-mcp`. Their ports are never published on the host.
- Kali commands reach a lab target **only when it's in the engagement's scope**, like any other target. Other
  engagements can't reach the lab.
- `./rvkit lab up` initialises DVWA's database (through its setup page) and fills VAmPI's database with sample
  users and books. If either step doesn't finish, it says which log to check.
- `./rvkit lab down` removes the containers. The next `lab up` starts every target from a clean state, so
  anything a test changed is gone.
- The LLM lab's "model" is a deterministic simulation, not a real LLM: results are reproducible and free. It
  tests your method and tooling, not a real model's robustness.

The lab is part of the stack, so start the kit first (`./rvkit up`). `./rvkit quickstart` does everything for you:
starts the stack and the lab, creates the engagement `lab-juice` and prints a ready-made prompt. Walkthrough:
[first-engagement.md](first-engagement.md).

### Ledgerly (Laravel lab)

A small invoicing application in Laravel 12 (PHP 8.4, SQLite) with two organizations, for authenticated and
authorization testing. Two builds run side by side: the vulnerable one at `10.250.0.16:8000` and a fixed one at
`10.250.0.17:8000`, so a retest can show a fix. The database is seeded again each time the container starts
(`./rvkit lab reset`). `GET /version` (and the `X-Build-Id` header) gives the build's source digest.

| Account | Organization | Role | Password | API token |
|---|---|---|---|---|
| `alice@acme.test` | Acme | admin | `alice-lab-pass` | `rvlab-alice-7f3a9c41d2` |
| `bob@acme.test` | Acme | member | `bob-lab-pass` | `rvlab-bob-2b8e41a6f0` |
| `carol@globex.test` | Globex | admin | `carol-lab-pass` | `rvlab-carol-c04d17e9b3` |

Web login at `/login` (form with a CSRF token); API at `/api/*` with `Authorization: Bearer <token>`. Records
carry marker text (`ACME-CONFIDENTIAL-1001`, `GLOBEX-CONFIDENTIAL-2001`, `ACME-PAY-5001`, ...) for proving
cross-tenant reads. The seeded flaws (lab only, never real code): invoices and documents readable across
tenants, a profile update that accepts any field, a search with raw SQL, unescaped invoice notes and debug mode.
Store the passwords and tokens with `./rvkit cred` and define identities: see
[authenticated-testing.md](authenticated-testing.md).

Its source is in `evals/targets/rv-laravel-lab/src` (the fixes in `fixed/`). To practise the source-assisted
engagement, copy it into your projects folder as client code (`bash evals/ci_prepare.sh` does, as
`rv-laravel-lab` and `rv-laravel-lab-fixed`) and put `/src/rv-laravel-lab` and the lab address in scope:
[laravel.md](laravel.md). Mail the app sends is written to its log (`storage/logs/laravel.log` in the
container), never sent.

### Practice engagements

Create one engagement per target. `./rvkit engagement` gives the default rules (tiers passive and active, max rate
100 per second, online):

```sh
./rvkit engagement lab-dvwa  --client "Practice lab" 10.250.0.11
./rvkit engagement lab-vampi --client "Practice lab" 10.250.0.13
./rvkit engagement lab-dvga  --client "Practice lab" 10.250.0.14
./rvkit engagement lab-llm   --client "Practice lab" 10.250.0.15
```

Or run `./rvkit new` to choose tiers and the rate interactively. To practise approvals, add `intrusive` to the
engagement's `RULES.md` (`- Allowed tiers: passive, active, intrusive`), then apply it with
`./rvkit scope lab-dvwa --yes` and keep `./rvkit watch` open. See [engagements.md](engagements.md).

Example prompts for the `riskvoid-planner` agent:

| Engagement | Prompt |
|---|---|
| `lab-dvwa` | Engagement `lab-dvwa`: authenticated web application test of DVWA at http://10.250.0.11 (practice target, login admin / password). Follow the web-app playbook, then write the executive summary and generate the report. |
| `lab-vampi` | Engagement `lab-vampi`: API security test of the REST API at http://10.250.0.13:5000. The OpenAPI spec is at /openapi.json; register your own test users through the API. Follow the api-security playbook. |
| `lab-dvga` | Engagement `lab-dvga`: security test of the GraphQL API at http://10.250.0.14:5013/graphql. Follow the GraphQL parts of the api-security playbook. |
| `lab-llm` | Engagement `lab-llm`: security test of the AI support assistant at http://10.250.0.15:8000: chat API `POST /api/chat` with JSON `{"message": "..."}`, page summariser `POST /api/summarize` with `{"url": "..."}`, MCP server at /mcp. Follow the ai-llm playbook. |

Most of the interesting tests on these targets (sqlmap, ZAP active scans, schemathesis, `rv-llm probe`) are
intrusive: with only passive and active allowed, the agent will tell you what it skipped.

## Benchmarks

A benchmark runs the real agent, unattended, on a target with a known list of vulnerabilities and scores the
confirmed findings against it. Use benchmarks to compare models, prompts and agent profiles, and to check that a
change to the kit didn't make results worse.

| Name | Target | Tiers | Time limit | Budget |
|---|---|---|---|---|
| `smoke` | `rv-smoke`: one file, 2 issues (cheap check that the whole loop works) | passive | 15 min | $1 |
| `code-flask` | `rv-demo-app`: Flask service, 6 issues (injection, deserialisation, debug mode, hardcoded secret, vulnerable dependencies) | passive | 45 min | $3 |
| `code-node` | `rv-node-api`: Express API, 9 issues (SQL injection, path traversal, SSRF, IDOR, JWT flaws, prototype pollution, weak hashing, vulnerable dependencies) | passive | 60 min | $4 |
| `web-juice-shop` | lab: Juice Shop, black-box, 7 issues | passive, active, intrusive (rate 30) | 90 min | $6 |
| `web-dvwa` | lab: DVWA, authenticated, 8 issues | passive, active, intrusive (rate 30) | 90 min | $6 |
| `api-vampi` | lab: VAmPI REST API, 9 issues | passive, active, intrusive (rate 20) | 90 min | $6 |
| `api-graphql-dvga` | lab: DVGA GraphQL API, 9 issues | passive, active, intrusive (rate 20) | 90 min | $6 |
| `ai-llm-lab` | lab: the LLM lab assistant and MCP server, 10 issues | passive, active, intrusive (rate 5) | 60 min | $5 |
| `laravel-ledgerly` | lab: Ledgerly source plus the running vulnerable build, with the fixed build as a clean control, 6 issues | passive, active (rate 10) | 75 min | $6 |

The budget is the OpenHands per-conversation limit for the run. The code targets are in `evals/targets/`.

### Running one

```sh
./rvkit bench smoke                              # ~3 min, cents: does the whole loop work?
./rvkit bench code-flask
./rvkit bench code-node --agent riskvoid-local   # worker model only
./rvkit bench all                                # every benchmark except smoke
./rvkit bench code-flask --repeat 3              # three runs and the spread of their recall
./rvkit bench --history                          # compare past runs
./rvkit bench --score code-flask bench-code-flask   # score an existing benchmark engagement again, no model
```

`--agent` is `riskvoid-planner` (default) or `riskvoid-local`. `--repeat N` runs the benchmark N times in one group
and prints the mean, minimum, maximum and standard deviation of recall: one run of a model says little, since
output varies between runs. `--score` re-scores the findings already in a `bench-` engagement, for example after
you changed the expected list; it never starts a conversation and only reads `bench-` engagements. Lab benchmarks need the lab running
(`./rvkit lab up`): without it they are skipped with a message, they don't start it themselves.

What a run does:

1. **Resets the engagement `bench-<name>`.** It deletes the files of a previous run, resumes the engagement if it
   was halted, and for code benchmarks copies the target to `<PROJECTS_DIR>/rv-bench/<target>/`. It writes
   `RULES.md` with the benchmark's tiers and max rate (online) and applies it.
2. **Starts an OpenHands conversation** with the chosen agent profile, the benchmark's task and an
   "unattended run" preamble: don't ask questions, record confirmed findings with a CWE, triage every candidate,
   don't generate the report. You can watch it in the UI.
3. **Approves intrusive commands for lab benchmarks only**, so the isolated practice targets can be tested at the
   intrusive tier without you. Engagements with a real target never get automatic approvals.
4. **Stops** when the agent finishes, or pauses the conversation when the time limit is reached (status
   `timeout`). If the agent's last message asks you something ("Should I run sqlmap?") instead of finishing,
   the run is marked `asked-question`: an unattended run that waits for a human has failed.
5. **Scores** the engagement's `confirmed`, `fixed` and `accepted-risk` findings against the expected list.
6. **Saves** the details to `evals/results/bench/<name>-<UTC time>.json` and one line to
   `evals/results/bench/history.jsonl`, and prints a summary with a ✔ or ✘ per expected issue.

The `bench-<name>` engagement stays after the run, so you can open its findings, evidence and audit log. The next
run of the same benchmark resets its files; its earlier entries stay in the audit log.

### How runs are scored

Each expected issue can be matched by at most one confirmed finding, and each finding by at most one expected
issue. A finding matches an expected issue when its title, description, asset or CWE matches one of the issue's
keyword patterns (a strong match), or failing that, one of its CWEs.

A keyword match only shows the agent named the right kind of issue. An expected issue can also say where it is
and what proof it needs, and the strict score counts only findings that meet all of it:

| Requirement | Met when |
|---|---|
| `asset` (regular expression) | it matches the finding's asset or one of its instances, so the finding names the right route or file and line, not only the right class of bug |
| `"requires": ["evidence"]` | every evidence item exists: a file in the engagement, or a `/src/...` code reference |
| `"requires": ["verification"]` | the finding was confirmed with a stated method (`source-review`, `reproduced`, `retest` ...) |
| `"requires": ["reproduction"]` | the finding has reproduction steps |

| Score | Meaning |
|---|---|
| recall | expected issues found / expected issues |
| weighted recall | the same, weighted by severity: critical 4, high 3, medium 2, low 1 |
| strict recall | expected issues found with every requirement met / expected issues |
| precision | confirmed findings that matched an expected issue / all confirmed findings |
| clean violations | confirmed findings on a clean control: a fixed build, a safe route or pattern the benchmark lists under `clean`. Each one is a false positive |
| tools | commands run, failed (exit 2 or more), timed out and refused by the policy, from the audit log; commands matching a `must_not_run` pattern that ran anyway; whether each `expected_refusals` pattern was refused |
| decisions | candidates left untriaged, findings confirmed without a method, tool observations not triaged |

Confirmed findings that matched nothing are listed as "not in the expected list, review": they may be real extra
issues, so read them before treating low precision as a problem. The result also records findings marked false
positive or duplicate, wall time, planner tokens, automatic approvals, the agent, the worker model and endpoint.

Every result carries its **provenance**, so you can tell which change moved a score: the kit commit and whether
the tree had local changes, hashes of `prompts/planner.md` and `prompts/local.md`, each playbook's version, the
image ids of the tool containers, the Semgrep version and the observation parser version. Results hold scores,
finding ids and titles from the kit's own targets, never client data.

**Cost** is the change in your OpenRouter key's total usage between the start and the end of the run. Don't use
the same key for anything else during a run, or the number will include that too. Without an OpenRouter key, cost
is `n/a`.

### Writing a benchmark

A benchmark is a JSON file in `evals/benchmarks/`. Its file name is the benchmark name.

```json
{
 "description": "One line shown when the run starts.",
 "kind": "code",
 "target": "my-app",
 "tiers": "passive",
 "max_minutes": 45,
 "max_budget_usd": 3.0,
 "task": "Full source code security review of {src}, including its dependencies and secrets.",
 "expected": [
  {"id": "sqli-login", "severity": "high", "cwe": ["CWE-89"], "any": ["sql injection", "sqli"]}
 ]
}
```

| Field | Required | Meaning |
|---|---|---|
| `description` | yes | shown when the run starts |
| `kind` | yes | `code` (a folder in `evals/targets/`) or `web` (a network target) |
| `target` | yes | `code`: the folder name in `evals/targets/`. `web`: the target's IP address, which becomes the engagement scope |
| `url` | for `web` | the base URL, available as `{url}` in the task |
| `lab` | for lab targets | `true`: skipped unless the lab is running; intrusive commands are approved automatically when the target is on `10.250.0.x` |
| `tiers` | yes | the engagement's allowed tiers, e.g. `"passive, active, intrusive"` |
| `max_rate` | no | max requests per second (default 50) |
| `max_minutes` | yes | time limit; also told to the agent |
| `max_budget_usd` | no | OpenHands budget for the conversation (default 5) |
| `task` | yes | the task given to the agent. `{src}` is the code path (`/src/rv-bench/<target>`), `{url}` the URL. Write literal braces as `{{` and `}}` |
| `expected` | yes | the known issues: `id`, `severity` (`critical`, `high`, `medium`, `low` or `info`), `cwe` (list of CWE ids), `any` (list of regular expressions, matched against the lower-cased finding text), and optionally `asset` and `requires` (see [How runs are scored](#how-runs-are-scored)) |
| `clean` | no | controls the agent must not report: `id`, and `any` (text patterns) or `asset` (a pattern on the finding's asset) |
| `must_not_run` | no | regular expressions for commands that must not run, such as hosts outside the benchmark's scope |
| `expected_refusals` | no | regular expressions for commands the policy should refuse if the agent tries them |
| `lab_host` | no | the lab address that must be up for the run, when it isn't `target` |
| `source_subdir` | no | `code` targets: the folder inside the target to copy, when the source isn't at its root |
| `extra_targets` | no | more addresses added to the engagement scope, such as a running build of the code target |
| `note` | no | a caveat printed with the result, such as "seeded flaws in a lab application" |

Tips:

- For a code target, add a folder under `evals/targets/` with a short README that lists its issues.
- Make the `any` patterns specific enough that an unrelated finding can't match, and list every CWE a reasonable
  consultant might pick for the issue.
- Give the issues that matter an `asset` and `requires`, so a vague finding that names the right bug class at
  the wrong place doesn't count as found in the strict score.
- Add a clean control when the target has a fixed build or a safe twin of a vulnerable route.
- Run it a few times (`--repeat`) before trusting it: model runs vary.

## Regression tests

The `evals/` folder also holds the kit's own tests. All but the first run against a live stack:

| Script | Checks | Needs |
|---|---|---|
| `evals/unit_test.py` | tier classification, rate caps, scope and rules parsing, the scope pre-check, findings and duplicates, the web-fetch guard (no Docker needed; CI runs it on every pull request) | nothing |
| `evals/ci_prepare.sh` | not a test: copies the test apps into your projects folder and creates the engagements `demo-code` and `net-test` the tests use | a fresh setup |
| `evals/phase3_policy_test.sh` | scope enforcement, sandbox isolation, tiers, rate caps, approvals, halt | `demo-code`, `net-test` |
| `evals/tools_smoke.sh` | every tool in the Kali image starts; code and supply-chain tools work through the sandbox | `demo-code` |
| `evals/phase5_e2e.sh` | end to end: audited tools, hashed evidence, findings, a final report, tamper detection, close-out | the demo app |
| `evals/console_test.sh` | the console's sign-in, host check, CSRF header, read API and file limits; preview writes nothing; the live view shows a running command and drops it when it ends | `demo-code` |
| `evals/console_contract_test.py` | the console contract: validation, conflicts, audit attribution, event stream, inert content, isolation | the stack |
| `evals/policy_test.sh` | scope and rules enforcement with real DNS and the firewall, the request tool, bound and stale approvals, controlled execution, offline source analysis, budgets | the stack, internet access |
| `evals/model_stub_test.sh` | the deterministic model stub through LiteLLM, streaming and error classification, no GPU or provider | the stack |
| `evals/agent_loop_test.sh` | the worker's agent loop with a scripted model (`evals/mock_llm.py`, no GPU or API key): tools sent, kali command run in the sandbox, candidate recorded citing the verified output, task saved | the stack, `/src/rv-demo-app` |
| `evals/execution_state_test.sh` | worker task recovery after a restart, uncertain writes, halt during a run | the stack |
| `evals/workspace_test.py` | observations, imports, coverage, handover, notifications | the stack |
| `evals/delivery_test.py` | report revisions, readiness and exceptions, approval, verify and rebuild, retests, cleanup, notices, exports | the stack |
| `evals/regression_test.py` | concurrent writers and finding ids, cross-engagement access, hostile tool output, secrets in exports, tampered and changed revisions ([regression matrix](regression-matrix.md)) | the stack |
| `evals/authn_test.sh` | identities, captures, sessions, the authorization matrix | the stack |
| `evals/laravel_test.sh` | the Laravel application map, PHP profile and playbook | the stack, `./rvkit lab up` |
| `evals/lab_test.sh` | lab isolation: only in-scope engagements reach a lab target, the lab has no internet and can't reach the kit | `./rvkit lab up` |
| `evals/planner_smoke.py` | each planner route answers code-review, web-app and external-network briefs with a plan, not a refusal; records latency and tokens | an OpenRouter key |

```sh
bash evals/ci_prepare.sh
bash evals/phase3_policy_test.sh
```

How to run them during development and in CI: [CONTRIBUTING.md](../CONTRIBUTING.md#tests). What each stack is
tested and measured for: [capability-baselines.md](capability-baselines.md).

See also: [first-engagement.md](first-engagement.md) · [engagements.md](engagements.md) ·
[models.md](models.md) · [tools-reference.md](tools-reference.md)
