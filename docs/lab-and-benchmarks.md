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

The budget is the OpenHands per-conversation limit for the run. The code targets are in `evals/targets/`.

### Running one

```sh
./rvkit bench smoke                              # ~3 min, cents: does the whole loop work?
./rvkit bench code-flask
./rvkit bench code-node --agent riskvoid-local   # worker model only
./rvkit bench all                                # every benchmark except smoke
./rvkit bench --history                          # compare past runs
```

`--agent` is `riskvoid-planner` (default) or `riskvoid-local`. Lab benchmarks need the lab running
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

| Score | Meaning |
|---|---|
| recall | expected issues found / expected issues |
| weighted recall | the same, weighted by severity: critical 4, high 3, medium 2, low 1 |
| precision | confirmed findings that matched an expected issue / all confirmed findings |

Confirmed findings that matched nothing are listed as "not in the expected list, review": they may be real extra
issues, so read them before treating low precision as a problem. The result also records candidates left
untriaged, findings marked false positive, wall time, planner tokens, automatic approvals, the agent, the worker
model and endpoint, and a hash of `prompts/planner.md`, so you can tell prompt versions apart in the history.

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
| `expected` | yes | the known issues: `id`, `severity` (`critical`, `high`, `medium`, `low` or `info`), `cwe` (list of CWE ids), `any` (list of regular expressions, matched against the lower-cased finding text) |

Tips:

- For a code target, add a folder under `evals/targets/` with a short README that lists its issues.
- Make the `any` patterns specific enough that an unrelated finding can't match, and list every CWE a reasonable
  consultant might pick for the issue.
- Run it a few times before trusting it: model runs vary.

## Regression tests

The `evals/` folder also holds the kit's own tests. All but the first run against a live stack:

| Script | Checks | Needs |
|---|---|---|
| `evals/unit_test.py` | tier classification, rate caps, scope and rules parsing, the scope pre-check, findings and duplicates, the web-fetch guard (no Docker needed; CI runs it on every pull request) | nothing |
| `evals/ci_prepare.sh` | not a test: copies the test apps into your projects folder and creates the engagements `demo-code` and `net-test` the tests use | a fresh setup |
| `evals/phase3_policy_test.sh` | scope enforcement, sandbox isolation, tiers, rate caps, approvals, halt | `demo-code`, `net-test` |
| `evals/tools_smoke.sh` | every tool in the Kali image starts; code and supply-chain tools work through the sandbox | `demo-code` |
| `evals/phase5_e2e.sh` | end to end: audited tools, hashed evidence, findings, a final report, tamper detection, close-out | the demo app |
| `evals/console_test.sh` | the console's sign-in, host check, CSRF header, read API and file limits; preview writes nothing | `demo-code` |
| `evals/lab_test.sh` | lab isolation: only in-scope engagements reach a lab target, the lab has no internet and can't reach the kit | `./rvkit lab up` |
| `evals/planner_smoke.py` | each planner route answers the planner prompt with a plan, not a refusal; records latency and tokens | an OpenRouter key |

```sh
bash evals/ci_prepare.sh
bash evals/phase3_policy_test.sh
```

How to run them during development and in CI: [CONTRIBUTING.md](../CONTRIBUTING.md#tests).

See also: [first-engagement.md](first-engagement.md) · [engagements.md](engagements.md) ·
[models.md](models.md) · [tools-reference.md](tools-reference.md)
