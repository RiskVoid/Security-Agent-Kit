# Regression matrix

Each risk the kit has to control, and the test that fails if the control breaks. All tests run against the live
stack with a scripted model or none, so they need no GPU and no API key. How to run them:
[CONTRIBUTING.md](../CONTRIBUTING.md#tests).

**Platforms.** CI runs every suite on Linux (GitHub's Ubuntu runners, Docker Engine) on each pull request. The
suites also pass on macOS with Docker Desktop, where the kit is developed, but nothing runs them there
automatically. Windows is not tested.

| Risk | What must hold | Test (check names as the suite prints them) |
|---|---|---|
| Restart during a run | an action that was in flight when the worker stopped isn't repeated; it waits for review | `execution_state_test.sh`: "restart: action in flight -> needs_review", "resume does not repeat it" |
| Uncertain writes | a write whose result is unknown is never retried automatically | `execution_state_test.sh`: same checks; `authn_test.sh`: "the approval is used once" |
| Approval changes | an approval covers one exact command or request, once; a change to the scope, command, body, identity or matrix makes it stale | `phase3_policy_test.sh`: "different command refused", "approval is single-use"; `policy_test.sh`: "different body refused", "scope change makes an approval stale"; `authn_test.sh`: "approval for alice doesn't cover bob", "a matrix changed after approval is refused" |
| Concurrent limits | budgets and rate caps hold across parallel calls | `policy_test.sh`: "command budget enforced", "request budget enforced"; `phase3_policy_test.sh`: "rate flag injected (max 20 shared by 2)" |
| Concurrent writers | parallel writers to one engagement get unique, gapless ids and lose no revision; a new database opened by several processes at once migrates once | `regression_test.py`: "12 parallel finding records: unique, gapless ids", "6 parallel imports ...", "8 parallel plan items and 8 obligations ...", "6 parallel updates of one finding ..."; `unit_test.py`: `ConcurrentOpen` (ten processes writing to a new database at once) |
| Stale edits | an edit based on an old revision is a conflict, not an overwrite | `console_contract_test.py`: "stale finding revision gives 409", "stale scope revision gives 409"; `workspace_test.py`: "objective saved; a stale edit is a conflict" |
| Halt | halt stops running commands and worker tasks and refuses new ones, model calls included | `phase3_policy_test.sh`: "halt kills running command", "halted engagement refuses commands"; `execution_state_test.sh`: "halt stops the task and its command", "halted: worker calls refused" |
| Hostile content | text from a target or a tool is data: it never becomes an instruction, a decision or markup | `regression_test.py`: "the instruction is imported as an observation's text", "no finding changed and no decision was made"; `console_contract_test.py`: "agent-written text comes back as data, unchanged", "HTML report view is sandboxed, no scripts" |
| Cross-engagement access | one engagement can't read, import, link or preview another's files or findings | `regression_test.py`: "import refused: ...", "preview refused: ...", "linking to a finding id that exists only in another engagement is refused"; `phase3_policy_test.sh`: "only own engagement visible in /work" |
| Privacy boundaries | client data doesn't reach a cloud model; secrets don't reach evidence, logs, exports or notices | `execution_state_test.sh`: "planner refused (x-rv-engagement)", "value not in the audit log"; `authn_test.sh`: "no secret in plain text (control files, audit log, evidence)"; `regression_test.py`: "the secret is in no export, SARIF, issue text, notice or report page" |
| Sessions | an expired or invalid session can't produce a pass or a fail | `authn_test.sh`: "valid-session control: expired", "no FAIL claimed without a valid session" |
| Console from another site | a page elsewhere can't drive the console | `console_contract_test.py`: "cross-site POST refused (Origin)", "cross-site request refused (Sec-Fetch-Site)" |
| Finding ids and history | ids are never reused; every change is a revision with its actor and reason | `regression_test.py` (above); `workspace_test.py`: "history keeps every revision and the decisions with reasons" |
| Report integrity | a delivered report matches its frozen inputs; a tampered or outdated revision can't be approved, rebuilt or exported | `delivery_test.py`: "a modified revision file is detected", "rebuilt from the frozen inputs: identical HTML", "approval refused when the record changed since generation"; `regression_test.py`: "a revision whose frozen inputs were edited can't be approved", "... nor rebuilt", "... nor exported"; `phase5_e2e.sh`: "tampered evidence -> DRAFT" |
| Who decides | the agent can't approve, except, waive or review | `delivery_test.py`: "the agent can't approve a report", "the agent can't record an exception", "the agent can't waive an obligation", "the agent can't review a notice" |

What this matrix doesn't cover: the quality of what a model finds. That is measured separately, with benchmarks
([lab-and-benchmarks.md](lab-and-benchmarks.md#benchmarks)), and summarised per stack in
[capability-baselines.md](capability-baselines.md).
