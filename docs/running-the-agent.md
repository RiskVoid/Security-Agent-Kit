# Running the agent

How to work with the agent day to day: starting a conversation, writing the task, following and steering a run,
and picking up again after a break, a restart or a client fix. It assumes the kit is set up
([getting-started.md](getting-started.md)) and an engagement exists ([engagements.md](engagements.md)).

---

## Open the UI and pick an agent

Open **http://localhost:8000/**. The start page skips OpenHands' generic onboarding and opens the agent UI with the
kit's defaults selected. Start a **new conversation** and check the agent:

| Agent | Models | Use it when |
|---|---|---|
| `riskvoid-planner` (default) | planner (OpenRouter) for planning and write-up; worker model for tool work, through `delegate_task` | you want the best results and an OpenRouter key is set |
| `riskvoid-local` | `private-llm` only: your worker endpoint, never a fallback | nothing may go to a cloud model, or you have no OpenRouter key |

`riskvoid-local` has the same tools except the worker delegation tool: the model runs the Kali tools itself. Its
quality depends on your worker model. See [models.md](models.md) for what each model sees.

Before you start, check that the pieces are up:

```sh
./rvkit status        # services, worker reachable?, planner, spend, pending approvals
```

If the worker isn't reachable, the planner can still run Kali commands itself, but tool output then goes to the
planner instead of staying with the worker. Start the worker first if that matters ([models.md](models.md)).

---

## Writing the task

The first message sets up the whole run. Include:

1. **The engagement name, in backticks.** The agent uses it for every tool call and reads its scope and rules.
2. **The type of test** (it picks the matching playbooks from that).
3. **The targets** to focus on, if not everything in scope.
4. **Limits** beyond `RULES.md`, if any ("passive only for now", "no authenticated testing").
5. **What to produce** at the end (usually: findings, executive summary, report).

Useful context: test accounts, the API spec location, known sensitive areas, what the client is worried about.
Never paste live production credentials you don't want in the conversation; tell the agent where the test
accounts are documented instead.

### Templates

Replace the engagement name, targets and details. Each one works as the first message.

**Source code review**

> Engagement `acme-2026-11`: source code security review of `/src/acme-webshop` (Python/Django). Follow the
> code-review playbook at ASVS level 2, plus the secrets-review and supply-chain playbooks. Verify every
> candidate against the code before confirming it, then write the executive summary and generate the report.

**Secrets review**

> Engagement `acme-2026-11`: secrets review of `/src/acme-webshop`, including git history. Follow the
> secrets-review playbook. For each secret, record where it is and whether it looks live; never repeat the value.
> Then write the executive summary and generate the report.

**Dependency and supply-chain review**

> Engagement `acme-2026-11`: dependency and supply-chain review of `/src/acme-webshop` and its Dockerfile.
> Follow the supply-chain playbook: SBOM, known vulnerabilities ranked with the intel tools (KEV, EPSS, CVSS),
> fixed versions in the remediation. Then write the executive summary and generate the report.

**Web application**

> Engagement `acme-2026-11`: web application test of https://app.acme.com. Follow the web-app playbook. Test
> accounts: `alice` / `bob` (passwords in `NOTES.md`). Passive and active tiers first; ask me before any
> intrusive step. Then write the executive summary and generate the report.

**REST API**

> Engagement `acme-2026-11`: REST API test of https://api.acme.com, spec at https://api.acme.com/openapi.json.
> Follow the api-security playbook (OWASP API Top 10), with two test users for authorisation checks: alice and
> bob, credentials in `/src/acme-api/docs/testing.md`. Ask me before fuzzing. Then write the executive summary and
> generate the report.

**GraphQL API**

> Engagement `acme-2026-11`: GraphQL API test of https://api.acme.com/graphql. Follow the api-security
> playbook's GraphQL steps: fingerprint, introspection or schema recovery, authorisation per query and mutation,
> batching and depth limits. Ask me before anything intrusive. Then write the executive summary and generate the
> report.

**AI / LLM application**

> Engagement `acme-2026-11`: security test of the support chatbot at https://chat.acme.com (chat API
> `POST /api/chat`, JSON `{"message": ...}`). Follow the ai-llm playbook: prompt injection, system prompt leakage,
> insecure output handling, excessive agency of its tools. Probes are intrusive, so ask me first. Then write the
> executive summary and generate the report.

**MCP server**

> Engagement `acme-2026-11`: security review of the MCP server at https://mcp.acme.com/mcp. Follow the ai-llm
> playbook's MCP checks: enumerate tools, check auth, tool descriptions for injected instructions, and dangerous
> tool arguments. Ask me before calling any tool. Then write the executive summary and generate the report.

**External network**

> Engagement `acme-2026-11`: external network assessment of 203.0.113.0/28 and *.acme.io. Follow the
> external-network playbook: passive recon, then port and service discovery at the engagement's rate limit, then
> vulnerability analysis. List any hosts you discover outside scope as candidate scope additions; don't test them.
> Then write the executive summary and generate the report.

**Retest after fixes**

> Engagement `acme-2026-11`: the client says they fixed F-001, F-003 and F-004. Retest each one with the same
> method as before. Mark it fixed if it no longer reproduces, with the new evidence; otherwise keep it confirmed
> and add a note. Update the executive summary and generate the report.

**Report only**

> Engagement `acme-2026-11`: testing is finished. Triage every remaining candidate (confirm or mark false
> positive, with the reason), write the executive summary and generate the report. Fix whatever keeps it a
> draft.

The [lab](lab-and-benchmarks.md) is a good place to try these first.

---

## What the agent does

With `riskvoid-planner`, a typical run goes:

1. **Checks the engagement.** `list_engagements` / `engagement_info`: scope, tiers, rate, network, window.
2. **Plans.** `list_playbooks` and `get_playbook` for every playbook that fits, then writes `PLAN.md`
   (objectives, the playbooks' checklists adapted to the targets, tools per step) with `write_file`.
3. **Works through the plan**, least intrusive first:
   - hands focused tool work to the worker with `delegate_task` (one goal, a tier, what to return). The worker runs
     the Kali commands, saves raw output under `evidence/tasks/<task_id>/`, records **candidate** findings and
     returns a short summary with secrets redacted;
   - or runs a Kali command itself with the kali `run` tool, for small checks or when the worker is down;
   - looks up vulnerability ids with the intel tools and reads public pages with the web tools.
4. **Asks you** before intrusive steps, and whenever scope or rules are unclear.
5. **Verifies.** Reproduces each candidate, reads the code path or checks the version, then marks it
   `confirmed` or `false-positive` (with the reason).
6. **Writes up.** `report/executive-summary.md` (and optionally methodology and conclusion), then
   `generate_report`. If the report comes back DRAFT, it fixes what's listed and regenerates.
7. **Summarises** what was tested, what was found by severity, what wasn't covered, and next steps.

With `riskvoid-local`, steps 3 and 5 happen in the one model, one Kali command at a time.

---

## Following a run

Keep a terminal open next to the UI:

```sh
./rvkit watch                    # approve or deny intrusive commands as they come in
```

And when you want to look closer:

```sh
./rvkit status                   # pending approvals, spend so far
./rvkit audit acme-2026-11 50    # the last 50 commands, refusals and approvals
```

In the engagement folder (`~/riskvoid/engagements/acme-2026-11/` by default):

- `PLAN.md`: the checklist, ticked as the agent goes.
- `evidence/tasks/<task_id>/`: each worker task's tool calls (`step-NN-<tool>.txt`) and full transcript
  (`transcript.jsonl`).
- Tool output files written by Kali commands.

You can also ask the agent: "list the worker tasks" (`list_tasks`), "what's the status of task …" (`get_task`),
"list the findings so far" (`list_findings`).

---

## Steering

- **Answer its questions.** It stops and asks about scope questions, intrusive steps and unclear rules.
- **Approvals.** Approve or deny in `./rvkit watch` (or `./rvkit approve <eng> <id>`), then tell the agent
  "approved, go ahead" so it runs the command again with the approval id. A denial: tell it what to do instead.
- **Redirect.** Type into the conversation at any time: "skip the directory brute force", "focus on the payment
  API", "stop scanning and verify the candidates you have".
- **Stop at once.** `./rvkit halt <eng>` kills every running command for the engagement and refuses new ones.
  The conversation keeps going; tell the agent what happened. `./rvkit resume <eng>` when you're ready. You can
  also stop the agent itself with the stop button in the UI.
- **Change scope.** Edit `SCOPE.md` / `RULES.md`, run `./rvkit scope <eng> --yes`, then tell the agent the scope
  changed so it reads it again. See [engagements.md](engagements.md#changing-scope-and-rules).

---

## Picking up again

The engagement's state lives in its folder, not in the conversation: `PLAN.md`, `NOTES.md`, `.rv/findings.db`, the
evidence files and the audit log. So you can always continue, in the same conversation or a new one.

| Situation | What to do |
|---|---|
| You closed the browser, or come back the next day | Open the same conversation (conversations are kept) and say "continue". |
| `./rvkit down` / `./rvkit up`, or a computer restart | Conversations and engagement files are kept. Open the conversation and say "continue". Finished worker tasks can still be collected with `get_task`. A task that was running shows as `interrupted`; its partial evidence is under `evidence/tasks/`, so ask the agent to read it or rerun the task. |
| The Colab worker stopped (idle shutdown, session ended) | Start it again (`/rv-start`, or the notebook and `./rvkit connect …`), check with `./rvkit test`. Then tell the agent to retry. If the conversation shows connection errors, start a new one. |
| A command was refused | Read the reason. `REFUSED: targets not in scope` / `tier` / `window` / `halted`: fix the scope or rules with `./rvkit scope`, or tell the agent to work within them. Don't let it rephrase the command to get around a refusal. |
| A tool failed or timed out | Ask the agent to run it again, narrower (fewer targets, a smaller wordlist) or with a longer timeout (up to 3,600 s; delegate runs longer than 30 minutes to the worker). |
| You want one tool run again | Say exactly that: "run nuclei again against app.acme.com with the latest templates and update the findings". |
| The conversation got long and slow | Start a new conversation and use the prompt below. |

Prompt for a new conversation on an existing engagement:

> Engagement `acme-2026-11`: continue where the previous session stopped. Read `PLAN.md` and `NOTES.md`, call
> `list_findings`, and tell me what's done and what's left before you continue.

Start a **new conversation** (rather than continuing) when:

- the conversation is long: every turn resends it, which is slower and costs more;
- you switched planner model, or ran `./rvkit openhands` / `./rvkit up` after a `git pull`: agent prompts and tool
  settings are applied to new conversations;
- the old one keeps showing model connection errors after you fixed the model.

---

## Retest after client fixes

1. If the engagement is closed, reopen it: `./rvkit resume acme-2026-11`.
2. If the fixes are in code, update the repository in `~/riskvoid/projects/`.
3. Use the [retest template](#templates). For each finding, the agent sets the status:
   - `fixed`: no longer reproduces. The report lists it as **Resolved**.
   - `accepted-risk`: the client accepts it. Listed as **Accepted risk**.
   - stays `confirmed`: still open.
4. Regenerate the report, then `./rvkit close acme-2026-11` again. It writes a new archive next to the first one.

If you want a separate report for the retest, create a new engagement instead (for example `acme-2026-11-retest`)
with the same scope.

## Regenerating the report

Ask the agent ("generate the report again"), or run it yourself:

```sh
./rvkit report acme-2026-11
```

It rebuilds from the findings database and the `report/*.md` files. See
[findings-and-reports.md](findings-and-reports.md).

## Starting over

To run the whole test again from scratch, create a new engagement with a new name (`acme-2026-11-run2`) and the
same targets. Don't reuse the old folder: its findings, evidence and audit history belong to the first run.

---

## Local-only mode

With `riskvoid-local`, everything runs on your worker model. To get good results from a smaller model:

- Give one playbook and a narrow goal per conversation: "secrets review of `/src/acme-webshop`", then a new
  conversation for the code review.
- Ask it to write tool output to files and read them with `head`, `jq` or `grep` (its prompt says this too).
- Use a worker profile with a longer context if you can (A100 on Colab; see [models.md](models.md)).
- Check its candidates yourself before it confirms them.

## Costs

The planner is billed by OpenRouter; the daily cap is `./rvkit budget` (default $20). To see what a typical run
costs with your models, run a benchmark: `./rvkit bench smoke` costs a few cents and reports the cost
([lab-and-benchmarks.md](lab-and-benchmarks.md)). Long conversations and large tool outputs read by the planner
cost the most: let the worker do the tool work.

## Good practice

- **Least intrusive first.** Code and passive analysis, then active scans, then (with approval) intrusive steps.
- **Keep scope tight.** Put exactly the authorised targets in `SCOPE.md`; add more with `./rvkit scope` when the
  client agrees.
- **Watch approvals.** Read each intrusive command before approving it. Keep `./rvkit watch` running.
- **Verify before confirming.** Scanner output is a lead. Ask for the evidence behind any finding you doubt.
- **One engagement per conversation**, named in the first message.
- **Close when done**, so the evidence is sealed and the engagement can't run anything else.

---

Next: [findings-and-reports.md](findings-and-reports.md) · See also: [engagements.md](engagements.md),
[tools-reference.md](tools-reference.md), [troubleshooting.md](troubleshooting.md)
