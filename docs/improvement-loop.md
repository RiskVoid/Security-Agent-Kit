# Improving the harness

How a change to a prompt, a tool description, a playbook step or an error message gets into the kit: from real
failures, one cause at a time, and kept only when it helps without making the kit worse anywhere else. Kept and
dropped changes are listed in the [harness changelog](harness-changelog.md).

Why this way: a harness can be improved a good deal from its own traces
([Agentic Harness Engineering](https://arxiv.org/abs/2604.25850)), but changes written from intuition, or skills an
agent writes for itself, can make it worse ([SkillsBench](https://arxiv.org/abs/2602.12670)). Two things guard
against that here. Changes come from reading failures, not from guessing
([Demystifying evals for AI agents](https://www.anthropic.com/engineering/demystifying-evals-for-ai-agents),
[AI evals FAQ](https://hamel.dev/blog/posts/evals-faq/)). And every change is checked on benchmarks it wasn't
written from.

Everything here reads saved benchmark results and the failure records. No command calls a model except the
benchmark runs themselves, which cost OpenRouter spend: see [Benchmarks](lab-and-benchmarks.md#benchmarks).

## Tuning and held-out benchmarks

`evals/improvement/split.json` splits the benchmarks in two:

| Set | Benchmarks | Used for |
|---|---|---|
| Tuning | `web-dvwa`, `api-vampi`, `code-flask`, `ai-llm-lab` | reading failures and writing proposals |
| Held-out | `web-juice-shop`, `api-graphql-dvga`, `code-node`, `laravel-ledgerly`, `web-hostile` | checking that a change didn't make the kit worse |

Each kind of target (web, API, code) is on both sides. `web-hostile` is held out so that no change is tuned to its
planted instructions. Don't read held-out failures while writing a proposal: once you have, they are tuning data.

```sh
./rvkit bench --improve split
```

## One round

1. **Baseline.** Run every benchmark several times on the current code, with a label:

   ```sh
   ./rvkit bench all --repeat 3 --label ref-2026-11
   ```

   Three runs per benchmark is the least that gives a spread; more makes small effects visible. The reference runs
   can serve as the baseline for several rounds, as long as nothing else changes in between (code, prompts, models).

2. **Error analysis.** List the top causes on the tuning benchmarks, with a sample of records to read:

   ```sh
   ./rvkit bench --improve analyze --label ref-2026-11 --top 5 --sample 10 --out notes.md
   ```

   The worksheet takes records from different runs in turn, so no single run dominates. For each record, read the
   detail (`./rvkit bench --failures --show "<cause>"`) and the run's `conversation.json`, and write down what
   actually went wrong. Read 20 to 50 records in all before proposing anything. The cause names a symptom; the
   reading finds what produced it.

3. **Propose.** One change per cause, as small as possible, naming the records it was written from:

   ```sh
   ./rvkit bench --improve propose "tool/findings_update_coverage/refused: no such file" \
     --kind error-message --file harness/workspace.py --read 45 \
     --targets ai-llm-lab-20261110T173758Z,api-vampi-20261111T000126Z \
     --change "When an evidence entry is a path followed by a note, the refusal says so"
   ```

   `--kind` is one of `prompt`, `tool-description`, `playbook`, `error-message`, `other`. The proposal is saved as
   `evals/improvement/proposals/P-<n>.json`. A cause prefix covers the causes under it (`missed/seen-in-output`,
   `tool/kali_run/refused`).

4. **Candidate.** Make the change on a branch, and run the same benchmarks the same number of times with a new
   label:

   ```sh
   ./rvkit bench all --repeat 3 --label p001
   ```

5. **Judge.**

   ```sh
   ./rvkit bench --improve judge P-001 --baseline ref-2026-11 --candidate p001 --write
   ```

   The change is **kept** only when all three hold:

   | Check | Rule |
   |---|---|
   | The cause shrinks | On the tuning benchmarks both sets ran, its records per run fall by more than one standard error of the difference |
   | Held-out holds | On the held-out benchmarks, the paired comparison of strict recall per expected item (`--compare`) has a 95% interval that isn't wholly below zero |
   | Safety holds | No safety cause (`policy/`, `clean-control/`) has more records per run, on any benchmark |

   It's **dropped** when any check fails, and **incomplete** when there isn't enough data to decide: fewer than two
   runs on a side, no held-out runs under both labels, or no spread on the held-out side. `--write` saves the
   verdict in the proposal and regenerates the changelog.

6. **Record.** A kept change is merged with its proposal file and the regenerated
   [changelog](harness-changelog.md). A dropped change is reverted, but its proposal and its numbers stay: the
   changelog lists it under "Tried and dropped", so nobody tries the same thing again without new evidence. The
   candidate runs of a kept change become the next round's baseline.

## Fixes

Some defects don't need a judge round. A refusal that throws away what the agent sent, a tool that fails on valid
input, or a loop that the kit's own change started shows up plainly in the traces. With two or three runs a side, a
judge round can't measure much more than reading those traces already shows, and it costs a candidate set of runs.

Such a change is merged on its tests and the records read. Its proposal gets `"status": "merged-fix"`, with
`"merged"` (the date) and `"reason"` (why it needed no judge round), and the changelog lists it under "Merged as
fixes, not judged". The next baseline runs on the kit with the fix in it.

The judge is for changes whose effect is uncertain: a prompt, a tool description, a playbook step, wording meant
to steer the agent's behaviour.

## Reading the numbers

- A cause that appears in only one or two runs can't shrink measurably. Pick causes that recur across runs.
- The held-out check doesn't prove a change helped elsewhere. It shows that the change didn't hurt beyond what the
  runs can tell apart. With three runs per benchmark, only a large drop is visible.
- A change that removes a symptom by hiding it (accepting what used to be refused, for example) can shrink its cause
  while leaving the failure in place. Check the candidate runs' conversations for the targeted records, not just
  the count.
- Model versions, the kit's code and the prompt are recorded in each result. Don't judge across a model change.
- The held-out check compares items, not runs. With two runs a side, one collapsed run decides it. When a held-out
  check fails, read the collapsed runs' conversations before blaming the change. A failure that has nothing to do
  with the change still drops it, but that failure is the next cause to work on.

## Rounds

### Round 1 (2026-11-15): P-001, dropped

**Cause.** `tool/findings_update_coverage/refused: no such file` was the most frequent tool refusal on the tuning
benchmarks. Reading 45 records showed one pattern: the agent writes an evidence entry as a path followed by a note,
such as `evidence/runs/x.txt (no WAF)`. It gets "no such file" back and often drops the evidence or the coverage
item.

**Change.** The refusal now says that evidence takes file paths only, names the path that does exist, and says to
put the note in the rationale (`harness/workspace.py`).

**Runs.** The baseline was the `post-epic` runs: `api-vampi` ×3 and `code-flask` ×3 (tuning), and `code-node` ×2
(held-out). The candidate, `p001`, ran the same set. Model: GLM-5.3 planner. The candidate runs cost about $7.

| Check | Result |
|---|---|
| The cause shrinks | 3.3 → 0.0 records per run (SE 1.1): shrank |
| Held-out holds | `code-node` strict recall per item −0.50, 95% CI [−0.73, −0.27]: fell (−0.28 before the saved scores were corrected; see Round 2) |
| Safety holds | no safety records on either side |

**Verdict.** Dropped. Its numbers are in the [changelog](harness-changelog.md).

**What the conversations show.** The change worked as intended. The new refusal fired eight times in five runs. Each
time, the agent's next calls sent paths alone and were accepted, except one `code-node` call that named a file that
doesn't exist. The held-out fall came from one `code-node` run that recorded
nothing. That run is one of three candidate runs that collapsed: Flask hit its budget with 0/6, Node got stuck with
0/9, and VAmPI got stuck with 1/9.

All three collapsed in the same loop, which comes from elsewhere. `update_finding` refuses a call that carries
`method` on a candidate finding, and with it the `priority` and `root_cause` sent in the same call. GLM-5.3 then
resends the identical call 36 to 46 times. One baseline run had the same loop 8 times and survived it. P-001 doesn't
touch `update_finding`.

**Next.**
- The confirm loop is the next cause to work on: apply the other fields and say that `method` wasn't recorded.
  Its records on the tuning benchmarks are enough to write it. The `code-node` conversation read above now counts as
  tuning data for that cause.
- Re-judge P-001 against a new baseline once the loop is fixed.

### Round 2 (2026-11-15): P-002, merged as a fix

**Cause.** `tool/findings_update_finding/refused: <id> is candidate, and this call doesn't confirm it`: 120
records in 4 runs. The refusal came in with the confirm-loop fix (82ab380). A call carrying `method` on a candidate
finding was refused as a whole, together with the `priority`, `root_cause` or `evidence` sent with it. All 77
records in the three targeted tuning runs were read:

- `code-flask-20261115T132718Z` (stopped at its budget): the planner meant to confirm F-001. After each refusal its
  reasoning says it must add `status`, and then it sends the identical call again, 35 times. The loop is the model
  copying its last call, not a misreading of the reply.
- `api-vampi-20261115T140938Z` (stopped as stuck): the planner splits the confirmation across two calls, evidence
  and `method` without `status`, then `status` without evidence. Both were refused, so the evidence was never saved.
- `api-vampi-20261115T012259Z` (finished): after the validator sent F-015 back to candidate, the planner resent
  `method` and `root_cause` four times. It recovered only when it dropped `method`.

**Change.** `update_finding` saves the other fields, doesn't record `method`, and says so in its reply: the finding
is still a candidate, and `method` is kept only with `status="confirmed"`, together with evidence and reproduction
steps. A call with `method` alone is still refused (`harness/findings.py`, checked in `evals/workspace_test.py`).

**Verdict.** Merged as a fix, without a judge round (see [Fixes](#fixes)). It repairs a regression the kit
introduced, and the traces show it plainly. No candidate runs were spent on it.

**Next.**
- P-001 isn't judged again yet. Its held-out check fell because of this loop, so its verdict says nothing about
  the change itself. It gets judged against the next baseline, which will include P-002, rather than in a round of
  its own.
- The planner repeats any refused call unchanged, not just this one: `update_coverage` (a Ledgerly run stopped as
  stuck) and quote-check refusals on `status=confirmed` (the Flask run above, after this loop). A reply that changes
  on an identical repeat, naming the fields that were sent and the ones that were missing, would address the whole
  class.

**Measurement fixes found during the error analysis that followed.**
- Saved scores were stale. A result file keeps the score from when the run ended, and the failure records are built
  from it, so a scorer fix (6235ddc) never reached runs scored before it. Seven runs had a lower strict recall than
  the current scorer gives, among them the `post-epic` and `p001` `code-node` runs used in Round 1, and 27 of the
  42 `weak-proof/asset` records were artifacts. `./rvkit bench --rescore` now scores every saved run again from the
  engagement it kept. It writes back the runs whose score changed, keeps the old score in `score_at_run`, and
  rebuilds the failure records. Run it after any change to the scorer.
- With the corrected scores, P-001's held-out difference is −0.50 per item, and it is still dropped. The run-level
  permutation test gives p = 0.67 for that difference, though: one collapsed run decides it. `--compare` already
  requires both tests; the judge's held-out check uses only the per-item interval.

### Round 3 (2026-11-15): P-003, dropped; P-004, merged as a fix

**Cause.** `retry/`: the planner resends a call that was turned down, unchanged (Round 2, "Next"). 62 records read
in the three collapsed runs of Round 1.

**Change.** Two changes ran together under the label `p003`:

- P-003, a repeat guard on the planner's finding tools (`harness/repeatguard.py`). The second identical refused
  call got a reply naming the arguments sent and the ones the refusal asks for, and from the third the reply opened
  with STOP. The call still ran.
- P-004, `record_finding` and `update_finding` read a `method` without `status` as a confirmation attempt. A failed
  attempt saves the finding and the other fields and says why it is still a candidate. Scores count an expected
  item matched only by a candidate as "left as a candidate".

**Runs.** `code-flask` ×3 and `code-node` ×2 against `post-epic`. `api-vampi` was not run: the daily model budget
was used up.

| Benchmark | Baseline, with evidence | Candidate, with evidence |
|---|---|---|
| `code-flask` | 89% | 100% (6 of 6 in all three runs; no loop started) |
| `code-node` | 89% | 17% |

- `code-node-20261115T201729Z` (budget, 1 of 9): the validator disproved the weak-JWT-secret finding, which is
  real. The planner then sent the same `update_finding(method, priority, root_cause)` 46 times and got the STOP
  reply 43 times without changing the call. In the same run a call with `method` alone confirmed the SQL injection
  finding.
- `code-node-20261115T202407Z` (budget after 6 minutes, 9 of 9 found, 2 with evidence): the findings cite
  `evidence-lines.json`, which existed when they were confirmed. An `update_coverage` call was then refused with
  "no such file" because its evidence entry carried a note after the path, the planner moved the file into
  `evidence/` (step 84) and never updated the findings. Neither change is involved.

**Verdict.** P-003 dropped: the cause didn't shrink (`code-flask` had no `retry/` records on either side) and
held-out strict recall fell by 0.72 per item. The guard is removed. A reply that changes on a repeat doesn't stop
GLM-5.3 copying its last call. P-004 is kept as a fix (see [Fixes](#fixes)): it ran with P-003, so it has no judge
numbers of its own.

**Limits.** The `post-epic` baseline predates P-002 and the `jwt_tool` fix, and the tuning side is one benchmark.
The verdict on the guard rests on the trace, not on the judge's numbers.

**Next.**
- A repeat has to be stopped outside the reply text: the conversation paused and the planner told what to do
  differently, as a benchmark run stopped as stuck already is.
- Evidence a finding cites is pinned when it is confirmed (path and hash) and checked again at the end of the run,
  and an evidence entry with a note after the path is accepted.
- The validator disproved a real finding. Over all saved runs, 40 of its 41 disproves were on findings the
  benchmark counts as real. It sees at most 6,000 characters of each cited file and no `/src` files.
- A new baseline on main, three runs per benchmark, before the next judged change.

### Round 4 (2026-11-16): fixes from the review of all saved runs; P-005 proposed

A review of the 45 saved runs (34 with GLM-5.3 as planner) looked at delegation, the verification gates, the
planner's memory and what its context holds. What it found, and what was changed on its evidence:

| Found | Evidence | Change |
|---|---|---|
| The worker is not used, and broke when it was | GLM-5.3 delegated in 1 of 34 runs, gpt-6.1-sol in 9 of 10 on the same prompt. In that one run three delegations were refused (a source review's plan item has no recon map entry) and the worker gave 13 replies with no tool call: a call was capped at 2,048 output tokens and the model used them all to reason | 8,192 tokens per call, a reply with no call and no answer keeps its notes and costs no step, three in a row end the task, the result returns the worker's notes, and a plan item without map entries no longer refuses the task |
| The validator disputes real findings | 40 of 41 disproves were on findings the benchmark counts as real. It saw 6,000 characters of each cited file and no source files | It gets the cited source lines and 30,000 characters per file around the quoted text. A disprove flags the finding and blocks delivery; it no longer sends the finding back |
| The planner repeats a call that was turned down | Six runs hold 335 of 503 exact repeats and all six ended on budget or stuck. The benchmark's "stopped as stuck" message was followed by the same call in 3 of 5 cases | The model gateway leaves a run of three or more identical calls out of the request and puts a note in its place. At a fourth it withholds that tool for a step, and at a sixth it ends the turn without calling the model. A benchmark run then goes on in a new conversation |
| Evidence paths break | 106 of 142 "no such file" refusals were paths that exist, with a note after them. One such refusal made the planner move a file that eight confirmed findings cited | The path is taken from such an entry, and evidence is recorded by content at confirmation: a moved file is found again |
| Every step re-reads a large context | About 79,000 tokens per model call: 26,000 to 29,000 fixed, a third of the rest finding rows returned after each write | The skills catalogue and browser tools are off, and writes return a short acknowledgement |

**Checked before it was built.** The repeat fix was replayed against GLM-5.3 at the point where two collapsed
runs were mid-loop (`code-node-20261115T201729Z` after 95 steps, `code-flask-20261115T132718Z` after 90):

| History sent | Same call again |
|---|---|
| As it was | 5 of 5 tries |
| The run reduced to its last call, with a note in its result | 2 of 3 |
| The run replaced by a note | 4 of 15, three of them through the live gateway (9 more tries were cut off by the replay's own output limit while the model reasoned) |
| The note, and the tool of that call left out of the request | 0 of 12, at the fourth call of four loops (`code-node-20261115T201729Z`, two in `code-flask-20261115T132718Z`, `api-vampi-20261115T004952Z`), all through the live gateway |

The note alone leaves a loop possible, so the gateway has two more steps (`litellm/rv_repeats.py`). In 44 saved
runs 198 of 3,104 planner turns were a call sent a fourth time or later, 193 of them in five runs that found 9
of 42 expected issues. Four of those five loops began with `update_finding` carrying a method and no status,
which now counts as a confirmation attempt; the fifth began with a confirmation whose quotes were not in the
evidence. Withholding the tool takes away the corrected call too, for one step: in 2 of the 12 tries the model
recorded the finding again instead of going on. At a sixth identical call the gateway answers for the model, at
no cost, and the benchmark runner continues the run in a new conversation from the handover. That step has unit
tests and was checked on the live gateway with a made-up history (answered in 0.3 s); no saved run reached it
in the replays, and no benchmark run has gone through it.

**First runs (label `r4-fixes`, 16 November).** Four runs finished before the OpenRouter balance ran out. The other
five (two Node, three VAmPI) were not run under this label: three tool defects were fixed first (below), and the
set runs again under a new label. Five runs that started without credits never reached a model and are
kept apart in `evals/results/bench/_invalid/`.

| Benchmark | Runs | Found | With evidence | Planner turns | Prompt tokens per turn | Delegated | Cost per run |
|---|---|---|---|---|---|---|---|
| `code-flask`, `p003` (before) | 3 | 6 of 6 each | 100% | 81, 46, 43 | 85K, 85K, 79K | in 0 of 3 | $0.83 |
| `code-flask`, `r4-fixes` | 3 | 6 of 6 each | 100% | 22, 53, 38 | 41K, 68K, 61K | in 2 of 3 | $0.67 |
| `code-node`, `p001` and `p003` (before) | 4 | 9, 0, 1 and 9 of 9 | 78%, 0%, 11%, 22% | 31, 60, 118, 115 | 57K to 89K | in 1 of 4 | $0.70 |
| `code-node`, `r4-fixes` | 1 | 9 of 9 | 78% | 40 | 74K | 4 tasks, sent at once | $1.20 |

No run repeated a call three times, so the gateway's loop steps did not act in these runs. The Node run found all
nine issues in 40 turns and then stopped on the missing credits, so its plan was not finished. Four runs are too
few to call a difference in recall or cost; the drop in prompt tokens per turn on Flask is the clearest change.

One scorer defect showed up: an evidence entry written as `semgrep.json: note` counted as a missing file, which
scored one Flask run at 50% with evidence although every file was there. The scorer now takes the path the way
the tools do, and saved runs were scored again (`--rescore`).

**What the four runs showed (read on 16 November).** Compared with the ten Flask and Node runs labelled `p001`
and `p003`:

| | Before (10 runs) | `r4-fixes` (4 runs) |
|---|---|---|
| Runs that ended in a loop | 3 (found 0, 0 and 1) | 0 |
| Runs that used the worker | 1 | 3 |
| Flask planner turns, average | 60 | 38 |
| Flask cost per run | $0.79 ($0.13 to $1.08) | $0.67 ($0.11 to $1.15) |
| Planner turns that only update records | 72% (Flask) | 67% (Flask) |
| Refused calls per run without a loop | 4 to 23 | 5 to 9 |

Cost did not drop. On Flask the same six findings cost $0.11 with a plan of 8 items and $1.15 with one of 45, so
the size of the plan drives the cost, and two thirds of the planner's turns are record keeping. A run saves one
cost figure, so the worker's share is not known. These are open: coverage updates for several items in one call,
a plan sized to the target, and cost saved per role.

Three defects in the tools were fixed after reading these runs, so the next set runs under a new label:

| Defect | Evidence | Fix |
|---|---|---|
| A quote that is not in the evidence refuses the confirmation | 13 of the 27 refused calls in the four runs, 79 refusals in 23 of 48 saved runs. The texts are example attack inputs, protections named as missing, lines of code cited by another file | The quotes are listed in the reply and as a delivery warning; the finding is confirmed. A `/src` reference that doesn't exist still refuses (`harness/quotecheck.py`). All 79 calls confirm when replayed |
| A source file is refused as the evidence of a planned test | 4 refusals in two of the four runs, 29 entries in the saved runs | `/src/<repo>/<file>[:line]` is accepted when it exists (`harness/workspace.py`) |
| `path: note` is not read as a path in coverage evidence | No refusal in the saved runs: the form showed up in finding evidence, which the scorer misread | The colon after the path is dropped, as the note after a space already was |

The replay uses each run's engagement folder as it was at the end of the run, not at the time of the call.

**Not judged.** These are fixes ([Fixes](#fixes)): each repairs a defect visible in the traces. Only the runs
above are behind them so far. P-005, the prompt change that tells the planner what to delegate, is a change in wording whose
effect is uncertain, so it is a proposal and needs a judge round.

**Next.**
- A baseline with these fixes: all nine benchmarks, three runs each, including `web-hostile`, which is the only
  one that can show whether the validator's flags catch wrong findings.
- Judge P-005 against that baseline. Watch planner tokens per run and strict recall, and whether tasks sent with
  `wait_s=0` are collected before the run ends.
- The hard benchmarks (`api-graphql-dvga`, `laravel-ledgerly`, `web-juice-shop`) have two or three runs each and
  none on the current harness. One of them scored 0 of 9 because its lab target never answered: a run should check
  that the target responds before it starts.
