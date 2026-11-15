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
