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

## Reading the numbers

- A cause that appears in only one or two runs can't shrink measurably. Pick causes that recur across runs.
- The held-out check doesn't prove a change helped elsewhere. It shows that the change didn't hurt beyond what the
  runs can tell apart. With three runs per benchmark, only a large drop is visible.
- A change that removes a symptom by hiding it (accepting what used to be refused, for example) can shrink its cause
  while leaving the failure in place. Check the candidate runs' conversations for the targeted records, not just
  the count.
- Model versions, the kit's code and the prompt are recorded in each result. Don't judge across a model change.
