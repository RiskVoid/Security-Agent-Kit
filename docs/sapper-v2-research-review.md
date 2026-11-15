# Sapper v2: research efficiency ideas for RiskVoid

Review date: 2026-11-15. Sapper snapshot: [`7b75e6f`](https://github.com/N1nEmAn/sapper-v2/tree/7b75e6f1f5d5b4ae0c55878b0dd0994d9b08f1fb). RiskVoid baseline: `c418469`, plus the working tree inspected during this review. This is a source review and design proposal, not an implementation or a measured performance comparison. No target testing or model benchmarks were run.

The highest-value adoption is a research loop that retrieves prior knowledge, selects a justified next experiment, preserves the result, and revisits blocked work when relevant evidence changes. Build it around RiskVoid's existing workspace, durable workers, policy gateway and verification. Importing Sapper's runtime would introduce a second orchestration system without addressing the underlying integration gaps.

## What the source actually implements

Sapper has two relevant execution paths: a fact/intent CLI with an autonomous loop, and a competition deployment orchestrated through terminal panes. Its graph stores observations and proposed actions with links between their prerequisites and results. Nodes have a title, description and optional detailed document. Recall searches the lightweight fields; work can be claimed under a filesystem lock. See [`lib/sapper.py`](https://github.com/N1nEmAn/sapper-v2/blob/7b75e6f1f5d5b4ae0c55878b0dd0994d9b08f1fb/lib/sapper.py#L249).

The competition doctrine separates coordination from execution. It specifies bounded reconnaissance, a progression through advice and additional expertise, parking unproductive work, and transferring relevant lessons. These are largely instructions for the commander, rather than an independently enforced scheduling policy. See the [commander doctrine](https://github.com/N1nEmAn/sapper-v2/blob/7b75e6f1f5d5b4ae0c55878b0dd0994d9b08f1fb/docker/commander/SKILL.md#L148).

The [watchdog](https://github.com/N1nEmAn/sapper-v2/blob/7b75e6f1f5d5b4ae0c55878b0dd0994d9b08f1fb/docker/commander/watchdog.sh) handles process failures, provider errors and the deadline, leaving strategy to the commander. The [hook bridge](https://github.com/N1nEmAn/sapper-v2/blob/7b75e6f1f5d5b4ae0c55878b0dd0994d9b08f1fb/lib/sapper-hook.py) injects bounded state and history into participating sessions. The [knowledge base](https://github.com/N1nEmAn/sapper-v2/blob/7b75e6f1f5d5b4ae0c55878b0dd0994d9b08f1fb/lib/kb.py) provides offline entries and lexical retrieval.

The [README](https://github.com/N1nEmAn/sapper-v2/blob/7b75e6f1f5d5b4ae0c55878b0dd0994d9b08f1fb/README.md) reports competition wins and lower token use than another team. Those are author-reported outcomes, not a controlled comparison isolating the harness. The [retrospective](https://github.com/N1nEmAn/sapper-v2/blob/7b75e6f1f5d5b4ae0c55878b0dd0994d9b08f1fb/BATTLE-REPORT.md) itself distinguishes event observations from inferred mechanisms. Neither establishes expected savings on our engagements.

## Existing RiskVoid capabilities to extend

| Capability | Current implementation | Actual remaining opportunity |
|---|---|---|
| Focused delegation | [`delegate_task`](../harness/worker.py#L1089): contracts, inputs, dependencies, coverage cell | Assemble context from authoritative records automatically; connect work to evidence prerequisites |
| Durable execution | [`worker.py`](../harness/worker.py#L766): saved conversations, leases, approvals, interruption recovery | Preserve research conclusions independently of one task's transcript |
| Context reduction | [`digest.py`](../harness/digest.py), [`compact`](../harness/worker.py#L336) | Retrieve relevant prior results across tasks, with bounded detail |
| Stuck-task handling | [`watch`, `advise`, `on_stall`](../harness/worker.py#L472) | Measure useful research progress and reschedule across investigations |
| Investigation records | [`workspace.py`](../harness/workspace.py): observations, hypotheses, coverage, staleness, handover | Link supporting and contradicting evidence, experiment outcomes and reopened questions |
| Independent review | [`validator.py`](../harness/validator.py), [`verification.py`](../harness/verification.py) | Review assumptions and missing research directions as well as findings |
| Parallel execution | Configurable `WORKER_PARALLEL_TASKS`, default 1 | Allocate model, tool and target capacity separately |
| Improvement process | [`improvement-loop.md`](improvement-loop.md), [`run_benchmark.py`](../evals/run_benchmark.py) | Add efficiency and transfer-specific experiments to the existing process |

These are implemented source capabilities. Their existence is not a claim that every deployment or model performs them successfully.

## Recommended changes, in order

### 1. Automatically build a small research packet before each task

This should be the first experiment: it works with one worker and needs no new service. Today a caller can supply `inputs`, but the worker starts primarily from the goal, policy, and contract. Relevant knowledge can remain in other task results, workspace records, or a handover note.

Add a packet builder in the workspace layer and call it when dispatching or resuming a worker. The proposed packet contains:

- Objective, coverage cell, current build and policy revision.
- Relevant map entries, observations and findings, retaining their verification states.
- Prior attempts, including negative and inconclusive results, each with evidence references.
- The unresolved question, completion condition and explicit blockers.
- A few matching method summaries, with detail available through a separate read operation.

Use a configurable token allowance and record the selected IDs and revisions. Start with stable identifiers, tags and lexical matching; evaluate retrieval before introducing embeddings or another database. Rebuild after material changes rather than attaching the entire engagement to every model call. This adapts the compact-history pattern from the [hook bridge](https://github.com/N1nEmAn/sapper-v2/blob/7b75e6f1f5d5b4ae0c55878b0dd0994d9b08f1fb/lib/sapper-hook.py#L90).

Expected benefit, to measure: fewer repeated reads, repeated scans and manual rebriefs. A useful packet must preserve uncertainty; an agent-authored summary does not become an instruction or a verified fact by being retrieved.

### 2. Link research questions, experiments and evidence

Extend the SQLite workspace instead of replacing it with a separate graph store. Existing plan items already have hypotheses and prerequisites. Introduce explicit relationships and experiment outcomes around those records.

Suggested logical model:

```text
question -> experiment -> observations -> conclusion
                 ^                           |
                 |------ next question ------|

conclusion --supports/contradicts--> question or finding
experiment --requires--> identity, build, observation or capability
```

An experiment should retain its plan item, task ID, method, prerequisite versions, execution outcome and evidence hashes. A conclusion should distinguish supported, refuted and unresolved claims. Record a negative result with its exact conditions: an input failed under one identity and build, rather than a general assertion that the application is safe.

The next runnable work should depend on usable evidence and access, not merely a predecessor task reaching `done`. Claims need not expire together: a build change may invalidate source conclusions, while a policy change may invalidate authorization to execute. Reuse existing staleness and revision machinery.

Sapper's linked fact/action representation is useful inspiration, but its node schema should not be copied as a complete provenance or truth-maintenance system. See [fact creation and intent creation](https://github.com/N1nEmAn/sapper-v2/blob/7b75e6f1f5d5b4ae0c55878b0dd0994d9b08f1fb/lib/sapper.py#L249).

### 3. Schedule by risk, information gained and remaining cost

Introduce a persisted queue over plan items with reasons for dispatch, pause, escalation and reopening. First run it in advisory mode: compare its suggestions to the current planner before allowing it to dispatch.

Rank work using client priorities, potential impact, applicability, prerequisite readiness, expected uncertainty reduction and estimated time/model cost. Preserve mandatory coverage and reserve capacity for difficult high-impact questions. Finishing many easy checks is insufficient if authorization or tenant isolation remains untested.

A proposed escalation sequence is:

1. Run a small discriminating experiment with a clear completion condition.
2. On repeated uncertainty, consult relevant prior methods and the existing advisor.
3. If justified, fund a different method or a stronger permitted model, with a new budget.
4. Park the question with a precise blocker or missing observation.
5. Reopen only when a relevant prerequisite changes or a reviewer explicitly reprioritizes it.

Time limits should come from our traces. Sapper's competition timings are a starting hypothesis, not settings to import. Its [doctrine](https://github.com/N1nEmAn/sapper-v2/blob/7b75e6f1f5d5b4ae0c55878b0dd0994d9b08f1fb/docker/commander/SKILL.md#L178) provides the underlying escalation pattern.

Improve progress detection before trusting automated escalation. Our `watch()` currently treats a previously unseen output hash as progress. A changed banner or timestamp can therefore appear productive. Prefer new attributable observations, resolved prerequisites, coverage transitions, and reproduced or refuted hypotheses. Keep output novelty as a diagnostic signal.

### 4. Reuse methods across related surfaces

Create small method records with applicability conditions, assumptions, required access, safe procedure, expected evidence and negative controls. Match them to related route groups or shared authorization code within the engagement. Transfer a method; revalidate its assumptions and result at the new surface.

For example, after verifying a tenant-isolation defect in one invoice operation, propose tests of related export and download operations using the existing identities and fixtures. Link results to the correct root cause and affected instances rather than inflating the finding count.

Sapper explicitly calls for sharing lessons between related challenges; its [retrospective](https://github.com/N1nEmAn/sapper-v2/blob/7b75e6f1f5d5b4ae0c55878b0dd0994d9b08f1fb/BATTLE-REPORT.md) attributes bursts of progress to that transfer. Our first version should remain engagement-local. Cross-client reuse would require separately reviewed, sanitized method promotion, with no credentials, target addresses, customer artifacts or benchmark answers.

The [offline KB interface](https://github.com/N1nEmAn/sapper-v2/blob/7b75e6f1f5d5b4ae0c55878b0dd0994d9b08f1fb/lib/kb.py) is a useful small design: searchable summaries and opt-in details. Prefer indexing our versioned playbooks before importing its technique corpus.

### 5. Use different roles only when they resolve different questions

Keep the existing planner, worker and evidence reviewer. Add bounded reconnaissance and assumption review as task profiles, rather than long-lived agents or another management hierarchy.

A second research task should name an independent method and decision it can resolve: source tracing versus runtime behavior, or valid-session controls versus a suspected access defect. Claim a work key based on engagement, build, coverage cell, method and relevant identity/fixture to avoid accidental duplicates. Explicitly requested independent reproduction remains possible.

Add a read-only review at phase transitions or persistent stalls: what important assumption remains unsupported, and what evidence would settle it? Sapper supplies a distinct [blindspot review template](https://github.com/N1nEmAn/sapper-v2/blob/7b75e6f1f5d5b4ae0c55878b0dd0994d9b08f1fb/templates/blindspot.md). This complements our existing finding validator, which examines supplied evidence rather than discovering missing investigations. Suggestions enter planning; they do not change scope or execute actions.

Expose a deterministic board through the existing handover and console: active question, last meaningful result, blocker, budget used, next decision and reason. Trigger replanning on material record changes, task completion, unblocked prerequisites or budget thresholds. Avoid paying for a model to poll unchanged state.

### 6. Separate model capacity from running tools

There is a concrete throughput opportunity in our implementation: `run_task()` holds `MODEL_LOCK` across the entire `_loop`, including synchronous tool execution. With the default capacity of one, a long external scan prevents another task from using the otherwise available model endpoint. See [`worker.py`](../harness/worker.py#L766).

Prototype separate admission controls for model inference, running tools, target rate and engagement concurrency. Release model capacity while a task waits for a tool; preserve task serialization and all durable checkpoints. Avoid shared-state tests running concurrently against the same fixtures.

For multi-route endpoints, later add bounded task profiles such as scout, standard and deep, using approved LiteLLM aliases. The current worker uses a global model selection, with a private route override; the advisor already supplies some stronger-model assistance. Per-task escalation is an extension, not the introduction of tiering from scratch. Every route and fallback must continue through the existing client-data check.

Raising `WORKER_PARALLEL_TASKS` alone is not the design: a single GPU can lose throughput or context capacity under contention. Measure queue delay, inference utilization and verified results per wall-clock minute on the actual endpoint.

## What to borrow, and what to leave behind

| Decision | Candidate |
|---|---|
| Adapt immediately | Bounded context packets, searchable method summaries, explicit escalation and parking records, distinct assumption review |
| Adapt after initial evidence | Evidence-dependent dispatch, experiment claims, meaningful progress events, separate inference/tool capacity |
| Selectively copy after review | Small recall or rendering helpers, fixtures and contract-test patterns, with attribution |
| Keep our implementation | MCP tools, SQLite records, hashed evidence, policy gateway, bound approvals, uncertain-write recovery, independent validator |
| Do not import | Terminal-pane orchestration, automatic permission-dialog acceptance, competition platform API/flag lifecycle, fixed competition deadlines and model names |

Sapper's [worker implementation](https://github.com/N1nEmAn/sapper-v2/blob/7b75e6f1f5d5b4ae0c55878b0dd0994d9b08f1fb/docker/commander/worker.sh) documents terminal-input and session-environment repairs. Those solve problems our programmatic MCP transport largely avoids. Its [watchdog](https://github.com/N1nEmAn/sapper-v2/blob/7b75e6f1f5d5b4ae0c55878b0dd0994d9b08f1fb/docker/commander/watchdog.sh) also auto-accepts dialogs and can rotate provider families. Those behaviors must not replace our explicit approvals or model-destination policy.

The upstream [MIT license](https://github.com/N1nEmAn/sapper-v2/blob/7b75e6f1f5d5b4ae0c55878b0dd0994d9b08f1fb/LICENSE) permits copying subject to its notice requirements. Any actual copied code should retain the notices and be recorded in [THIRD_PARTY.md](../THIRD_PARTY.md), following [CONTRIBUTING.md](../CONTRIBUTING.md). Technique entries reference other sources, so review their provenance separately. No upstream code has been copied in this review. The README also points to [nvwabase](https://github.com/N1nEmAn/nvwabase) as the general-purpose foundation; this review inspected that project's landing page only and does not recommend it as an audited dependency.

## Validation and implementation sequence

Use the existing tuning/held-out improvement process. First establish repeated baseline runs at fixed model versions, model budget and target-request budget. Then evaluate one change at a time:

| Increment | Experiment | Main measurement |
|---|---|---|
| A | Automatically assemble task packets from existing records | Repeated tool work, context tokens, verified outcomes at equal budget |
| B | Persist experiment outcomes and evidence prerequisites | Repeated hypotheses, stale-result reuse, justified reopened investigations |
| C | Queue recommendations and distinct assumption review | Strict coverage and important findings per budget, including difficult cases |
| D | Engagement-local method reuse | Time to independently reproduce on a related surface, false transfer to protected controls |
| E | Separate capacity and optional model profiles | Queue delay, wall time, total model cost and target traffic |

Existing metrics already include strict recall, precision, cost, time and operator load. Add tokens across every role, duplicate experiment rate, time to first strictly verified finding, productive coverage per budget, retrieval relevance and analyst rebrief effort. Count coordinator, advisor and reviewer calls in cost comparisons; parallel workers can hide expensive coordination.

Use new tuning fixtures for repeated route families, a missing identity becoming available, a changed build invalidating prior work, a long-running tool beside a short task, an exhausted provider, and an attractive hypothesis refuted by a clean control. Keep held-out cases independent. Reset engagement memory between ordinary evaluation runs; test warm-memory transfer as a separate condition with a frozen, documented method corpus. Existing web lookup restrictions do not by themselves prevent memory from leaking benchmark answers.

Retain the current safety and held-out acceptance rules. Do not trade away required coverage or precision to improve findings-per-minute. No numeric efficiency gain is established by this review.

The recommended first implementation is increment A, followed by a compact research board. This creates a measurable foundation for the queue and method reuse while keeping the change small enough to attribute any improvement.
