# Findings and reports

How the kit records findings, keeps evidence verifiable, and turns both into the client report: a self-contained web
page (`.html`), a `.docx`, a PDF and a findings register `.xlsx`. It also covers what makes a report DRAFT and how to brand it.

---

## Findings

Each engagement has its own findings database, `/work/<engagement>/.rv/findings.db` (SQLite), which kali commands can only read. Findings get ids in
order: `F-001`, `F-002`, …

### Fields

| Field | Content |
|---|---|
| `title` | short name of the issue |
| `severity` | `critical`, `high`, `medium`, `low` or `info` |
| `cvss_vector`, `cvss_score` | a CVSS 3.1 vector, whose base score is computed (a different score given with it is refused), or a CVSS 4.0 vector with the score from the FIRST calculator (optional) |
| `cwe` | for example `CWE-89` |
| `asset` | what is affected: host, URL, API operation, `file:line` |
| `description`, `impact`, `reproduction`, `remediation` | short markdown; it goes into the report as written |
| `evidence` | list of evidence paths, each optionally followed by a space and a note |
| `status` | see below |
| `source` | `planner`, or `worker:<task_id>` for candidates the worker recorded |
| `notes` | internal notes. Not printed in the report |
| `priority` | remediation order, `P1` to `P4`, set separately from the technical severity |
| `prerequisites` | what a reproduction needs: an account, a role, a tenant, data |
| `instances` | the affected locations: observations linked to the finding (file:line, route, package) |
| `root_cause` | the shared cause, when several instances have one |
| `verification`, `verified_by`, `verified_method`, `verified_at` | `unverified`, `verified` or `not-reproducible`; who verified it, how (`runtime-reproduction`, `replay`, `authorization-matrix`, `source-review`, `tool-output`, `retest`, `client-confirmation`, or `not stated`) and when |
| `revision`, `created`, `updated` | revision number (each change adds one) and UTC timestamps |

### Statuses

| Status | Meaning | In the report |
|---|---|---|
| `candidate` | found but not verified (scanner output, worker lead) | no; untriaged candidates keep the report DRAFT |
| `confirmed` | verified by reproducing it, reading the code path or checking the version | yes, as **Open** |
| `false-positive` | checked and doesn't hold; the reason is kept with the decision | no; counted in the activity summary |
| `duplicate` | the same issue as another finding, named in `duplicate_of` (its evidence is merged into that one) | no; counted in the activity summary |
| `fixed` | fixed by the client and retested | yes, as **Resolved** |
| `accepted-risk` | the client accepts the risk | yes, as **Accepted risk** |

### Who records what

- **The worker** records `candidate` findings only (title, severity, asset, description, evidence, CWE), with the
  evidence from its task.
- **The planner** sees them with `list_findings` and `get_finding`, verifies each one and sets the status with
  `update_finding` (`confirmed` with the verification `method`, `false-positive` with the `reason`, or `duplicate`
  with `duplicate_of` set to the finding it keeps). It records issues it finds itself
  with `record_finding`, and fills in CVSS, impact, reproduction and remediation.
- **After client feedback**, the planner sets `fixed` or `accepted-risk`.

You can ask the agent to change any finding ("lower F-004 to medium: it needs an admin session", "mark F-007 as
accepted risk"), or change it in the console's **Findings** tab. There's no `./rvkit` command for findings.

### Decisions, reasons and history

Every change keeps the finding's earlier revision, and every decision is recorded with who made it and why:

- `false-positive` and `accepted-risk` need a reason, so does a severity change and a change to a priority that
  was already set. The change is refused without one.
- Confirming a finding records the verification method; without one it says `not stated`, and the handover lists
  it as a pending decision.
- **Not reproducible** (console, or the `finding.not_reproducible` operation) records that a retest couldn't
  reproduce a finding, with the reason; the status stays as it was until someone decides.
- `get_finding` with `history=true` (or **History** in the console) shows every revision and decision.

## Investigation workspace

What an engagement must answer, how far testing got and what still needs a decision, kept in the same
`findings.db` so it survives restarts, model switches and a change of researcher.

### Observations

An observation is what a tool reported, before anyone decides whether it's a finding. `import_observations` (or
**Import tool output** in the console's **Investigation** tab) reads a tool's output from the engagement folder
(`semgrep.json`, `evidence/authz/...`; not the findings database, the audit log, the report or hidden files):

| Parser | File |
|---|---|
| `semgrep` | Semgrep JSON (`--json`) |
| `osv-scanner`, `pip-audit` | their JSON output |
| `bandit`, `gitleaks` | their JSON reports |
| `authz` | an authorization-matrix run (`evidence/authz/`): `FAIL` and unexpected-deny cells; blocked cells are limitations |
| `laravel_map` | an application map (`evidence/appmap/`): its leads; its gaps are limitations |
| `http` | an HTTP exchange the sandbox wrote (`evidence/http/`, replays) |

Each observation has a fingerprint (tool, rule, location, the normalized snippet), so importing the same output
again counts it as seen again instead of adding it twice. Parser errors and what the tool says it skipped are kept
with the import and shown; a file no parser recognizes is an import with an error, not a silent nothing.

Grouping is a person's (or the planner's) decision. The workspace suggests groups (same rule in the same file, the
same package, the same route template) but never merges them: you **link** the observations that share a root
cause to one finding (they become its instances and their evidence is added), mark one a **duplicate** of
another, or **dismiss** it with the reason.

### Coverage

The plan is a list of tests. `plan_tests` with a playbook name (or **Add its checklist to the plan**) adds one item
per checklist line of that playbook, with the playbook's version and the standard references it names (ASVS,
WSTG, OWASP API Top 10 2023, OWASP LLM Top 10 2025). Each item ends in one of:

| Outcome | Needs |
|---|---|
| `tested` | the evidence it produced |
| `failed` | the finding it produced |
| `blocked` | the reason, and what would unblock it |
| `excluded`, `not-applicable` | the rationale |

An outcome records the build (source digest or deployed build) and the policy revision it ran on. **Reassess**
with a new build or policy revision marks earlier outcomes recorded against another one as stale, for a retest.
Coverage is reported per state and per standard. OWASP Top 10 lists are risk categories, not checklists: coverage
is measured against the planned tests and the requirements they reference, not "Top 10 covered".

### Objective and handover

The objective is what the engagement must answer (`set_objective`, or the console). The handover is built from the
records each time it's read: the objective, finding counts, material findings (critical and high, candidate or
confirmed), observations to triage, coverage, blocked and stale tests, import problems, pending decisions and the
next useful actions, plus a free-text note you edit. The planner reads it with `get_handover` when it resumes an
engagement; the console shows it in the **Investigation** tab.

---

## Evidence

Evidence is what makes a finding defensible: the tool output, request and response, or code location behind it.

### How evidence is recorded

Every Kali command runs in the engagement folder. When it finishes, the kit hashes every file it created or
changed (SHA-256) and stores the hashes in the audit log with the command. The tool result ends with
`[evidence recorded: semgrep.json, …]`. Files in `.home/`, Joern's `workspace/`, `node_modules/` and `.git/`
are skipped, and files over 512 MB are listed without a hash.

The command's own output (stdout and stderr, with the command, exit code, tier and time at the top) is saved by
the Kali server too, as `evidence/runs/<time>-<program>-<id>.txt`, and hashed in the same audit entry. The result
ends with `[output saved as verified evidence: …]`, so any command's output can be cited and shows as **Pass**,
even when the tool only prints to the screen. The agents are told to cite these paths instead of copying output
into files themselves.

A finding's evidence entries point at those files, optionally with a note:

```
/work/acme-2026-11/semgrep.json (rule python.django.security.injection.sql, orders/views.py:88)
/work/acme-2026-11/evidence/sqli-orders.txt
/src/acme-webshop/orders/views.py:88
```

`/src/…` entries are code references: they point into the client's code and aren't hashed.

### Integrity check

`evidence_provenance` (a Kali tool; the report runs it for every evidence file) hashes each file again and looks
for the audited command that produced exactly that content:

| Status | Meaning | In the report |
|---|---|---|
| `verified` | unchanged since the audited command produced it | **Pass**, with the command and time |
| `MODIFIED after it was produced` | the file changed after the command wrote it | **Fail**; keeps the report DRAFT |
| `not produced by an audited kali command` | the file exists but wasn't written by a Kali command (for example a worker step file or transcript) | **Not audited**; allowed |
| `missing` | the file doesn't exist | **Fail**; keeps the report DRAFT |
| (code reference) | a `/src/…` location | **Code ref** |

So: **never edit an evidence file after it's written.** To annotate it, put the note in the finding, or write a
new file with another Kali command. The agent's own workspace sees engagement files read-only, so it can't edit
them by accident.

Worker step files (`evidence/tasks/<task_id>/step-NN-<tool>.txt`) are written by the worker, not by Kali commands,
so they show as Not audited. Each Kali command inside a task has its own verified `evidence/runs/` file, and the
worker cites that one.

### Secrets

The worker removes secrets (private keys, AWS keys, GitHub and Slack tokens, API keys, JWTs, `password=…` style
values) from the summaries it sends back to the planner, and the report generator applies the same redaction to
finding text and the summary documents. Evidence files keep the original values. The patterns are a safety net,
not a guarantee: findings should describe and locate a secret, never quote it.

---

## The report

### Inputs

All in `/work/<engagement>/report/`:

| File | Required | Content |
|---|---|---|
| `meta.txt` | client name required | `Client:`, `Prepared by:`, `Version:` (default 1.0), `Classification:`. Created on the first report run if missing. `./rvkit new` writes `Client:` |
| `executive-summary.md` | yes | 3–5 paragraphs for a non-technical reader: what was assessed, overall posture, top risks in business terms, priorities |
| `methodology.md` | no | extra methodology text; the tool and tier summary is added automatically |
| `conclusion.md` | no | closing remarks |

The agent writes these with the findings server's `write_file` tool. It may write only these paths:
`PLAN.md`, `NOTES.md`, `notes/<name>.md` or `.txt`, `report/executive-summary.md`, `report/methodology.md`,
`report/conclusion.md` and `report/meta.txt` (up to 1 MB each). You can edit them yourself in the engagement
folder too. `Classification` (default `Confidential`) is printed on the cover.

### Contents

1. **Cover**: client, engagement, testing period (first to last audited activity), report date, prepared by,
   version and status (DRAFT or Final). A DRAFT report starts with the list of what blocks delivery.
2. **Executive summary**, then "Findings at a glance": counts per severity (and how many are open) and a table of
   all reported findings.
3. **Scope and rules of engagement**: the active scope (networks, domains including subdomains, source code) and
   rules (tiers, max rate, network, window, testing period), as enforced.
4. **Methodology**: your `methodology.md`, the tier model, how many commands ran per tier, how many were refused,
   how many intrusive actions were approved or denied, the most-used tools, and how severity is rated (CVSS
   adjusted with CISA KEV and EPSS for known vulnerabilities).
5. **Findings**, most severe first. Each with severity, CVSS score and vector, CWE, status, affected asset,
   description, impact, steps to reproduce, remediation, and an evidence table (path and note, SHA-256, integrity).
6. **Conclusion**, if `conclusion.md` exists.
7. **Appendix A: Evidence integrity**: every evidence file with its full SHA-256, the command that produced it and
   when, and the integrity result.
8. **Appendix B: Activity summary**: first and last activity, commands run and refused, approvals, emergency
   halts, scope changes, and how many results were triaged as false positives.

Only `confirmed`, `fixed` and `accepted-risk` findings are included.

### DRAFT or final

The report is marked DRAFT (on the cover, in the file name and in the tool result) while any readiness check
blocks delivery. These are facts about the record, to be fixed:

- `report/executive-summary.md` is missing or empty;
- there are untriaged `candidate` findings;
- `Client:` in `report/meta.txt` is empty;
- a reported finding has no evidence;
- an evidence file is missing, was modified after it was produced, or is outside the engagement folder.

These are methodology checks. A person (console or CLI, not the agent) may record an exception for one, with the
rationale, and the exception is listed in the revision:

| Check | Blocks when |
|---|---|
| `coverage-plan` | there is no coverage plan |
| `coverage-open` | planned tests have no outcome |
| `coverage-stale` | outcomes were recorded on another build or policy revision |
| `fields:<F-id>` | a reported finding has no asset, description, impact, reproduction or remediation |
| `verification:<F-id>` | a confirmed finding has no verification method |
| `retest:<F-id>` | a finding is marked fixed without a resolved retest record |

Warnings don't block: untriaged observations, open cleanup obligations, and finding text that looks like it holds
a secret (the report redacts it; remove it from the finding).

The result lists each issue. Fix them (or ask the agent to) and generate again.

### Revisions, approval and sending

Each generation is a new **report revision** (`R-001`, `R-002`, ...) in `report/revisions/<R-id>/`: the files, the
inputs they were built from (`inputs.json`: the finding revisions, report texts, details, coverage and the
activity summary) and the SHA-256 of every file. Earlier revisions, of the same day or not, are kept as they were;
the latest is also copied to `report/` as before.

| State | Meaning |
|---|---|
| `generated` | built, but a readiness check blocks delivery |
| `ready` | nothing blocks delivery: every check passes or has an exception |
| `approved` | a person approved it for client delivery |
| `superseded` | a later revision was approved |

**Approve** (console, or `./rvkit report <eng> approve R-003`) is a person's decision; the agent can't approve. It
is refused unless the revision is the latest, is `ready`, its files still match their hashes, and the findings,
coverage, exceptions and report texts are unchanged since it was generated. If anything changed, generate again
and approve the new revision. Approval sends nothing: when you send the report, **Record sending** (or
`./rvkit report <eng> sent R-003 "<to>" "<how>"`) adds that to the revision.

**Verify** re-hashes a revision's files. **Rebuild** renders the report again from the revision's frozen
`inputs.json` into `report/revisions/<R-id>-rebuild-<time>/` and compares the HTML byte for byte (the `.docx`,
`.pdf` and `.xlsx` embed creation times, so they differ in metadata only).

### Retests

A retest links a confirmed or fixed finding to the build it was retested on and its regression cases, each with
its result (`pass`, `fail`, `partial`), the evidence of the retest (required) and the earlier evidence (the
finding's, unless given). Its outcome:

- `resolved` (every case passes): the finding becomes `fixed` in a new revision, with the method `retest`;
- `partial` or `unresolved`: it stays, or goes back to, `confirmed`.

The original reproduction and every earlier revision stay in the finding's history. The record keeps the build
the finding was found on (from its coverage item), and when the retest needed scope or access re-authorized, who
did that and when. The agent records retests with `record_retest`; the console's **Report** tab lists them.

### Cleanup and retention

Cleanup obligations are what has to be undone or decided before close-out: test data and fixture changes,
credentials to revoke, access to remove, what to keep or delete (`fixture`, `credential`, `data`, `access`,
`retention`, `other`). Each stays open until it's recorded done (with what was done) or waived (a person's
decision, with the reason). Open ones are pending decisions in the handover and a warning in the readiness checks.

### Notices and exports

A **notice** is a draft about one confirmed critical or high finding, for you to review before it's shared:
`report/notices/N-001-F-004.md`, tied to the finding's revision. **Mark reviewed** is refused if the finding or
the file changed since it was prepared. Nothing is sent from the kit.

**Export** builds, from the approved revision's frozen findings (or the latest revision, marked DRAFT, when you
ask for that), in `report/exports/<R-id>/`:

| File | Content |
|---|---|
| `findings.json` | the reported findings (schema `rvkit-findings/1`), each with its revision, and the report revision and approval |
| `findings.sarif` | SARIF 2.1.0: one rule and one result per finding, with a source location for `file:line` assets and instances, otherwise the asset as a logical location; `security-severity` from the CVSS score |
| `issues/<F-id>.md` | issue-ready text per finding |

Ticket systems and client portals aren't connected: upload the files yourself.

### Generating

The agent calls `generate_report` at the end of a run. You can run it yourself at any time:

```sh
./rvkit report acme-2026-11
```

It takes about a minute (the PDF is the HTML report printed with headless Chromium) and prints the revision, its state and the readiness
checks. Files in `/work/<engagement>/report/revisions/<R-id>/`, the latest also in `/work/<engagement>/report/`:

| File | Content |
|---|---|
| `<eng>-report-<date>.html` | the report as one web page in the RiskVoid report design (`-DRAFT.html` while it's a draft) |
| `<eng>-report-<date>.docx` | the report as an editable Word document (`<eng>-report-<date>-DRAFT.docx` while it's a draft) |
| `<eng>-report-<date>.pdf` | PDF of the same |
| `<eng>-findings-<date>.xlsx` | findings register |

Generating again on the same day replaces that day's files in `report/`; every revision keeps its own copy in
`report/revisions/`.

The `.html` report is a single file with its fonts and logo embedded: it loads nothing from the internet, so you
can email it, archive it or open it offline. It has no scripts. Print it from a browser for a PDF with one page
per section (cover first). With a custom or plain brand it uses your name, logo, primary and accent colours and
font names (fonts are not embedded for custom brands: readers see them if installed, a system font otherwise).
In the console, **Report > View HTML report** opens it in a locked-down tab.

You can edit the `.docx` by hand after generating it (for example to polish wording). Do that last, or save it
under another name: generating again the same day overwrites it. Content changes are better made in the findings
and the `.md` files, so the next generated report has them too.

### Findings register

The `.xlsx` has the client, engagement and report date at the top, then one row per reported finding: ID,
Severity, Finding, Asset, CWE, CVSS, Status (Open / Resolved / Accepted risk) and Remediation (first 1,000
characters).

---

## Branding

Set in `.env`, then `./rvkit up`:

| Setting | Result |
|---|---|
| `REPORT_BRAND=riskvoid` (default) | RiskVoid logo, colours and fonts |
| `REPORT_BRAND=plain` | neutral design, no logo; `ORG_NAME` as the name |
| `REPORT_BRAND=custom` + `REPORT_BRAND_FOLDER=/path/to/brand` | your logo, colours and fonts: copy `harness/brands/example/` and follow [its README](../harness/brands/example/README.md) |

`ORG_NAME` is the default "Prepared by" on the cover (and the name the planner works for). Per engagement,
`Prepared by:` in `report/meta.txt` overrides it. `meta.txt` is created on the first report run with the brand's
name filled in, so an engagement first reported under another brand keeps that name until you edit the file.

If the brand folder or `brand.json` is invalid, report generation stops with an error saying what to fix, and
nothing is written. See [configuration.md](configuration.md) for all settings.

---

## Handing over and closing out

1. Generate the final report (status `final`, no issues).
2. Review the `.docx` / PDF yourself. You are responsible for what goes to the client.
3. Send the PDF (and the `.xlsx` if the client wants a register).
4. Close the engagement: `./rvkit close <eng>`. It writes the audit extract and a SHA-256 manifest, archives the
   folder with its own checksum, and halts the engagement. See
   [engagements.md](engagements.md#closing-an-engagement).

For a retest later, see [running-the-agent.md](running-the-agent.md#retest-after-client-fixes).

---

See also: [engagements.md](engagements.md), [running-the-agent.md](running-the-agent.md),
[tools-reference.md](tools-reference.md)
