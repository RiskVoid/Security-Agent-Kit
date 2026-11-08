# The RiskVoid Console

The console is a local web page for the operator's side of the kit: engagements, approvals, findings, reports
and the audit log. Everything in it can also be done with `./rvkit`; the console puts it in one place and saves
you the terminal round-trips. You still talk to the agent in the OpenHands UI.

```sh
./rvkit console            # starts it and opens it in your browser, signed in
./rvkit console --no-open  # prints the sign-in link instead (for example on a remote machine over SSH)
```

It uses the riskvoid.io dashboard design (same colours, type, sidebar, cards and form controls), with the fonts
and logo served locally: the page makes no requests outside your machine.

It runs in the foreground; Ctrl-C stops it. The address is `http://127.0.0.1:8100/` (set `CONSOLE_PORT` in
`.env` to change it).

## What you can do

| Page | What it does | Same as |
|---|---|---|
| **Engagements** list | Every engagement with its client, status (active, halted, closed), confirmed findings, how many wait for triage, and pending approvals. Filter by name or client. | `./rvkit eng list` |
| **New engagement** | Name, client, targets, tiers, rate, network and the private-worker switch, validated before anything is created. | `./rvkit new` |
| Engagement **Overview** | Findings by severity, the active scope and rules (with where client data may go), pending approvals for this engagement, and a ready prompt to paste into the agent UI. **Models** shows where each model route sends data now and flags routes the engagement's `Client data:` rule doesn't allow. **Conversations**: start an OpenHands conversation bound to the engagement (with an optional first message), open or unbind one. **Credentials**: store, replace or remove a credential the agent uses by reference; values are never shown. | `./rvkit show`, `conversation`, `cred` |
| **Live** | What the engagement is doing now, refreshed every few seconds: the commands running in the Kali sandbox (with their tier and time against their timeout), worker tasks and their current step and model, approvals waiting for you, today's OpenRouter spend against the daily budget, and the latest commands, refusals and approvals. | `./rvkit status`, `./rvkit audit` |
| **Scope & rules** | Edit `SCOPE.md` and `RULES.md`, **Preview changes** (a diff, the parser's warnings, and exactly what the firewall will allow), then **Apply**. Preview writes nothing. | `./rvkit scope <eng>` |
| **Findings** | Sort by severity and filter by status. Click a finding to change its status (including `duplicate` with the finding it duplicates), severity and notes, and read the description, reproduction, remediation and evidence. **Check evidence integrity** shows a badge per evidence file: verified, code ref, not audited, or what's wrong. | the findings tools in chat |
| **Worker tasks** | Every task the planner handed to the worker model, newest first: status, tier, which model served it, what it depends on, each command it ran and its summary. A task waiting for an approval shows the approval id. A task interrupted by a restart shows the recovery decision and what was in flight, with **Resume from checkpoint**. **Cancel** stops a task. Refreshes every few seconds while a task is active. | `list_tasks` in chat, `./rvkit task` |
| **Report** | Edit the cover details (client, prepared by, version, classification) and the executive summary, **Generate report**, see whether it's DRAFT and why, **View HTML report**, and download the `.html`, `.docx`, `.pdf` and `.xlsx`. | `./rvkit report` |
| **Audit log** | Every command, refusal, approval, halt and scope change for the engagement, newest first. | `./rvkit audit` |
| **Halt now / Resume / Close out / Delete** | The engagement controls, each with a confirmation step where it matters. | `./rvkit halt`, `resume`, `close`, `eng delete` |
| **Approvals** | Every pending intrusive command across engagements, with Approve and Deny. **Enable desktop notifications** alerts you when a new one arrives while the page is open. The tab title shows the count. | `./rvkit watch` |
| **Status** | The output of `./rvkit status`: services, worker, planner, spend, engagements. | `./rvkit status` |
| **Model log** | Failed model calls and calls another model answered instead, with what to do; filter by period. Per engagement in its **Model log** tab. | `python3 scripts/model_events.py` |

**Model log** lists model calls that failed, each with what to do (top up credits, raise the budget, restart Colab,
...), and calls another model answered instead. Each engagement has its own **Model log** tab. The sidebar page
shows every engagement's calls, and calls that couldn't be matched to one. The sidebar badge and the tab count the
failures of the last 24 hours. See [models.md](models.md#when-a-model-call-fails).

After you approve a command, tell the agent to run it again (the approval is for that exact command, once).

## Security

The console can approve intrusive commands and change scope, so it is kept out of the agent's reach:

- **It runs on your computer, not in Docker**, and listens on `127.0.0.1` only. The agent's containers
  (OpenHands and the worker) are on an internal network with no route to the host, and Kali commands can only reach
  in-scope targets (the firewall also blocks the Docker host's own addresses).
- **Other containers can open the port, but can't sign in.** Docker Desktop and OrbStack forward
  `host.docker.internal` to your computer's loopback, so the kit's own service containers (LiteLLM, the MCP servers)
  can connect to the console's port. Every request needs the session token, which no container has, so they get
  `401`. On Linux Docker the port isn't reachable from containers at all. `./rvkit doctor` and `./rvkit console`
  refuse a kit folder placed inside `PROJECTS_DIR` or `ENGAGEMENTS_DIR`, which would expose `.env` and the token.
- **It needs a session token.** `./rvkit console` opens a sign-in link that sets an `HttpOnly`,
  `SameSite=Strict` cookie. The token is in `.rvkit/console.token` (readable only by you, not mounted into any
  container). Delete that file to make a new one; old sign-ins stop working.
- **Requests for another host name are refused** (protection against DNS rebinding), **cross-site requests are
  refused** (`Origin` and `Sec-Fetch-Site`), and **every change needs a header a web page on another site can't
  send** and a JSON body, so a malicious page can't make your browser act on the console. Every field is checked;
  malformed input gets `400` with the reason.
- **It uses the same operations as `./rvkit` and the agent's tools**: `rvctl` in the Kali container for scope,
  approvals and the engagement lifecycle; `harness/ops.py` in the findings container for findings, the report's
  cover details and executive summary, and the report. Only the operations listed there exist; the console can't
  run anything else.
- Report downloads are limited to `.html`, `.docx`, `.pdf` and `.xlsx` files in an engagement's `report/` folder.
  The HTML report opens with a policy that blocks scripts and every network request (`sandbox`, `default-src 'none'`).
- Text written by the agent (findings, commands, notes) is shown as text, never as HTML.

To use it from another machine, forward the port over SSH rather than exposing it:

```sh
ssh -L 8100:127.0.0.1:8100 you@kit-host     # then, on the kit host: ./rvkit console --no-open
```

Open the printed sign-in link on your own machine.

## Scope and rules preview

**Preview changes** shows the diff and what the policy will allow, exclude and when, the stop conditions, and what
the kit doesn't enforce for this scope. Lines the kit can't enforce or doesn't understand are listed under
**Can't apply** with the reason, and **Apply** stays disabled until they are fixed. Applying creates a new policy
revision and makes earlier approvals that weren't used yet stale.

An approval card says what the approval is bound to: the scope and rules revision, the programs and input files
of a command or the headers of a request, and the worker task that asked. A request made through the request tool
shows as `HTTP <method> <url>`.

## Who changed what

Every change made in the console is recorded in the engagement's audit log (the **Audit log** tab) with who made
it (`console:<your login>`, `cli:<your login>` for `./rvkit`, `agent:…` for the agent) and the revision before and
after: finding updates, cover details, the executive summary, scope and rules, approvals, halt and resume.

When something changed after you opened it (the agent updated a finding, you saved from another tab, someone used
`./rvkit`), saving doesn't overwrite it. The console says what happened, keeps your edit on screen and, for a
finding, shows the version saved meanwhile and who saved it. Saving again replaces that version deliberately. For
scope and rules, preview again: the diff is then against the current scope.

## Live updates

The page receives changes as they happen (server-sent events on `/api/stream`): new approvals, engagement state,
and, while the **Live** tab is open, running commands and worker tasks. If the connection drops, the page polls
every few seconds until it comes back.

## Keyboard and small screens

Tabs follow the usual pattern: arrow keys, Home and End move between them. A confirmation (close out, delete) puts
focus on Cancel; Escape closes it. Errors are announced to screen readers. On a phone-width window the sidebar
becomes a menu and the tab strip scrolls sideways; nothing scrolls the whole page sideways.

## Not in the console yet

- The planner's own reasoning and messages: use the OpenHands UI. The **Live** tab shows what it runs (every
  Kali command and worker task) and the spend, but not the conversation, and spend is for the whole kit, not per run.
- The conversation itself: **New conversation** creates and binds it and can send the first message; you follow
  it in the OpenHands UI.
- Continuing the planner automatically after an approval: tell it to run the command again. Worker tasks continue
  by themselves.
- Models and the worker (Colab, fallback, budget): use `./rvkit worker`, `./rvkit budget` and `/rv-start`.
- Several users: there is one token per kit and approvals don't record who approved.
