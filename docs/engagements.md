# Engagements

An engagement is one authorised piece of work for one client: a scope (what may be tested), rules (how hard,
how fast, when), a working folder, a findings database, an audit trail and a report. This page covers the whole
lifecycle, from creating an engagement to archiving it, and how the kit enforces what you put in it.

For a guided first run, see [first-engagement.md](first-engagement.md). For talking to the agent once an
engagement exists, see [running-the-agent.md](running-the-agent.md).

---

## Lifecycle

```
 ./rvkit new ──► SCOPE.md + RULES.md written and applied (authoritative copy in the control volume)
                       │
                       ▼
 conversation with riskvoid-planner ──► PLAN.md ──► tool runs (kali / worker) ──► evidence + findings
                       │                                     │
                       │                       intrusive command? ──► APPROVAL REQUIRED ──► ./rvkit watch
                       ▼
 report/executive-summary.md ──► generate_report / ./rvkit report ──► .docx + .pdf + .xlsx (DRAFT until ready)
                       │
                       ▼
 ./rvkit close ──► audit extract + MANIFEST.sha256 + archive in _archive/ ──► engagement halted
```

At any point: `./rvkit scope <eng>` changes scope or rules, `./rvkit halt <eng>` stops everything, and
`./rvkit audit <eng>` shows what ran.

---

## Before you start: client code

If the work includes source code, put each repository in your projects folder (`PROJECTS_DIR`, default
`~/riskvoid/projects`):

```sh
git clone https://git.example.com/acme/webshop.git ~/riskvoid/projects/acme-webshop
```

The OpenHands, worker and Kali containers see that folder read-only as `/src`, so this repository is
`/src/acme-webshop`. The tools only
see it when `/src/acme-webshop` is in the engagement's scope (below). Nothing in the kit writes to client code.

---

## Creating an engagement

### Interactively: `./rvkit new`

```sh
./rvkit new            # or: ./rvkit new acme-2026-11
```

It asks, in order (Enter accepts the default in brackets):

| Question | Default | Notes |
|---|---|---|
| Engagement name | | Letters, digits, `.`, `_`, `-`; starts with a letter or digit; up to 64 characters. Refused if the engagement already has a `SCOPE.md`. |
| Client name (shown on the report) | empty | Written to `report/meta.txt`. You can add it later. |
| Targets | | One per prompt, empty line to finish. It lists the code folders it finds in `PROJECTS_DIR` as `/src/<folder>`. At least one target. |
| Allowed tiers | `passive, active` | Comma-separated list of `passive`, `active`, `intrusive`. |
| Max requests/packets per second | `100` | A whole number. |
| Network | `online` | `online` or `offline` ([below](#online-and-offline)). |
| Keep this client's tool output on the worker endpoint only? | `n` | `y` adds `Worker model: private` to `RULES.md` ([below](#rulesmd)). |

It writes `SCOPE.md`, `RULES.md` (an existing one is kept) and, if you gave a client name, `report/meta.txt`, applies them straight away and prints a prompt you can
paste into the agent UI.

### In one command: `./rvkit engagement`

```sh
./rvkit engagement acme-2026-11 --client "Acme Ltd" app.acme.com "*.acme.io" 203.0.113.0/28 /src/acme-webshop
```

Same result without questions, with the defaults: tiers `passive, active`, max rate 100, network `online`, no
private worker. Edit `RULES.md` afterwards to change them (see [Changing scope and rules](#changing-scope-and-rules)).

If the engagement already exists, `./rvkit engagement` refuses and changes nothing. Add `--replace` to swap its
whole `SCOPE.md` for the targets you give; the diff is printed and applied at once. `RULES.md` is kept.

### Limits

- Engagement names must match `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`.
- Each engagement gets its own unprivileged user in the Kali container. Up to 250 engagements can be registered
  at once; deleting a closed one frees its slot (see [Cleaning up](#cleaning-up-an-engagement)).

---

## The engagement folder

Each engagement is a folder in your engagements folder (`ENGAGEMENTS_DIR`, default `~/riskvoid/engagements`).
The agent and tools see it as `/work/<engagement>/`.

```
~/riskvoid/engagements/
├── audit.log                     informational copy of the audit log (all engagements); see below
├── _archive/                     archives written by ./rvkit close
│   ├── acme-2026-11-20261121T163000Z.tar.gz
│   └── acme-2026-11-20261121T163000Z.tar.gz.sha256
└── acme-2026-11/
    ├── SCOPE.md                  authorised targets (your copy; see "Changing scope and rules")
    ├── RULES.md                  tiers, rate, network, window, worker
    ├── PLAN.md                   the agent's plan and playbook checklists
    ├── NOTES.md, notes/          the agent's working notes
    ├── findings.db               findings database (SQLite)
    ├── *.json, *.txt, evidence/  tool output written by kali commands (hashed in the audit log)
    ├── evidence/tasks/<task_id>/ worker tasks: step-NN-<tool>.txt per tool call, transcript.jsonl
    ├── out-<timestamp>.txt       full output of a command whose output was too long to return (>30,000 chars)
    ├── .home/                    tool home folder and caches (not evidence)
    ├── report/
    │   ├── meta.txt              Client, Prepared by, Version, Classification
    │   ├── executive-summary.md  written by the agent (required for a final report)
    │   ├── methodology.md        optional
    │   ├── conclusion.md         optional
    │   ├── acme-2026-11-report-2026-11-21.docx / .pdf
    │   └── acme-2026-11-findings-2026-11-21.xlsx
    ├── audit.jsonl               after close: this engagement's audit entries
    └── MANIFEST.sha256           after close: SHA-256 of every file
```

The top-level `audit.log` is a convenience copy for reading on the host. The worker and findings containers
can write to this folder, so the copy is not trusted: evidence checks, the activity summary in reports, close-out
extracts, `./rvkit audit` and the console all read the authoritative log in the Kali control volume
(`/control/audit.log`), which nothing but the Kali server writes.

Who writes what:

- **You** write `SCOPE.md` and `RULES.md` (through `./rvkit`), and can edit `report/meta.txt`.
- **Kali commands** write tool output. Every file a command creates or changes is SHA-256 hashed in the audit log
  (except tool caches: `.home/`, Joern's `workspace/`, and any `node_modules/` or `.git/` folder).
- **The agent** writes `PLAN.md`, `NOTES.md`, `notes/*` and the `report/*.md` / `meta.txt` files through the
  findings server's `write_file` tool. Its own workspace sees `/work` read-only, so it can't edit evidence.
- **The findings server** writes `findings.db` and the report files.

See [findings-and-reports.md](findings-and-reports.md) for findings, evidence and the report.

---

## SCOPE.md

One target per line. A leading `-` or `*` is ignored, and so is anything after `#`.

```markdown
# Authorised scope (2026-11-07). One host, domain, CIDR, or /src/<repo> path per line.
- app.acme.com
- *.acme.io                     # all subdomains of acme.io
- 203.0.113.0/28
- 198.51.100.7
- https://portal.acme.com:8443/login   # read as portal.acme.com
- /src/acme-webshop
```

| Entry | Meaning |
|---|---|
| `app.acme.com` | That domain **and all its subdomains**. You can't limit scope to one exact host name yet. |
| `*.acme.io` | The same as `acme.io`: the domain and its subdomains. |
| `203.0.113.0/28`, `198.51.100.7` | IPv4 networks and addresses. A host address inside a CIDR is fine (`10.0.0.5/24` becomes `10.0.0.0/24`). |
| `https://host:8443/path` | The scheme, port and path are dropped: only the host counts. Scope is per host, not per port or URL. |
| `/src/<repo>` | Client code the tools may read (read-only). Code not listed here is invisible to engagement commands. |

Ignored, with a warning when you apply the scope:

- IPv6 addresses and networks (IPv6 isn't supported; all IPv6 traffic from engagement commands is dropped).
- Loopback, link-local (including cloud metadata `169.254.169.254`), `0.0.0.0/8` and multicast. These are never
  reachable.
- Paths outside `/src`.
- Anything that isn't an IPv4 address, a CIDR or a dotted domain name (for example a single-label name like
  `intranet`).

Domain names are resolved through a per-engagement DNS server that answers only for in-scope domains (and, for
online engagements, the infrastructure domains). Their addresses become reachable once resolved.

---

## RULES.md

```markdown
# Rules of engagement for acme-2026-11. Change here, then run: ./rvkit scope acme-2026-11
- Allowed tiers: passive, active
- Max rate: 100
- Network: online
# - Window (UTC): 08:00-18:00
# - Strict tiers: on
# - Worker model: private
```

| Rule | Values | Default (rule missing) |
|---|---|---|
| `Allowed tiers:` | any of `passive`, `active`, `intrusive`, comma-separated | `passive, active` (a line with no valid tier means `passive` only) |
| `Max rate:` | requests or packets per second, a whole number | `100` |
| `Network:` | `online` or `offline` | `online` |
| `Window (UTC):` | `HH:MM-HH:MM`, in UTC. An overnight window such as `22:00-06:00` works | no window: any time |
| `Strict tiers:` | `on`, or anything else for off | off |
| `Worker model:` | `private`, or anything else for the default | not private |

Lines starting with `#` are comments, so remove the `#` to turn on a rule. Rule names are matched without regard to
case.

**Worker model: private** means the worker's tool work for this engagement always uses the `private-llm` model: the
worker endpoint only, never the OpenRouter fallback, even when you have turned the fallback on. See
[models.md](models.md).

---

## Changing scope and rules

Edit `SCOPE.md` or `RULES.md` in the engagement folder, then:

```sh
./rvkit scope acme-2026-11          # shows the diff against the active copy; changes nothing
./rvkit scope acme-2026-11 --yes    # applies it
```

**Editing the files alone has no effect.** The active scope and rules are a copy kept in the Kali container's
root-only control volume (`kali-control`), together with approvals, halt flags and the audit log. Only `./rvkit`
updates that copy, so the agent can't widen its own scope. Inside the sandbox, `SCOPE.md` and `RULES.md` show the
active copy, read-only. Every applied change is recorded in the audit log (`scope-sync`) and counted in the
report.

`./rvkit show <eng>` prints what is active now, as JSON: scope, rules, halt state and the infrastructure domains.

---

## Tiers

Every command the agent runs through the Kali tool is classified into a tier. Commands above the engagement's
allowed tiers are refused. Intrusive commands also need your approval each time.

| Tier | Meaning | Examples |
|---|---|---|
| **passive** | code and config analysis, research, offline tools | `semgrep`, `bandit`, `gitleaks`, `trufflehog`, `rv-joern`, `osv-scanner`, `trivy`, `syft`, `grep`, `jq`, `python3`, `bash`, `jwt_tool` without `-t`, `rv-llm payloads` |
| **active** | scans, crawling, fingerprinting, requests to targets | `nmap`, `naabu`, `httpx`, `nuclei`, `nikto`, `ffuf`, `feroxbuster`, `gobuster`, `katana`, `whatweb`, `wafw00f`, `testssl`, `sslscan`, `wpscan`, `amass`, `arjun`, `gowitness`, `graphw00f`, `graphql-cop`, `clairvoyance`, `curl`, `wget`, `nc`, `rv-llm ask`, `rv-llm mcp`, `jwt_tool -t <url>` |
| **intrusive** | exploitation, brute force, fuzzing, attack payloads, DoS-capable tools | `sqlmap`, `hydra`, `medusa`, `commix`, `dalfox`, `zaproxy` / `zap.sh` / `zap-full-scan.py`, `schemathesis`, `garak`, `msfconsole`, `netexec`, `hashcat`, `john`, `hping3`, `slowhttptest`, `rv-llm probe`, `rv-llm mcp-call`, `jwt_tool -t <url>` with `-X`/`-I`/`-S`/`-M` |

Special cases:

- **nuclei** is intrusive with `-tags`, `-itags` or `-t` naming `intrusive`, `dos`, `fuzz` or `brute` templates,
  or with `-dast` / `-fuzz`. Otherwise active.
- **nmap** is intrusive with `--script` containing `brute`, `dos`, `exploit`, `intrusive` or `vuln`. Otherwise
  active.
- A command line with several programs (`a | b`, `a && b`, `$(…)`) gets the highest tier of any of them. Wrappers
  like `timeout`, `env`, `nice` and `sudo` are skipped to find the real program.

- `sh -c '…'`, `bash -lc "…"` and `eval '…'` get the tier of what they run, and rate caps apply inside them.

**Known limitation.** Tiers are decided by program name. A program the kit doesn't list, including `python3`,
`bash` and your own scripts, counts as passive; `curl` counts as active. Such commands can send intrusive traffic
to in-scope hosts without approval. The firewall still limits them to the scope. See
[SECURITY.md](../SECURITY.md#known-limitations).

**Strict tiers.** Add `- Strict tiers: on` to `RULES.md` (then `./rvkit scope <eng>`) to close the common cases:

- interpreters running code count as intrusive: `python3 x.py`, `python3 -c …`, `perl`, `ruby`, `node`, `php`,
  `bash script.sh`, `socat`, … (`python3 --version` and `--help` stay passive);
- `curl` and `wget` sending data count as intrusive: `-d`, `--data*`, `--json`, `-F`, `-T`, `-X POST/PUT/PATCH/DELETE`,
  `--post-data`, `--method=POST`, ….

Every such command then waits for your approval, so use it on engagements where that is worth the extra approvals
(production systems, fragile targets). It still goes by the command line, not by what the code does. The lists
are in the `strict` section of `kali-mcp/tiers.yaml`.

All the tier lists, subcommand rules and rate flags are in [`kali-mcp/tiers.yaml`](../kali-mcp/tiers.yaml).

The tier lists also name programs that aren't installed in the Kali image (`hydra`, `medusa`, `msfconsole`,
`netexec`, `hashcat`, `john`, `hping3`, `slowhttptest`, `masscan`, `dirsearch`, and ProjectDiscovery `httpx`; the
image has `httpx-toolkit`), so they're classed correctly if you add them. What is installed:
[tools-reference.md](tools-reference.md).

When the planner hands work to the worker model, it also gives the task a tier. The worker refuses a tier the
engagement doesn't allow.

---

## Rate limits

When a command runs one of these tools, the kit adds the engagement's max rate:

| Tool | Flag added |
|---|---|
| `nmap` | `--max-rate N` |
| `masscan` | `--rate N` |
| `naabu` | `-rate N` |
| `nuclei`, `httpx`, `httpx-toolkit`, `katana` | `-rl N` |
| `ffuf` | `-rate N` |
| `feroxbuster` | `--rate-limit N` |
| `dirsearch` | `--max-rate N` |
| `schemathesis run` | `--rate-limit N/s` |
| `rv-llm probe` | `--rate N` |

If the command already sets one of these flags at or below the max, it is left alone. A higher value is refused.
When the kit changed the command, the result's second line is `[rate limit applied: …]` (after
`exit=<code> tier=<tier>`), and the audit log keeps both versions.

---

## Online and offline

Both modes always allow the in-scope targets. The difference is the "infrastructure" sites the tools need for
rules, packages and vulnerability databases:

- **online** (default): engagement commands may also reach these sites and their subdomains, on TCP 80 and 443
  only: `pypi.org`, `files.pythonhosted.org`, `osv.dev`, `semgrep.dev`, `nvd.nist.gov`, `api.first.org`,
  `cisa.gov`, `github.com`, `githubusercontent.com`, `registry.npmjs.org`, `proxy.golang.org`, `rubygems.org`,
  `repo.maven.apache.org`, `grype.anchore.io`, `mirror.gcr.io`, `ghcr.io` (the list is
  `kali-mcp/infra_domains.txt`).
- **offline**: none of them. Tools that download rules or databases on use won't work: use the local semgrep
  rules (`semgrep --config /opt/semgrep-rules/<lang>`) and skip scanners that fetch databases. The agent's prompt
  tells it this.

This applies to engagement commands. Web research by the agent (search and fetch) and vulnerability lookups go
through other services; see [architecture.md](architecture.md).

---

## How scope is enforced

Two layers:

1. **Pre-check (readable refusals).** Before a network tool runs, the kit looks for host names and IP addresses in
   its command line. Any that aren't in scope give
   `REFUSED: targets not in scope for <eng>: [...]`. This catches mistakes early with a clear message; it only looks
   at network tools.
2. **Firewall (the real boundary).** Each command runs as the engagement's own unprivileged user, in a sandbox that
   shows only its engagement folder and in-scope code (read-only). An nftables policy for that user allows only
   in-scope addresses, resolved in-scope domains and, when online, the infrastructure sites. Everything else is
   dropped, including the kit's own services, other engagements' targets, loopback, link-local and IPv6.

So a script that builds a URL the pre-check can't see is still blocked by the firewall if the host is out of scope.

The practice lab network (`10.250.0.0/24`) is treated like any other target: reachable only from engagements that
have a lab address in scope.

---

## Approvals

An intrusive command doesn't run at first. The Kali tool answers:

```
APPROVAL REQUIRED (intrusive). Approval id: 3f9a1c2e. Ask the user to review and run on the host:
./rvkit approve acme-2026-11 3f9a1c2e   Then call run again with the same command and approval_id='3f9a1c2e'.
```

The agent should show you the command and say why it needs it. You decide on the host:

```sh
./rvkit watch                              # live: notification + a/d/s prompt for each new request
./rvkit approvals                          # list pending approvals (all engagements)
./rvkit approvals acme-2026-11             # ... for one engagement
./rvkit approve acme-2026-11 3f9a1c2e      # approve
./rvkit deny acme-2026-11 3f9a1c2e         # deny
```

`./rvkit watch` checks every 3 seconds, shows a desktop notification (macOS, or `notify-send` on Linux) and asks
for each new request: `a` approve, `d` deny, `s` skip for now (the default; it stays pending). It needs a
terminal. Stop it with Ctrl-C.

Or use the **Approvals** page of the [console](console.md) (`./rvkit console`): every pending command across
engagements, with Approve and Deny buttons and optional desktop notifications.

After you approve, **tell the agent it's approved** (for example "approved, go ahead"). It must call the Kali tool
again with the identical command and the `approval_id`.

The rules:

- An approval is for **that exact command**. The agent can't change a single character, or the approval doesn't
  apply.
- It can be used **once**. Running the same command again needs a new approval.
- It **expires 24 hours** after you decide it.
- Asking again for the same command while it's still pending returns the same approval id.
- Every request, approval, denial and use is in the audit log.

The engagement's rate limit is applied to approved commands too.

---

## Halt and resume

```sh
./rvkit halt acme-2026-11      # kill every running command for this engagement and refuse new ones
./rvkit resume acme-2026-11    # allow commands again
```

Halting kills all processes of the engagement's user at once and refuses new Kali commands and worker tasks with
`engagement is halted`. Use it whenever something looks wrong. It doesn't affect other engagements.

## Testing window

With `Window (UTC): 08:00-18:00` in `RULES.md`, commands outside that time are refused with
`outside the testing window in RULES.md (UTC)`. Commands already running aren't stopped at the end of the window;
use `halt` for that.

---

## Audit log

Every Kali command, refusal, approval, halt and scope change is logged.

```sh
./rvkit audit                     # last 20 entries, all engagements
./rvkit audit acme-2026-11        # last 20 for one engagement
./rvkit audit acme-2026-11 200    # last 200
```

The authoritative log is in the control volume (`/control/audit.log`, root-only). A copy is appended to
`<ENGAGEMENTS_DIR>/audit.log` for convenience. Each line is JSON:

| Field | Meaning |
|---|---|
| `ts` | UTC time |
| `engagement`, `uid` | the engagement and its sandbox user |
| `command` | the command as run (after the rate limit was added) |
| `original` | the command as the agent sent it, when the kit changed it |
| `tier` | `passive`, `active` or `intrusive` |
| `exit`, `seconds` | exit code and duration (`exit` is -1 on timeout) |
| `outputs` | files the command created or changed, with their SHA-256 |
| `approval` | the approval id used |
| `refused` | the reason, for refused commands |
| `event` | for non-command entries: `scope-sync`, `approval-requested`, `approval-approved`, `approval-denied`, `halt`, `resume`, `closed` |

Commands time out after 600 seconds by default (the agent can ask for up to 3,600; when the planner calls the
kali tool directly, OpenHands stops waiting after 30 minutes, so long scans are better delegated to the worker).

---

## Seeing what's going on

```sh
./rvkit status          # services, models, spend, number of engagements, pending approvals
./rvkit eng list        # every engagement: tiers, network, targets, HALTED, pending approvals
./rvkit show acme-2026-11
```

The engagement commands except `engagement` and `watch` also work under `eng`: `./rvkit eng show acme-2026-11`, `./rvkit eng close …`.

---

## Closing an engagement

When the work is delivered:

```sh
./rvkit close acme-2026-11
```

This:

1. writes `audit.jsonl` into the engagement folder: every audit entry for this engagement;
2. copies the active `SCOPE.md` and `RULES.md` over the folder's copies, so the archive holds what was enforced;
3. writes `MANIFEST.sha256`: the SHA-256 of every file in the folder (tool caches are skipped: `.home/`, Joern's
   `workspace/`, and any `node_modules/` or `.git/` folder);
4. archives the folder to `<ENGAGEMENTS_DIR>/_archive/<eng>-<UTC time>.tar.gz` (without `.home/` and
   `workspace/`; `node_modules/` and `.git/` folders are archived but not in the manifest) and writes the archive's own checksum next to it as `.tar.gz.sha256`;
5. halts the engagement.

To check an archive later:

```sh
cd ~/riskvoid/engagements/_archive
shasum -a 256 -c acme-2026-11-20261121T163000Z.tar.gz.sha256    # Linux: sha256sum -c …
```

And the files inside an extracted archive, or the engagement folder itself:

```sh
cd ~/riskvoid/engagements/acme-2026-11
shasum -a 256 -c MANIFEST.sha256
```

### Reopening

A closed engagement is only halted. To do more work (say, a retest):

```sh
./rvkit resume acme-2026-11
```

When you're done, `./rvkit close acme-2026-11` again writes a new manifest and a new, separately timestamped
archive. The earlier archive stays as it was.

### Cleaning up an engagement

Once an engagement is closed and archived, delete it:

```sh
./rvkit eng delete acme-2026-11
```

This removes its scope, rules, approvals and firewall rules, so it no longer shows in `./rvkit eng list` or the
agent's `list_engagements`, no longer counts towards the 250 limit, and its targets drop off the web tool's
refusal list. Nothing on disk is deleted: the folder is renamed to `_deleted-acme-2026-11-<UTC time>`, the
archives stay in `_archive/`, and the audit log keeps the engagement's history. Remove or move the renamed
folder yourself when you no longer need it. Files the sandbox wrote there may belong to another user; on Linux,
delete them with `sudo` or from a container.

`./rvkit eng delete <name> --force` deletes an engagement that was never closed, after asking you to confirm. It
writes no archive or manifest, so keep it for practice and test engagements.

---

## Several engagements at once

Engagements are fully separate: each has its own sandbox user, firewall rules, DNS, approvals and halt switch. A
command for one engagement can't see another engagement's folder or code, or reach its targets (unless the
targets are in both scopes). Name the engagement in every conversation, and use one conversation per engagement.

The worker runs one task at a time by default, so tasks from parallel conversations queue up. With an endpoint
that serves parallel requests, raise `WORKER_PARALLEL_TASKS` in `.env`.

## Practice engagement

`./rvkit quickstart` creates `lab-juice` (scope `10.250.0.10`, OWASP Juice Shop in the isolated lab; client
"Practice lab"; default rules). It's a safe place to try scope changes, approvals and halts. See
[first-engagement.md](first-engagement.md) and [lab-and-benchmarks.md](lab-and-benchmarks.md).

---

Next: [running-the-agent.md](running-the-agent.md) · See also: [findings-and-reports.md](findings-and-reports.md),
[cli-reference.md](cli-reference.md), [SECURITY.md](../SECURITY.md)
