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
    ├── .rv/findings.db           findings database (SQLite); read-only to kali commands
    ├── *.json, *.txt, evidence/  tool output written by kali commands (hashed in the audit log)
    ├── evidence/tasks/<task_id>/ worker tasks: step-NN-<tool>.txt per tool call, transcript.jsonl
    ├── out-<timestamp>.txt       full output of a command whose output was too long to return (>30,000 chars)
    ├── .home/.cache/             tool caches (not evidence); each command gets a fresh, empty home folder
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
- **The findings server** writes `.rv/findings.db` and the report files. Kali commands see `.rv/` read-only, so
  agent code can't edit findings, approvals or exceptions behind the findings server's checks. Earlier versions
  kept the database at the top of the folder; it moves into `.rv/` the first time the engagement is used.

See [findings-and-reports.md](findings-and-reports.md) for findings, evidence and the report.

---

## SCOPE.md

One entry per line. A leading `- ` or `* ` bullet is ignored, and so is anything after `#`.

```markdown
# Authorised scope (2026-11-07)
- app.acme.com                       # that host only
- *.acme.io                          # the subdomains of acme.io (not acme.io itself)
- api.acme.com:443,8443              # that host, those ports only
- 203.0.113.0/28
- 198.51.100.7:22,80
- https://portal.acme.com:8443       # portal.acme.com on port 8443
- https://shop.acme.com/api/         # only URLs under /api/ on that host (request tool only)
- !admin.acme.io                     # excluded, with its subdomains
- !203.0.113.9
- !https://app.acme.com/admin        # that path excluded on app.acme.com
- /src/acme-webshop
```

| Entry | Meaning |
|---|---|
| `app.acme.com` | That host only, every port. Its subdomains are **not** in scope: list them, or use a wildcard. |
| `*.acme.io` | The subdomains of `acme.io`, at any depth. `acme.io` itself only if you list it too. |
| `host:443,8443`, `host:8000-8100` | Only those ports (TCP and UDP). Works for host names, wildcards, addresses and CIDRs. |
| `203.0.113.0/28`, `198.51.100.7` | IPv4 networks and addresses. A host address inside a CIDR is fine (`10.0.0.5/24` becomes `10.0.0.0/24`). |
| `https://host` or `https://host:8443` | The host on the URL's port (443 for https, 80 for http when none is given). |
| `https://host/path/` | Only URLs under that path, on that host and port. A path can't be enforced for arbitrary commands, so such a host is reachable **only through the request tool** (`http_request`), never through `run`. |
| `!entry` | Excluded, whatever else the scope says: a name (with its subdomains), `*.name` (the subdomains only), an address or CIDR, or a URL path. An excluded URL path makes its host request-tool only, like a path limit. |
| `/src/<repo>` | Client code the tools may read (read-only). Code not listed here is invisible to engagement commands. |

**Lines the kit can't enforce or doesn't understand stop the scope from being applied**, with the reason for each
line, instead of being ignored:

- IPv6 addresses and networks. Engagement commands have no IPv6 route and DNS answers carry no IPv6 addresses.
- Loopback, link-local (including cloud metadata `169.254.169.254`), `0.0.0.0/8` and multicast. These are never
  reachable as targets. (The firewall itself lets a command reach 127.0.0.1 on unprivileged ports, except
  kali-mcp's 8090, so tools such as gowitness can talk to the browser they start.)
- Paths outside `/src`, invalid ports, credentials or a query in a URL entry.
- `acme.io` and `*.acme.io` with different ports: both get their addresses from the same DNS rule, so the firewall
  can't keep their ports apart. Give them the same ports.
- Anything that isn't an address, a CIDR, a dotted host name or one of the forms above (for example a single-label
  name like `intranet`).

Host names are resolved through a per-engagement DNS server that answers only for in-scope names (and, for online
engagements, the infrastructure domains). Their addresses become reachable, on the listed ports, once resolved.

**What the kit doesn't enforce** is listed every time you preview or apply a scope (and by `./rvkit policy <eng>`),
for example: an excluded name that shares an IP address with an in-scope host can still be reached there by a tool
that sets the `Host` header itself (exclude the address too if that matters), and stop conditions are instructions,
not something the kit detects.

**Changed in this version:** a plain host name used to cover its subdomains and every port, a URL's port and path
were ignored, and unrecognised lines were skipped with a warning. Check older scopes with `./rvkit policy <eng>`
and add `*.` entries where you meant subdomains.

---

## RULES.md

```markdown
# Rules of engagement for acme-2026-11. Change here, then run: ./rvkit scope acme-2026-11
- Allowed tiers: passive, active
- Max rate: 100
- Network: online
- Timezone: Europe/Berlin
- Window: 08:00-18:00
- Dates: 2026-11-10 to 2026-11-21
- Days: mon-fri
- Max requests: 5000
- Max commands: 500
- Stop condition: the site returns errors or slows down
# - Execution: controlled
# - Strict tiers: on
# - Worker model: private
# - Client data: local, colab
```

| Rule | Values | Default (rule missing) |
|---|---|---|
| `Allowed tiers:` | any of `passive`, `active`, `intrusive`, comma-separated | `passive, active` |
| `Max rate:` | requests or packets per second, 1 to 100000 | `100` |
| `Network:` | `online` or `offline` | `online` |
| `Timezone:` | an IANA name such as `Europe/Berlin`, or `UTC`. `Window`, `Dates` and `Days` use it | `UTC` |
| `Window:` | `HH:MM-HH:MM`; an overnight window such as `22:00-06:00` works. `Window (UTC):` from older files still works | any time |
| `Dates:` | `YYYY-MM-DD to YYYY-MM-DD`, both days included | no date limit |
| `Days:` | `mon-fri`, `mon,wed,fri`, ... | every day |
| `Max requests:` | requests through the request tool, for the whole engagement (redirects count) | no budget |
| `Max commands:` | commands through `run` and source analysis, for the whole engagement | no budget |
| `Max parallel:` | network commands running at once (1 to 16); each gets `Max rate` divided by this | `2` |
| `Redirects:` | `in-scope` (the request tool follows redirects that stay in scope) or `none` | `in-scope` |
| `Execution:` | `standard` or `controlled` ([below](#controlled-execution)) | `standard` |
| `Approval expiry:` | `1h` to `168h` | `24h` |
| `Strict tiers:` | `on` or `off` | `off` |
| `Worker model:` | `private` or `auto` | `auto` |
| `Browser support:` | domain names the browser tool may load page assets from (fonts, CDNs) although they aren't in scope; GET page assets only ([authenticated-testing.md](authenticated-testing.md#the-browser)) | none |
| `Client data:` | `any`, or where model calls about this engagement may go: any of `local`, `colab`, `api`, `openrouter`, `anthropic`, `openai` ([below](#where-client-data-may-go)) | `any` |
| `Stop condition:` | free text, one per line: shown to the agent with the rules, kept in each policy revision | none |
| `Note:` | free text kept with the rules | none |

Lines starting with `#` are comments, so remove the `#` to turn on a rule. Rule names are matched without regard to
case. **An unknown rule, a line that isn't `Key: value` or an invalid value stops the rules from being applied**
(free text goes after `Note:` or `Stop condition:`).

**Worker model: private** means the worker's tool work for this engagement always uses the `private-llm` model: the
worker endpoint only, never the OpenRouter fallback, even when you have turned the fallback on. See
[models.md](models.md).

### Where client data may go

`Client data:` limits where model calls about this engagement are sent. The model gateway (LiteLLM) knows where
each model route goes: `local` (a model on your machine or network), `colab` (the Colab tunnel), `api` (another
remote endpoint), or a provider (`openrouter`, `anthropic`, `openai`). A call is tied to the engagement when it
comes from a conversation bound to it ([below](#conversations)), from one of its worker tasks, or when its tool
calls or your messages name the engagement or its `/work/<eng>` or in-scope `/src` paths. Tool results don't
count, so a page or file the agent reads can't tie a call to an engagement or untie it.

- A call whose model goes somewhere the rule doesn't allow is refused with `[RiskVoid] refused by policy:
  engagement acme allows its client data only to local, colab; ...`. It shows in the **Model log**.
- A call that is allowed, but whose fallback model isn't, runs without the fallback.
- The console's Overview shows where each model route goes now and flags the ones the rule doesn't allow.
- With `Client data: local, colab`, start conversations with **New conversation** (or `./rvkit conversation <eng>
  new`): it picks `riskvoid-local` when the planner's route isn't allowed.

The rule only adds restrictions: nothing the agent reads or writes can loosen it.

---

## Changing scope and rules

Edit `SCOPE.md` or `RULES.md` in the engagement folder, then:

```sh
./rvkit scope acme-2026-11          # the diff, what the policy allows and excludes, what it doesn't enforce
./rvkit scope acme-2026-11 --yes    # applies it
./rvkit policy acme-2026-11         # the active policy and its revision history
```

**Editing the files alone has no effect.** The active scope and rules are a copy kept in the Kali container's
root-only control volume (`kali-control`), together with approvals, halt flags and the audit log. Only `./rvkit`
(or the console) updates that copy, so the agent can't widen its own scope. Inside the sandbox, `SCOPE.md` and
`RULES.md` show the active copy, read-only.

Every applied change becomes a numbered **policy revision**, kept with the texts, the effective policy, who
applied it and when (`./rvkit policy <eng> --json`), and is recorded in the audit log (`scope-sync`). Approvals
that were pending or approved but not yet used under the previous revision become **stale** and can't be used.

`./rvkit show <eng>` prints what is active now, as JSON: scope, effective policy, rules, budget use, halt state
and the infrastructure domains.

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

When a command runs one of these tools, the kit adds its share of the engagement's max rate: `Max rate` divided
by `Max parallel` (default 2), so network commands running at the same time stay within `Max rate` together:

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

Three layers:

1. **Pre-check (readable refusals).** Before a network tool runs, the kit looks for host names and IP addresses in
   its command line. Any that aren't in scope, are excluded, or may only be reached through the request tool give
   `REFUSED: targets not in scope for <eng>: [...]`. This catches mistakes early with a clear message; it only
   looks at network tools.
2. **Firewall and resolver (the boundary for commands).** Each command runs as the engagement's own unprivileged
   user, in a sandbox that shows only its engagement folder and in-scope code (read-only). An nftables policy for
   that user allows only in-scope addresses on their listed ports, addresses of in-scope names as the
   engagement's resolver answers them, and, when online, the infrastructure sites. Excluded addresses are dropped
   first; excluded names and request-tool-only hosts don't resolve. Everything else is dropped, including the
   kit's own services, the Docker host, other engagements' targets, loopback, link-local and IPv6.
3. **The request tool (URL-level limits).** `http_request` is sent by kali-mcp itself. It checks the scheme,
   host, port, path and exclusions of every URL (and of every redirect), resolves the name, checks the address,
   and connects to exactly the address it checked.

So a script that builds a URL the pre-check can't see is still blocked by the firewall if the host is out of scope.
The firewall works on addresses and ports: it can't tell two virtual hosts on one address apart, and it can't see
URL paths. That is why path limits are request-tool only.

The practice lab network (`10.250.0.0/24`) is treated like any other target: reachable only from engagements that
have a lab address in scope.

---

## Request tool and source analysis

Besides `run` (a shell command), the agent has two typed actions whose effect the kit understands:

- **`http_request`**: one HTTP request (method, URL, headers, body). GET, HEAD and OPTIONS are tier active; POST,
  PUT, PATCH and DELETE can change state and are intrusive, so they need an approval. Redirects are followed only
  while they stay in scope (and only for GET and HEAD; `Redirects: none` turns this off). Each request counts
  against `Max requests` and is spaced to `Max rate`. The request and the full response are saved as verified
  evidence in `evidence/http/`; the audit log records them with `Authorization`, `Cookie` and API-key headers
  redacted. TLS certificates aren't verified (test systems often use their own CA); the certificate's SHA-256 is
  recorded instead.
- **`analyze_source`**: semgrep (offline rules), gitleaks (secrets redacted), trufflehog (no verification) or
  bandit on in-scope code, run in the sandbox **with no network at all**. The JSON report is saved in
  `evidence/source/`.

The worker uses both, and kali-mcp enforces the tier of the worker's task: a passive task can't send a GET request
or run an active command, whatever the model asks for.

## Controlled execution

`Execution: controlled` in `RULES.md` narrows `run`:

- **Passive commands get no network at all**, unless they run a DNS or registry lookup tool (`dig`, `host`,
  `nslookup`, `whois`, `dnsx`, `subfinder` and similar; the list is `PASSIVE_NET` in `kali-mcp/core.py`). Code
  review, parsing and other offline work can't reach targets or the internet.
- **Scripts and interpreters count as intrusive** (as with `Strict tiers: on`): each one needs an approval, and
  the approval is bound to the script's contents.

## Budgets and parallel commands

`Max requests` and `Max commands` are budgets for the whole engagement, counted across the planner, every worker
task and the console; once one is used up, further requests or commands are refused with a clear message. Use is
shown by `./rvkit show <eng>` (`usage`). `Max parallel` limits how many network commands run at once; each of them
gets an equal share of `Max rate`, so together they stay within it.

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

- An approval is bound to **that exact action**: for a command, its text, the programs it runs (by their SHA-256)
  and the files it reads from the engagement folder or `/src` (a script, a wordlist, a request file); for a
  request, the method, URL, headers and body. Changing any of them needs a new approval, and the refusal says
  what differs.
- It is bound to the **scope and rules revision** it was requested under. Applying a changed scope or rules makes
  every pending or unused approval stale. Approving a request made under an older revision is refused.
- It can be used **once**, even when two calls race for it. Running the same command again needs a new approval.
- It **expires** 24 hours after you decide it (`Approval expiry:` in `RULES.md` changes this).
- Asking again for the same action while it's still pending returns the same approval id.
- Every request, approval (with who approved it), denial, use and stale approval is in the audit log.

The engagement's rate limit is applied to approved commands too.

A worker task that hits an approval pauses (`awaiting_approval`, with the approval id) without holding the worker
model. Once you approve, it runs the approved action by itself, exactly once; a denied or stale approval is
reported to the model instead. You don't need to tell the agent anything.

---

## Credentials

Give the agent a password, token or API key without putting it in a chat or a file it can read:

```sh
./rvkit cred acme-2026-11 set APP_PASS      # asks for the value (hidden); it is never printed
./rvkit cred acme-2026-11 set API_KEY --expires 2026-11-30   # refused after that day
./rvkit cred acme-2026-11 list              # names and when they were set, no values
./rvkit cred acme-2026-11 rm APP_PASS
```

The console's Overview has the same in its **Credentials** card. Values are stored in the engagement's control
folder, encrypted with the vault key (`/control/eng/<eng>/credentials.vault.json` and `/control/vault.key`, root
only, mode 0600), never in the engagement folder. `./rvkit vault rotate` replaces the key and re-encrypts every
credential and identity session. An expired credential is refused rather than sent.

The agent sees only the names (kali tool `list_credentials`) and uses a credential by reference:

- in a command: `$RV_CRED_APP_PASS`. The sandbox gets the variable only when the command has network and names
  it in the command itself (not only in a script the command runs). Agent code in that command can read the value,
  so use credentials of test accounts, not real users' passwords.
- in the request tool: `{{cred:APP_PASS}}` in the URL, a header or the body. The approval covers the reference,
  not the value, and the value is not sent on to another host after a redirect.

Wherever a value would show up (command output, evidence files, saved requests and responses, the audit log), it
is replaced by its reference. The audit log records which credentials a command used. Report exports aren't
scrubbed: don't paste a value into a finding by hand.

For logged-in testing, define **identities** (test accounts built on these credentials), import request
**captures** and let the agent propose **authorization matrices**: see
[authenticated-testing.md](authenticated-testing.md).

---

## Conversations

An OpenHands conversation can be **bound** to one engagement. Every model call it makes then follows that
engagement at the model gateway: its `Client data:` rule, and its halt. That holds if you switch the
conversation's model or agent profile later.

```sh
./rvkit conversation acme-2026-11 new "Review /src/acme for injection flaws"   # create, bind, send a first message
./rvkit conversation acme-2026-11 list                                        # bound conversations and their status
./rvkit conversation acme-2026-11 bind <conversation-id>                      # bind one you started in the UI
./rvkit conversation acme-2026-11 unbind <conversation-id>
```

The console's Overview does the same in its **Conversations** card (New conversation, Unbind, and a link that opens
each in OpenHands). A conversation belongs to at most one engagement. Conversations you start in the OpenHands UI
without binding them still follow an engagement whenever their tool calls name it.

---

## Worker tasks

A task handed to the worker model is durable: its state, each step and the conversation so far are saved in
`evidence/tasks/<task_id>/`. Each action is recorded as started before it runs and as done after, so after a
restart the worker knows exactly what may have happened.

| Status | Meaning |
|---|---|
| `queued`, `waiting` | not started yet; `waiting` means it waits for the tasks in its `depends_on` |
| `running` | working |
| `awaiting_approval` | paused until you decide its approval; continues by itself afterwards |
| `done`, `error` | finished |
| `blocked` | a task it depends on failed |
| `cancelled` | stopped by you or the planner; its running command was killed |
| `halted` | the engagement was halted |
| `interrupted` | the worker restarted while it was running |

After a worker restart, queued tasks start again, tasks waiting for an approval keep waiting, and running tasks
become `interrupted` with a recovery decision:

- **resumable**: no action was in flight; resuming continues where it stopped.
- **needs review**: an action that can change state (an intrusive command, a POST request) was in flight. It is
  never repeated automatically: check the target, then resume; the model is told the result is unknown.

```sh
./rvkit task cancel <task-id>     # stop a task and kill its running command
./rvkit task resume <task-id>     # continue an interrupted task from its last checkpoint
```

The console's **Worker tasks** tab has Cancel and Resume from checkpoint buttons. Resuming checks the engagement's
current policy first.

---

## Halt and resume

```sh
./rvkit halt acme-2026-11      # kill every running command for this engagement and refuse new ones
./rvkit resume acme-2026-11    # allow commands again
```

Halting kills all processes of the engagement's user at once and refuses new Kali commands and worker tasks with
`engagement is halted`. It also stops the engagement's worker tasks (status `halted`), pauses its bound
conversations, and the model gateway refuses their model calls and those of its worker tasks. Use it whenever
something looks wrong. It doesn't affect other engagements.

## Testing window

With `Window`, `Dates` or `Days` in `RULES.md`, commands and requests outside them are refused with the reason, for
example `outside the testing window 08:00-18:00 (Europe/Berlin)` or `testing ended on 2026-11-21 (Europe/Berlin)`.
Commands already running aren't stopped at the end of the window; use `halt` for that. Offline source analysis is
not testing a target and still runs.

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
