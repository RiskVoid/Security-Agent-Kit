# Security policy

The RiskVoid Security Agent Kit runs real attack tools on behalf of an AI agent. Its safety depends on a few
controls: the per-engagement scope firewall, the command sandbox, intensity tiers with human approval, the egress
limits on the agent containers, and keeping secrets away from the planner. A way around any of them is a security
bug, and we want to hear about it.

**Read [Known limitations](#known-limitations) before you use the kit on client work.** Some gaps are known and
not fixed yet.

---

## Known limitations

These are known, documented gaps in this release. They are not bugs to report, unless you find that a control
is weaker than described here.

1. **Tiers are assigned by program name.** The kit decides whether a command is passive, active or intrusive
   from the name of the program it runs (`sqlmap` is intrusive, `nmap` is active, and so on). A program the kit
   doesn't list counts as passive, so a script or an interpreter (`python3 -c ...`, `bash script.sh`) runs at
   the **passive** tier, and `curl`, `wget` or `nc` with a payload at the **active** tier. Either can send
   intrusive traffic to in-scope hosts **without approval**, even on an engagement that allows only passive
   commands. This is the default because classifying arbitrary code isn't reliable. **`Strict tiers: on`** in an
   engagement's `RULES.md` closes the common cases: interpreters running code (`python3`, `perl`, `node`,
   `bash script.sh`, …) and `curl`/`wget` sending data (`-d`, `--data*`, `-F`, `-X POST/PUT/PATCH/DELETE`) count
   as intrusive, so each needs your approval. It is still matching on the command line, not on what the code
   does: a compiled binary the agent writes itself, or an unusual way of invoking a tool, can get past it. The
   network layer still enforces scope: these commands can only reach in-scope hosts. Treat approvals as a guard
   against mistakes, not against a determined agent.
2. **The planner's web fetch tool checks names and addresses, not content.** The `web` MCP server (`web-mcp`)
   refuses every engagement target (the union of all engagements' scope) and every non-public address, on the
   first request and on each redirect, and fails closed when it can't read the scopes. Its requests are not in the
   audit log. Each connection goes to an address that passed the check (the name is not resolved again), so DNS
   rebinding can't redirect it. The worker has no internet of
   its own: its `web_search` and `fetch_url` tools go through this server, with the same checks.
3. **Kit services can reach the internet.** `web-mcp`, `intel-mcp`, `kali-mcp` (for its own updates and rule
   downloads, not agent commands), LiteLLM and SearXNG have outbound access. The two agent-facing containers,
   OpenHands and the worker, are on an internal network without it.
4. **IPv6 targets are not supported.** All IPv6 traffic from engagement commands is dropped, and IPv6 scope
   entries are ignored with a warning.
5. **A domain in scope includes its subdomains.** `acme.com` in `SCOPE.md` also allows `anything.acme.com`. You
   can't yet limit scope to one exact host name.
6. **Secret redaction is pattern-based.** The worker removes secrets from what it sends back to the planner using
   regular expressions (gitleaks-style patterns). It will miss secrets that don't match a pattern. Treat it as a
   safety net, not a guarantee.
7. **OpenHands' local API answers without the session key on 127.0.0.1.** Any process inside the `agent-canvas`
   container, including the agent's own terminal, can call it and change OpenHands settings (LLM profiles, MCP
   servers, agent prompts). It can't change engagement scope, rules or approvals: those live in a separate,
   root-only control volume that only `./rvkit` changes.
8. **The Colab worker endpoint is on the internet.** It is reached through a Cloudflare or ngrok tunnel and is
   protected only by its API key. Keep the key secret, and stop the runtime when you're done.
9. **The model gateway's data rules assume the planner reaches models only through LiteLLM.** `Client data:` and
   halt are enforced at LiteLLM. The agent's terminal runs in the same container as OpenHands and has the LiteLLM
   key OpenHands uses, so a compromised agent could call LiteLLM with a request that names no engagement; such a
   call is allowed by the data rule. It still can't reach a provider other than through LiteLLM's configured
   routes, and every call is in LiteLLM's logs.
10. **Credential values are scrubbed from output, evidence and the audit log, not from reports.** If a value is
   copied into a finding by hand, the report shows it.
11. **Tested platforms.** So far the kit has been verified on macOS (Apple Silicon) with OrbStack. Linux and amd64
   have not been through the full test suites yet.

### How the agent's network access is limited in this release

- **The console** (`./rvkit console`) listens on the host's `127.0.0.1` and needs a session token that no
  container has. Docker Desktop and OrbStack let containers on non-internal networks open that port through
  `host.docker.internal`; without the token they get `401`. The agent's own container has no route to it and the
  sandbox firewall blocks the host's addresses.
- **Approvals are bound to the action.** An approval covers one exact command (with the SHA-256 of the programs it
  runs and the files it reads) or one exact request (method, URL, headers, body), under one scope and rules
  revision, once. Changing any of these, or the scope, needs a new approval. The worker's task tier is enforced by
  kali-mcp, not only stated in the prompt.
- **Scope lines that can't be enforced are refused**, not ignored, and what the kit can't enforce for a given
  scope (for example URL paths for arbitrary commands, or two virtual hosts on one address) is listed when the
  scope is applied. URL path limits are enforced only by the request tool, so raw commands can't reach those
  hosts at all.
- **Kali tools.** Every command runs as an unprivileged user for that engagement, in a sandbox that sees only its
  own engagement folder and in-scope code (read-only). An nftables firewall lets that user reach only in-scope IPs
  and domains, plus package and vulnerability-database sites for online engagements. Link-local and cloud metadata
  addresses and the kit's own services are always blocked. Of loopback, only 127.0.0.1 on unprivileged ports other
  than kali-mcp's own (8090) is open, so a tool can drive a helper it started (gowitness and its Chromium).
- **The OpenHands agent container** has no direct internet access. Its traffic goes through an allowlisting egress
  proxy (package registries and vulnerability databases, `egress/allowlist.txt` plus `EGRESS_EXTRA_DOMAINS`) and
  can reach only the kit's model gateway and MCP servers directly. Its terminal and browser can't reach engagement
  targets; tool traffic to targets goes through the kali tool. Web research goes through the `web` MCP server
  (item 2).
- **Engagement files** are read-only in the OpenHands container. The planner writes its plan, notes and report
  text through the findings server's `write_file` tool (a fixed list of paths); evidence is written only by kali
  commands, which hash it in the audit log.
- **Approvals.** Intrusive commands wait for a human: `./rvkit approve <eng> <id>`. An approval is single-use,
  bound to the exact command, and expires after 24 hours. `./rvkit halt <eng>` stops everything for an engagement:
  commands, worker tasks, bound conversations and their model calls.
- **Where client data goes.** `Client data:` in `RULES.md` limits which model destinations (local, Colab, an API,
  OpenRouter, Anthropic, OpenAI) may receive calls about an engagement; the model gateway refuses the others and
  drops fallbacks that aren't allowed. Content the agent reads can't change which engagement a call is about.
- **Credentials by reference.** The agent uses stored credentials as `$RV_CRED_<NAME>` or `{{cred:NAME}}` without
  seeing them; values are kept in the control volume and replaced by the reference in output and evidence.

---

## Reporting a vulnerability

**Please don't open a public issue for a security problem.**

Report it privately through GitHub: go to the repository's **Security** tab and choose **Report a vulnerability**
(https://github.com/RiskVoid/Security-Agent-Kit/security/advisories/new).

Please include:

- what the problem is and which control it gets around
- the steps to reproduce it: the engagement's `SCOPE.md` and `RULES.md`, the commands or prompts, and what happened
- the kit version (commit hash), your OS, Docker runtime (Docker Desktop, OrbStack, Docker Engine) and architecture
- the relevant lines of `./rvkit audit <eng>` and container logs, with your own secrets removed

Only test against systems you own or are allowed to test. The practice lab (`./rvkit lab up`) is a good place to
reproduce scope and approval issues.

The maintainers will reply in the advisory, keep you updated there, and agree a disclosure date with you. We credit
reporters in the advisory unless you ask us not to.

## Scope

In scope:

- **Scope-enforcement bypass:** a Kali command reaching a host or port that isn't in the engagement's active
  scope, getting a name resolved that isn't in scope, or reaching the kit's own services.
- **Sandbox escape:** a command escaping the per-command sandbox: seeing another engagement's folder or code that
  isn't in scope, writing to client code, gaining privileges, or reaching the root-only control volume. The
  `kali-mcp` container itself has `SYS_ADMIN` and `NET_ADMIN` and runs without AppArmor so it can build the
  sandbox, so an escape to its root is serious.
- **Approval and policy bypass:** running an intrusive-tier program without approval, reusing or redirecting an
  approval, an agent approving its own command, changing `SCOPE.md` / `RULES.md` / approvals without `./rvkit`,
  getting around a halt, a testing window or a rate cap.
- **Egress bypass:** the OpenHands agent container reaching a host that isn't on the egress allowlist, or the
  worker's `fetch_url` reaching an in-scope or non-public address.
- **Secrets leaking to the planner or to other services:** the OpenRouter key or other `.env` secrets reaching the
  agent, the worker or the Kali sandbox; a structural path where raw tool output or client code reaches the planner
  without going through the worker's redaction; a worker fallback that sends data while it is turned off, or for an
  engagement marked `Worker model: private`.
- **Audit and evidence integrity:** changing or forging audit-log entries or evidence hashes so that the report
  shows tampered evidence as verified.
- **Exposure:** a kit service listening beyond 127.0.0.1, or the Colab endpoint answering without its API key.
- **Injection in the kit's own code:** `rvkit`, the MCP servers, the report generator, the Colab launcher.

Out of scope:

- The [known limitations](#known-limitations) above, as described.
- Vulnerabilities in third-party tools and images (OpenHands, LiteLLM, SearXNG, the Kali packages and so on):
  report those upstream. Tell us too if the kit's configuration makes them exploitable.
- The practice lab targets. They are vulnerable on purpose.
- A model refusing, hallucinating or being jailbroken, unless that lets it get around one of the controls above.
- Attacks that need control of the host, Docker, or your `.env` file.

## Supported versions

| Version | Supported |
|---|---|
| `main` | Yes |
| Anything else | No |

There are no releases yet. Fixes go to `main`; update with `git pull` and `./rvkit up`, and rebuild the images
when a fix touches them.

---

## Responsible use

- Use the kit **only on systems you own, or that you have written permission to test.** Keep the authorisation
  (scope, dates, contacts) with the engagement. Unauthorised testing is illegal in most countries.
- Put exactly the authorised targets in `SCOPE.md` and the agreed limits in `RULES.md`. The kit enforces what you
  write there, not what the client agreed to.
- **You are responsible for the agent's actions.** Review intrusive commands before you approve them, watch running
  engagements, and use `./rvkit halt` if anything looks wrong.
- **You are responsible for how you use any model** with the kit. This applies especially to the default
  abliterated (refusal-removed) worker model: it will not refuse harmful requests, so the safeguards are yours.
- Check where client data goes (see "Where your data goes" in the README) against your client agreements before
  you start.

The kit is provided "as is", without warranty, under the Apache License 2.0 (see `LICENSE`).
