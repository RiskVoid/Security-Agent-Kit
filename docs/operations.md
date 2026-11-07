# Operating the kit

This page is about running the kit day to day: starting and stopping it, updating it, where your data lives, how to
back it up, and how to reset or remove it.

## A typical day

```sh
./rvkit up          # start the stack (if it isn't running)
/rv-start           # in Claude Code: start the Colab worker (or start it by hand, see models.md)
./rvkit status      # everything green?
./rvkit watch       # in a second terminal while the agent works
…
/rv-stop            # release the Colab GPU when you're done
./rvkit down        # optional: stop the stack
```

The stack restarts by itself after a reboot if Docker starts at login (every service has
`restart: unless-stopped`), except the lab targets. The Colab worker doesn't: start it each session. A local or
`api` worker runs as long as its server runs.

## Starting, stopping, checking

| Command | What it does |
|---|---|
| `./rvkit up` | Pulls the published images for this version, starts everything, re-applies the OpenHands configuration. |
| `./rvkit down` | Stops and removes the containers. Volumes and files are kept. |
| `./rvkit status` | One-screen overview. |
| `./rvkit doctor` | Full check with fixes ([cli-reference.md](cli-reference.md#doctor)). |
| `./rvkit logs [service]` | Recent logs. |
| `docker compose restart <service>` | Restart one service, for example `kali-mcp` after a hang. |

What survives a restart:

| | `./rvkit down` / `up` | Restarting a single service |
|---|---|---|
| Engagements, findings, evidence, reports (host folder) | kept | kept |
| Scope, rules, approvals, audit log (`kali-control` volume) | kept | kept |
| OpenHands conversations and settings (`openhands-data` volume) | kept | kept |
| OpenRouter spend in the current period (`litellm-spend` volume) | kept | kept |
| Worker task results (`get_task`) | lost: the evidence files remain | lost if `worker-mcp` restarts |
| Running Kali commands | killed | killed if `kali-mcp` restarts |

After a restart, a conversation that was in the middle of a tool call may show an error: start a new conversation
for the same engagement ([running-the-agent.md](running-the-agent.md)).

## Ports

Everything listens on `127.0.0.1` only; nothing is reachable from your network.

| Port | Service |
|---|---|
| 8000 | The UI (gateway in front of OpenHands) |
| 4000 | LiteLLM model gateway (needs `./rvkit key litellm`) |
| 8888 | SearXNG search |

If a port is taken, the best fix is to free it. `rvkit` itself expects the UI on 8000 and LiteLLM on 4000: if you
move either one (the left number of its `ports:` line in `docker-compose.yml`), the containers work but `up`,
`status`, `doctor` and the OpenHands configuration step can't reach them. Moving SearXNG's 8888 is safe.

To use the UI from another machine, use an SSH tunnel rather than publishing the port:

```sh
ssh -L 8000:127.0.0.1:8000 you@kit-host
```

## Updating

```sh
git pull
./rvkit up
```

`up` pulls the published images for the version in `VERSION`, starts them, migrates `.env` (new settings get
their defaults) and re-applies the OpenHands configuration, so prompt and tool changes take effect in **new**
conversations. Read the release notes for anything that needs your action.

If you've changed the kit's code yourself, or you're on a commit that has no published images, build them:

```sh
RVKIT_BUILD=1 ./rvkit up
```

The first build takes about 10 minutes, mostly the Kali image.

### OpenHands version

OpenHands is pinned in `docker-compose.yml`, because `rvkit` configures it through its API. Its database in the
`openhands-data` volume is upgraded by newer versions and can't be read by older ones. If OpenHands doesn't start
and `./rvkit logs agent-canvas` says `Can't locate revision`, the volume was used by a newer version: set
`AGENT_CANVAS_TAG` in `.env` to that version and run `./rvkit up`.

## Data and backups

| What | Where | Back up? |
|---|---|---|
| Your settings and secrets | `.env` | Yes, somewhere private. |
| Engagements: scope files, plan, notes, findings, evidence, reports, archives | `ENGAGEMENTS_DIR` (default `~/riskvoid/engagements`) | Yes. This is your work. |
| Client code | `PROJECTS_DIR` (default `~/riskvoid/projects`) | It's the client's; follow your agreement. |
| Authoritative scope, rules, approvals, audit log, engagement registry | Docker volume `kali-control` | Yes, for open engagements. Closed engagements carry their own audit extract. |
| Conversations, OpenHands settings | Docker volume `openhands-data` | If you want the chat history. |
| OpenRouter spend counter | Docker volume `litellm-spend` | No. |
| CVE lookup cache | Docker volume `intel-cache` | No. |
| Semgrep community rules | Docker volume `semgrep-rules` | No, downloaded again on start. |

Docker prefixes volume names with the Compose project name, which is the kit folder's name in lower case (for
example `security-agent-kit_kali-control`). `docker volume ls` shows them. To copy a volume to a file:

```sh
docker run --rm -v security-agent-kit_kali-control:/v:ro -v "$PWD":/b alpine tar czf /b/kali-control.tgz -C /v .
```

`ENGAGEMENTS_DIR/audit.log` is a convenience copy of the audit log for all engagements. The authoritative one is
in `kali-control` and is what reports and `./rvkit close` use.

## Disk space

Images take about 18 GB (about 21 GB with the lab; the Kali image alone is 11 GB); engagements grow with evidence (scanner output, Joern workspaces, screenshots). Closed
engagements are archived as `.tar.gz` in `ENGAGEMENTS_DIR/_archive/`; once you've stored the archive and its
`.sha256` elsewhere, you can delete the engagement folder. `./rvkit doctor` warns when free disk where engagements
live drops below 25 GB. `docker system df` shows what Docker uses.

## Resetting

Start from a clean state while keeping your engagements folder:

| To reset | Do this | You lose |
|---|---|---|
| OpenHands configuration | `./rvkit openhands` | nothing |
| The practice lab | `./rvkit lab down && ./rvkit lab up` | lab state |
| Conversations | `./rvkit down`, `docker volume rm <project>_openhands-data`, `./rvkit up` | all chat history and your own OpenHands settings |
| CVE cache | `./rvkit down`, `docker volume rm <project>_intel-cache`, `./rvkit up` | nothing that matters |

Deleting volumes can't be undone. Don't delete `kali-control` while you have engagements you still work on: it holds
their authoritative scope, approvals, audit log and sandbox user ids.

## Uninstalling

```sh
./rvkit close <engagement>      # for each open engagement you need to keep a record of
./rvkit lab down
docker compose --profile lab down -v --rmi all    # containers, volumes and images of the kit
```

Then delete the kit folder and, once you've kept what you need, your data folder (`~/riskvoid` by default).
`./rvkit install` created a link at `~/.local/bin/rvkit`: remove it too. Stop your Colab runtime if it's running.

## Running on Linux

The kit is tested on macOS (Apple Silicon) with OrbStack; Linux with Docker Engine is expected to work but hasn't
been through the full test suites yet ([SECURITY.md](../SECURITY.md#known-limitations)).

- Install Docker Engine and the Compose v2 plugin, and add your user to the `docker` group.
- `kali-mcp` needs `NET_ADMIN`, `SYS_ADMIN` and AppArmor unconfined to build its sandbox. Hosts with strict
  AppArmor or SELinux policies may need adjustment; `./rvkit doctor` checks that the firewall loaded.
- A local model server must listen on an address containers can reach (`0.0.0.0` or the Docker bridge), not only
  `127.0.0.1`. Ollama: `OLLAMA_HOST=0.0.0.0`.
- Desktop notifications in `./rvkit watch` use `notify-send` when it's installed.

---

See also: [configuration.md](configuration.md), [troubleshooting.md](troubleshooting.md),
[architecture.md](architecture.md).
