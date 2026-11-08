# Contributing

Thanks for helping. This file covers how to set up the kit for development, run the tests, and add playbooks and
tools.

- **Security problems:** don't open a public issue. See [SECURITY.md](SECURITY.md).
- **Conduct:** see [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
- **Bigger changes** (a new service, a change to the scope or approval model, a new dependency): open an issue first
  so we can agree on the approach.

## Licence of contributions

The kit is licensed under the Apache License 2.0. Contributions are accepted under the same licence (inbound =
outbound): by opening a pull request you agree that your contribution is licensed under Apache-2.0, as section 5 of
the License says. There is no CLA, and no `Signed-off-by` line is required.

Only contribute code you wrote or have the right to submit. If you add third-party code, a tool or a data source,
say so in the PR and add it to [THIRD_PARTY.md](THIRD_PARTY.md) with its licence.

---

## Development setup

You need what the README lists: macOS or Linux, Docker (Docker Desktop, OrbStack or Docker Engine), about 16 GB RAM,
about 25 GB free disk, and `python3`.

```sh
git clone https://github.com/RiskVoid/Security-Agent-Kit.git
cd Security-Agent-Kit
./rvkit setup
```

`setup` creates `.env` with fresh secrets, builds the images (about 10 minutes the first time), starts the stack and
configures OpenHands. Never commit `.env`.

What you need beyond that depends on what you work on:

| Working on | Also needs |
|---|---|
| Kali tools, scope, sandbox, findings, report | nothing more |
| The planner, prompts, benchmarks | `OPENROUTER_API_KEY` in `.env` (benchmarks cost money, see below) |
| The worker loop | a worker model: Colab, a local server, or any OpenAI-compatible endpoint (`./rvkit worker`) |

**Rebuilding after a change.** The harness code, playbooks, `kali-mcp` code and tools are copied into the images, and
`./rvkit up` doesn't rebuild (it uses the published images for the version in `VERSION` when they exist).
`RVKIT_BUILD=1 ./rvkit up` rebuilds every image from your checkout. After changing them, rebuild the service you touched, then re-apply the OpenHands
configuration:

```sh
docker compose up -d --build kali-mcp      # or web-mcp, worker-mcp, findings-mcp, intel-mcp, egress-proxy
./rvkit up
```

---

## Tests

The test suites are in `evals/`. They talk to the running stack (through `docker compose exec`), so start it first
with `./rvkit up`. Each prints `PASS` / `FAIL` per check and ends with `passed N, failed M`; the exit code is
non-zero if anything failed.

### Test engagements

Most suites use two engagements and the demo app. One command creates them (and is what CI runs):

```sh
bash evals/ci_prepare.sh
# demo-code: the deliberately insecure demo app (copied into PROJECTS_DIR), passive only
# net-test:  example.com and 1.1.1.1, all tiers, max rate 20
```

`net-test` sends a few small requests to `example.com` and `1.1.1.1` (an HTTP GET each, and one nmap probe to port
80 of 1.1.1.1). If that's not acceptable on your network, skip the network part of the policy test.

### Suites

| Suite | What it checks | Needs | Run |
|---|---|---|---|
| `phase3_policy_test.sh` | scope enforcement: sandbox isolation, tiers, scope pre-check false positives, firewall, rate caps, approvals, halt, audit log | `demo-code`, `net-test`, internet (pip-audit check) | `bash evals/phase3_policy_test.sh` |
| `tools_smoke.sh` | every tool in the Kali image starts; supply-chain and code tools work through the sandbox (osv-scanner, trivy, syft, grype, semgrep offline rules, Joern); vulnerability intel ranking | `demo-code`, internet (vulnerability databases, OSV / NVD / KEV) | `bash evals/tools_smoke.sh` |
| `phase5_e2e.sh` | audited tool runs, findings citing hashed evidence, final report, tamper detection, close-out manifest and archive | the demo app in your projects folder; it creates and resets its own engagement `p5-e2e` | `bash evals/phase5_e2e.sh` |
| `console_test.sh` | the console: sign-in, host-header check, CSRF header, read API, report-file limits, preview writes nothing, live view | `demo-code` | `bash evals/console_test.sh` |
| `console_contract_test.py` | the console's contract: sign-in, cross-site and content-type checks, field validation, conflicts (409), audit attribution, the event stream, sandboxed report view, isolation from the containers | the stack; it creates and deletes `rv-console-test` | `python3 evals/console_contract_test.py` |
| `policy_test.sh` | scope and rules enforcement with real DNS and the firewall: exact hosts, wildcards, exclusions, ports, URL limits, time rules; the request tool, bound and stale approvals, controlled execution, offline source analysis, budgets | the stack and internet access; it creates and deletes `rv-pol-test` | `bash evals/policy_test.sh` |
| `model_stub_test.sh` | the deterministic model stub (`evals/mock_llm.py` scenario mode) through LiteLLM: answers by turn, streaming, 429 and 402 classified like provider errors; no GPU or provider | the stack | `bash evals/model_stub_test.sh` |
| `lab_test.sh` | lab isolation: an engagement reaches only its own lab target; lab targets have no internet and can't reach the kit's services; DVWA login works | `./rvkit lab up`, `demo-code`, `net-test`; it creates `lab-juice` and `lab-dvwa` itself | `bash evals/lab_test.sh` |
| `planner_smoke.py` | each planner route answers authorised code-review, web-app and external-network briefs with a usable plan, not a refusal; records latency and tokens | `OPENROUTER_API_KEY` (costs a few cents) | `python3 evals/planner_smoke.py [--brief code\|web\|network] [model ...]` |

Results that the suites write go to `evals/results/`, which is git-ignored: results can contain model output about
your targets.

### Benchmarks

Benchmarks run the real agent unattended on a known target and score its findings (recall, severity-weighted
recall, precision, OpenRouter cost, time). Run one after you change a prompt, a playbook, a tool description or a
model.

```sh
./rvkit bench smoke                        # 2-issue file, about 3 minutes, a few cents: does the whole loop work?
./rvkit bench code-flask                   # also code-node, web-juice-shop, web-dvwa, api-vampi,
                                           # api-graphql-dvga, ai-llm-lab
./rvkit bench smoke --agent riskvoid-local # worker model only
python3 evals/run_benchmark.py --history   # compare runs
```

- Code benchmarks need the planner (OpenRouter key) and a worker model; `--agent riskvoid-local` needs only the
  worker.
- Lab benchmarks (`web-*`, `api-*`, `ai-llm-lab`) need `./rvkit lab up`. Intrusive commands are approved
  automatically only for lab-only scopes.
- Each benchmark has a budget cap (`max_budget_usd` in `evals/benchmarks/<name>.json`). Cost is measured from your
  OpenRouter key's usage, so don't use the key for anything else during a run.
- Definitions are in `evals/benchmarks/`, code targets in `evals/targets/`. If you add a benchmark, keep hints out
  of the target code (no comments that name the vulnerability).

Put the benchmark numbers (before and after) in your PR when you change agent behaviour.

---

## Changing the Colab launcher

`colab/serve.py` is the source. The notebook `colab/rvkit_model_server.ipynb` is generated from it. After editing
`serve.py`:

```sh
python3 colab/build_notebook.py
```

Commit both files. Don't edit the notebook by hand.

---

## Adding a playbook

Playbooks are Markdown files in `harness/playbooks/`. The findings MCP serves them (`list_playbooks`,
`get_playbook`), so the planner can use them with any agent profile.

Format (see `harness/playbooks/secrets-review.md` for a short one):

```markdown
---
title: Secrets review
standard: OWASP ASVS V13.3 (secret management), CWE-798
tiers: passive
---
# Secrets review

## 1. Scan
- [ ] Working tree: `gitleaks dir /src/<repo> --report-format json --report-path gitleaks.json`
...

## Findings
- How to group and write up findings for this kind of test.

## Done when
What must be true before the planner can call this part finished.
```

- The front matter needs `title`, `standard` and `tiers`: `list_playbooks` shows them.
- Phases are numbered `##` sections with `- [ ]` checklist items. The planner copies them into `PLAN.md`.
- Give exact commands, as they run in the Kali sandbox: paths under `/src/<repo>` for code, output files written to
  the current directory (the engagement folder), JSON output where the tool supports it.
- **Check every command and flag against the tool version installed in the image.** Run it through the sandbox on a
  test engagement. Flags change between versions.
- Say which tier each step needs when it isn't passive, and note anything that contacts a third party (for
  example, secret verification calls the provider).
- Finish with a `## Findings` section (conventions) and a `## Done when` section.

Then rebuild `findings-mcp` (the playbooks are copied into its image), add the playbook to the table in the README,
and consider a benchmark that exercises it.

---

## Adding a tool to the Kali image

A tool needs five changes. Missing one of them leaves the agent unaware of it, or lets it run at the wrong tier.

1. **`kali-mcp/Dockerfile`:** install it. Prefer, in this order: a Kali package; a pinned PyPI version in its own
   virtual environment (Kali's Debian Python packages must not be overwritten by pip); a pinned release binary
   checked against the publisher's SHA-256 (amd64 and arm64); a pinned Git commit. Make it readable by the
   engagement users (`chmod -R a+rX`) and link it into `/usr/local/bin` (the sandbox's login shell resets `PATH`).
   Add it to the tool list comment at the top.
2. **`kali-mcp/tiers.yaml`:** put the program name in the right list: `intrusive` (exploitation, brute force,
   fuzzing, anything that changes state or can cause a denial of service), `active` (scanning, crawling,
   fingerprinting, any request to a target) or neither (passive: offline analysis). Programs not listed are
   **passive**, so a network tool you forget here runs without the tier checks. If it can rate-limit, add it under
   `rate_flags` (with `format` if the value isn't a bare number, `after` if the option belongs to a subcommand).
   If its risk depends on a subcommand or flag, add `subcommands` rules. You don't need to touch the policy code;
   `python3 evals/unit_test.py` checks the file (unknown keys, bad regexes, a program in two tiers).
3. **`evals/tools_smoke.sh`:** add a line to the "tools start" list (a version check). If it analyses code or
   dependencies, add a check that runs through the sandbox on `demo-code`.
4. **`kali-mcp/server.py`:** add it to the `run` tool's docstring, under the right area, with a short usage hint.
   This is what the planner reads.
5. **`harness/worker.py`:** add it to the `kali_run` tool description. This is what the worker model reads.

If the tool downloads data on first use (rules, templates, vulnerability databases), add those hosts to
`kali-mcp/infra_domains.txt`, or bake the data into the image for offline engagements. Add the tool and its licence
to [THIRD_PARTY.md](THIRD_PARTY.md); check the licence allows how the kit uses it.

Then rebuild `kali-mcp` and run `tools_smoke.sh` and `phase3_policy_test.sh`.

---

## Version pinning

Pin every image, package, binary and Git dependency to an **exact version** (a tag, a version, a digest or a
commit), and pick releases that are **at least two weeks old** when you pin them. A fresh release hasn't had time to
show regressions or to be pulled after a compromise. Verify downloaded binaries against the publisher's checksum.

- Docker images: an exact tag or a digest, overridable with a `*_TAG` variable in `.env` where the stack already
  does that.
- Python and npm packages: `==` / exact versions, not ranges.
- Bump related pins together, and run the suites that cover them.

Known exception: the Kali base is rolling (its apt packages are whatever the repository has on build day). GitHub
Actions are pinned to a commit SHA, with the release tag in a comment.

---

## CI and releases

- `.github/workflows/ci.yml` runs on every push and pull request and takes about a minute: shellcheck, Python
  compile, compose validation, the notebook-is-generated check, and the unit tests (`python3 evals/unit_test.py`:
  tiers, rate caps, scope and rules parsing, the scope pre-check, findings, the web-fetch guard, the console). It
  builds no images. This is the check a pull request needs.
- `.github/workflows/integration.yml` builds every image and runs the full-stack suites: `evals/ci_prepare.sh`,
  then policy, console, tools, end-to-end and lab (amd64, no model or API key needed). Image layers are cached
  between runs, so a run that changes little takes much less than the first one (15–20 minutes). It runs:
  - on demand: **Actions > Integration > Run workflow**, on any branch;
  - on a pull request with the **`full-ci`** label (add it when a change touches the Kali image, the sandbox,
    `rvkit`, `docker-compose.yml` or the MCP servers; later pushes re-run it while the label is on);
  - nightly on `main`;
  - before every release (the release workflow publishes nothing unless it passes).

  The benchmarks need models and cost money, so they don't run in CI.
- `.github/workflows/release.yml` publishes the images to GHCR for amd64 and arm64 when you push a tag `vX.Y.Z`
  that matches `VERSION`. To release: bump `VERSION` and the `RVKIT_VERSION:-…` defaults in `docker-compose.yml`
  together (CI checks they match), merge, then tag.

---

## Style

- Match the code around you. Keep changes small and focused.
- `rvkit` must run under macOS's bash 3.2: no associative arrays, and careful with `"${@:-}"`.
- Python: standard library where practical. New dependencies need a reason in the PR.
- Docs: plain, direct English, short sentences. Update the README when you change a command or a default.
- Never commit secrets, `.env`, `evals/results/` or client data.

## Pull request checklist

- [ ] The change does one thing, and the PR says why.
- [ ] `bash -n rvkit` and `python3 -m py_compile` on changed Python files pass; `shellcheck` on changed shell
      scripts if you have it.
- [ ] The test suites that cover your change pass (say which ones you ran, and on which platform: macOS / Linux,
      arm64 / amd64).
- [ ] Changes to scope, sandbox, tiers, approvals or egress: `phase3_policy_test.sh` passes, and you've added a
      check for the new behaviour.
- [ ] Changes to prompts, playbooks, tool descriptions or models: benchmark numbers before and after.
- [ ] New tools or dependencies: pinned, checksum-verified where possible, and listed in `THIRD_PARTY.md`.
- [ ] `colab/serve.py` changed: notebook regenerated with `python3 colab/build_notebook.py`.
- [ ] README and `./rvkit help` updated if commands or defaults changed.
- [ ] No secrets, `.env`, results or client data in the diff.
