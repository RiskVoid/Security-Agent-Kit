# Third-party software, models and data

The kit's own code is Apache-2.0 (see `LICENSE` and `NOTICE`). It pulls, installs and calls a lot of third-party
software. This file lists what, and under which licence or terms.

**Nothing third-party is vendored in this repository.** The only vendored code is RiskVoid's own brand toolkit in
`harness/brand/`. Everything else is pulled as a Docker image, installed when an image is built, or downloaded at
runtime. The repository ships Dockerfiles; release tags also publish built images to GHCR (section 4a).

If you build the images and **redistribute** them (a registry, an appliance, a VM), you redistribute everything
inside them, and their licences apply to you: GPL and AGPL source-offer duties, the WPScan and Nmap licence terms,
and the Semgrep Rules License (which does not allow redistribution at all, which is why the images don't contain
those rules: section 3). Check this before you publish images.

Licences were checked on 2026-11-07 against the pinned versions. "Verified" says where the licence was read:

- **dpkg**: the package's `/usr/share/doc/<package>/copyright` in the built image (the `Files: *` licence)
- **pip**: the installed package's metadata
- **upstream**: the `LICENSE` file of the upstream repository, the image's OCI licence label, or the model card
- **not verified**: we could not confirm it; check it yourself

Versions change: Kali packages follow the rolling repository (see below). Re-check when you bump a pin.

---

## 1. Docker images pulled at runtime

These run unmodified, each as its own container. The kit only passes them configuration (environment variables,
mounted config files).

| Image | Version | Licence | Verified | Notes |
|---|---|---|---|---|
| OpenHands agent-canvas (`ghcr.io/openhands/agent-canvas`) | 1.33.0 | MIT | upstream (OpenHands, OpenHands software-agent-sdk) | The image also contains Node.js, openvscode-server and other components under their own licences |
| LiteLLM (`ghcr.io/berriai/litellm`) | v1.106.2 | MIT, except the `enterprise/` directory | upstream | `enterprise/` has its own commercial licence. The kit doesn't set a LiteLLM enterprise licence key |
| SearXNG (`searxng/searxng`) | 2026.10.23-629368e40 | AGPL-3.0-or-later | upstream (image label) | See [SearXNG and the AGPL](#searxng-and-the-agpl) |
| Valkey (`valkey/valkey`) | 8.0.2-alpine | BSD-3-Clause | upstream | Stores LiteLLM's spend counter |
| Caddy (`caddy`) | 2.11.7-alpine | Apache-2.0 | upstream | Front door for the OpenHands UI |

### SearXNG and the AGPL

SearXNG is licensed AGPL-3.0-or-later. The kit runs the official image **unmodified**, as a separate service
bound to 127.0.0.1. It only mounts a settings file (`searxng/settings.yml`); that is configuration, not a change to
SearXNG's code. The kit talks to it over HTTP and does not link to it, so the AGPL does not extend to the kit.

If you **modify** SearXNG's code and let other people use it over a network, the AGPL requires you to offer them
the source of your modified version. Source of the unmodified version: https://github.com/searxng/searxng

Search queries go to SearXNG's upstream search engines, under those engines' terms.

### Practice lab (`./rvkit lab up`, optional)

Deliberately vulnerable targets on an isolated network. Pulled only when you start the lab.

| Image | Version | Licence | Verified |
|---|---|---|---|
| OWASP Juice Shop (`bkimminich/juice-shop`) | v20.3.0 | MIT | upstream (image label) |
| DVWA (`ghcr.io/digininja/dvwa`) | pinned digest | GPL-3.0 | upstream |
| VAmPI (`erev0s/vampi`) | pinned digest | MIT | upstream |
| DVGA, Damn Vulnerable GraphQL Application (`dolevf/dvga`) | pinned digest | MIT | upstream |
| MariaDB (`mariadb`) | 11.4.12 | GPL-2.0 | upstream (image label) |

The RiskVoid LLM lab (`evals/targets/rv-llm-lab`) is RiskVoid's own code (Apache-2.0), built on `python:3.13-slim`.

---

## 2. Base images for the images the kit builds

| Base image | Used by | Licence |
|---|---|---|
| `kalilinux/kali-rolling` | `kali-mcp` | A Linux distribution: every package keeps its own licence (section 3). Kali's policies (open source policy, EULA): https://www.kali.org/docs/policy/ |
| `python:3.13-slim` | `web-mcp`, `worker-mcp`, `findings-mcp`, `intel-mcp`, lab LLM | Debian packages under their own licences; Python under the PSF License |
| `alpine:3.24.3` | `egress-proxy` | Alpine packages under their own licences |

**The Kali base is rolling.** `apt-get install` takes whatever the Kali repository has on the day you build, so two
builds a week apart can contain different versions. The versions below are from a build on 2026-11-07.

---

## 3. Tools in the Kali image (`kali-mcp`)

### Kali packages (apt)

| Area | Tool (package) | Version | Licence | Verified |
|---|---|---|---|---|
| Recon | nmap | 7.991 | Nmap Public Source License (NPSL) 0.94 | dpkg |
| | naabu | 2.6.1 | MIT | dpkg |
| | dnsx | 1.3.1 | MIT | dpkg |
| | subfinder | 2.17.0 | MIT | dpkg |
| | amass | 5.1.1 | Apache-2.0 | dpkg |
| | katana | 1.8.0 | MIT | dpkg |
| | httpx (httpx-toolkit) | 1.9.0 | MIT | dpkg |
| | whatweb | 0.6.4 | GPL-2.0-or-later | dpkg |
| | gowitness | 3.2.2 | GPL-3.0-or-later | dpkg |
| | chromium (for gowitness) | 156.0.8078.47 | BSD-3-Clause, plus many bundled components under other licences | dpkg |
| | dig (bind9-dnsutils) | 9.20.30 | MPL-2.0 (plus ISC, BSD) | dpkg |
| | whois | 5.6.6 | GPL-2.0-or-later | dpkg |
| | netcat-openbsd | 1.238 | BSD-3-Clause / BSD-2-Clause | dpkg |
| | ping (iputils-ping) | 20250605 | BSD-3-Clause (some files GPL-2.0-or-later) | dpkg |
| Web | nuclei | 3.11.1 | MIT | dpkg |
| | nikto | 2.6.1 | GPL-2.0 | dpkg |
| | ffuf | 2.3.0 | MIT | dpkg |
| | feroxbuster | 2.13.1 | MIT | dpkg |
| | gobuster | 3.8.2 | Apache-2.0 | dpkg |
| | arjun | 2.2.7 | GPL-3.0 | dpkg |
| | crlfuzz | 1.4.1 | MIT | dpkg |
| | wafw00f | 2.4.2 | BSD-3-Clause | dpkg |
| | wpscan | 4.1.0 | **WPScan dual licence** (see below) | dpkg |
| | ZAP (zaproxy) | 2.17.0 | Apache-2.0 | dpkg |
| | dalfox | 3.2.4 | MIT | dpkg |
| | sqlmap | 1.10.10 | GPL-2.0-or-later with sqlmap's clarifications | dpkg |
| | commix | 4.1 | GPL-3.0-or-later | dpkg |
| | testssl (testssl.sh) | 3.2.4 | GPL-2.0 | dpkg |
| | sslscan | 2.1.5 | GPL-3.0-or-later with OpenSSL exception | dpkg |
| | SecLists (wordlists) | 2025.3 | CC BY-SA 3.0 according to the Kali package; the upstream repository says MIT | dpkg, upstream |
| Code / secrets | gitleaks | 8.26.0 | MIT | dpkg |
| | trufflehog | 3.99.2 | **AGPL-3.0** | dpkg |
| Supply chain | trivy | 0.76.0 | Apache-2.0 | dpkg |
| | syft | 1.54.1 | Apache-2.0 | dpkg |
| Sandbox / policy | nftables | 1.1.7 | GPL-2.0 | dpkg |
| | dnsmasq (dnsmasq-base) | 2.93 | GPL-2.0 or GPL-3.0 | dpkg |
| | util-linux | 2.42.4 | GPL-2.0-or-later (parts LGPL) | dpkg |
| | iproute2 | 7.2.0 | GPL-2.0 | dpkg |
| | libcap2-bin | 2.78 | BSD-3-Clause or GPL-2.0 | dpkg |
| General | curl | 8.22.0 | curl licence | dpkg |
| | wget | 1.25.0 | GPL-3.0-or-later | dpkg |
| | jq | 1.8.2 | MIT | dpkg |
| | git | 2.53.0 | GPL-2.0 | dpkg |
| | Python | 3.14.7 | PSF License | not verified (no machine-readable copyright entry; PSF is Python's upstream licence) |
| | OpenJDK (for Joern and ZAP) | 25.0.5 | GPL-2.0 with Classpath exception | dpkg |

Licences with conditions worth knowing:

- **WPScan** is dual-licensed. Its free licence covers penetration testers using it in an assessment and testing your
  own systems. Commercial uses such as offering WPScan as a managed service or SaaS, or distributing it as part of a
  commercial product, need a commercial licence from the WPScan team. WPScan's vulnerability data API also needs
  its own API token and has its own terms.
- **Nmap** uses the Nmap Public Source License, based on GPL-2.0 with extra conditions. Embedding or redistributing
  Nmap in a proprietary product needs a separate licence from the Nmap project.
- **trufflehog** is AGPL-3.0: if you modify it and offer it to others over a network, you must offer the source.

### Python tools (pip, own virtual environments)

| Tool | Version | Licence | Verified |
|---|---|---|---|
| semgrep (engine) | 1.181.1 | LGPL-2.1-or-later | pip |
| bandit | 1.9.4 | Apache-2.0 | pip |
| pip-audit | 2.10.1 | Apache-2.0 | pip |
| mcp (MCP Python SDK) | 1.29.0 | MIT | pip |
| schemathesis | 4.32.4 | MIT | pip |
| clairvoyance | 2.5.5 | MIT | pip |
| garak (NVIDIA) | 0.17.1 | Apache-2.0 | pip |
| PyTorch (CPU, for garak) | 2.14.1 | BSD-3-Clause and other permissive licences (Apache-2.0, MIT, BSL-1.0, ...) | pip |

### Tools from GitHub (pinned commits) and release binaries (pinned, checksum-verified)

| Tool | Version | Licence | Verified |
|---|---|---|---|
| jwt_tool | commit `3bc7407` | GPL-3.0 | upstream (LICENSE in the image) |
| graphql-cop | commit `2b7e086` | MIT | upstream (LICENSE in the image) |
| graphw00f | commit `4901f82` | BSD-3-Clause | upstream (LICENSE in the image) |
| osv-scanner (Google) | 2.7.0 | Apache-2.0 | upstream |
| grype (Anchore) | 0.121.0 | Apache-2.0 | upstream |
| Joern | 4.0.665 | Apache-2.0 | upstream |

The kit adds its own small helpers: `rv-llm`, `rv-joern` (with `taint.sc`) and the `jwt_tool` wrapper. They are
RiskVoid code under Apache-2.0.

### Rule sets

| Content | Source | Licence |
|---|---|---|
| Semgrep community rules (`/opt/semgrep-rules`) | `github.com/semgrep/semgrep-rules` at commit `16b9e6d` (`SEMGREP_RULES_COMMIT`), **downloaded on your machine at first start, not in the image** | **Semgrep Rules License v1.0** (see below) |
| nuclei templates (`/opt/nuclei-templates`) | ProjectDiscovery, release `v10.5.1`, cloned at build time | MIT (LICENSE in the image) |

**Semgrep Rules License v1.0** (https://semgrep.dev/legal/rules-license). This is not an open-source licence. In
plain terms:

- You may use the rules **only for your own internal business purposes**.
- You may **not** redistribute the rules, and you may **not** make them available to others **as a service**. So
  you can't build a hosted scanning product or a competing SaaS on them.
- The same terms cover the registry rule packs semgrep downloads at runtime (`--config p/python` and similar).

The kit doesn't ship the rules, in the repository or in its published images: `kali-mcp` downloads them at first
start into a volume on your machine (`semgrep-rules`). Using the kit for your own security work is internal use.
If you plan to offer the kit (or a service built on it) to others, get a licence from Semgrep first, or set
`SEMGREP_RULES_COMMIT=` (empty) to skip the download.

### Databases downloaded by scanners at runtime

trivy, grype, osv-scanner, pip-audit and nuclei download vulnerability databases or templates on first use (online
engagements only). That data comes from many sources, each under its own terms. Examples: the trivy database
(Aqua Security), the grype database (Anchore), PyPI and OSV advisories.

---

## 4. Other images the kit builds

| Image | Component | Version | Licence | Verified |
|---|---|---|---|---|
| `web-mcp`, `worker-mcp`, `intel-mcp` | mcp (MCP Python SDK) | 1.30.0 | MIT | pip |
| `findings-mcp` (report) | mcp | 1.30.0 | MIT | pip |
| | python-docx | 1.2.0 | MIT | pip |
| | openpyxl | 3.1.5 | MIT | pip |
| | Pillow | 12.3.0 | MIT-CMU | pip |
| | LibreOffice Writer (no GUI, Debian) | 25.2.3 | MPL-2.0 | dpkg |
| `egress-proxy` | tinyproxy (Alpine package) | Alpine 3.24 | GPL-2.0 | upstream |

### Brand fonts (report image)

Downloaded at build time from a pinned commit of `github.com/google/fonts`, SHA-256 checked. All three are under
the **SIL Open Font License 1.1** (verified: the `OFL.txt` next to each font at that commit).

| Font | Copyright |
|---|---|
| Space Grotesk | The Space Grotesk Project Authors |
| Inter Tight | The Inter Project Authors |
| JetBrains Mono | The JetBrains Mono Project Authors |

---

### 4a. Published images

Release tags (`v0.1.0`, ...) publish `ghcr.io/riskvoid/security-agent-kit-egress`, `-harness`, `-report` and `-kali`
for amd64 and arm64 (`.github/workflows/release.yml`). They contain the components in sections 2 to 4, **except
the Semgrep community rules**, which are downloaded on the user's machine. Distributing these images means
distributing GPL and AGPL software (Kali and Alpine packages, tinyproxy, jwt_tool, and others in section 3): the
corresponding source is in the Kali, Debian and Alpine source archives for the versions listed and in the upstream
repositories at the pinned versions and commits.

## 5. RiskVoid brand toolkit (`harness/brand/`, `harness/assets/`)

`harness/brand/` is a vendored copy of RiskVoid's own document toolkit (`rv_brand.py`, `gdocs-notes.md`).
`harness/assets/` holds the RiskVoid logos used in reports. Both belong to RiskVoid. The code is Apache-2.0, like
the rest of the kit.

**Trademarks.** "RiskVoid" and the RiskVoid logo are trademarks of RiskVoid. The Apache License does not grant
trademark rights. You may say that your work is based on the RiskVoid Security Agent Kit. If you publish a fork or
offer reports made with it as your own product, replace the logos and the RiskVoid branding.

---

## 6. Models

The kit doesn't ship model weights. The Colab launcher (`colab/serve.py`) downloads them from Hugging Face at a
pinned revision when you start a session.

| Model | Source | Licence | Verified |
|---|---|---|---|
| Qwen3.8-27B (base weights, by Qwen) | `Qwen/Qwen3.8-27B` | Apache-2.0 | upstream (model card) |
| Mainstream worker build (`RVKIT_MODEL=qwen`): Qwen3.8-27B GGUF | `lmstudio-community/Qwen3.8-27B-GGUF` (Qwen publishes no GGUF of this model; this is a stock llama.cpp conversion of Qwen's weights) | Apache-2.0 | upstream (model card) |
| Default worker build: abliterated (`RVKIT_MODEL=abliterated`) | `huihui-ai/Huihui-Qwen3.8-27B-abliterated-GGUF`, a community build with refusals removed | Apache-2.0 (as stated on its model card) | upstream (model card) |

You are responsible for how you use any model, and especially the abliterated build. See `SECURITY.md`,
"Responsible use".

**Planner and fallback models** (by default via OpenRouter) are not part of the kit. Their use is governed by the
terms of OpenRouter and of each model provider.

### Software the Colab launcher installs in your Colab runtime

| Software | Version | Licence |
|---|---|---|
| llama.cpp (`llama-server`) | latest prebuilt release or source build at session start | MIT |
| cloudflared | 2026.10.3 (SHA-256 checked) | Apache-2.0 |
| huggingface_hub | latest at session start | Apache-2.0 |
| pyngrok (only if you set `NGROK_TOKEN`) | latest at session start | MIT |
| colab-mcp (Claude Code helper, `.mcp.json`) | commit `b9ab389` | Apache-2.0 |

Google Colab, Cloudflare quick tunnels, ngrok, Hugging Face and OpenRouter are services with their own terms of
service. Read them for your plan; Colab restricts some uses of tunnels and proxies.

---

## 7. Data sources (vulnerability intelligence)

`intel-mcp` and the worker call these public services. The kit doesn't redistribute their data; it caches answers
locally for 24 hours.

| Source | What | Terms |
|---|---|---|
| NVD (NIST) | CVE details, CVSS | https://nvd.nist.gov/developers/terms-of-use. Required notice: "This product uses the NVD API but is not endorsed or certified by the NVD." (also in `NOTICE`) |
| FIRST EPSS | exploit prediction scores | https://www.first.org/epss/ (FIRST publishes EPSS data freely and openly). FIRST's Services Terms of Use (https://www.first.org/about/policies/terms) license its content for vulnerability disclosure, incident response and preventative cybersecurity uses; other uses need FIRST's written permission |
| CISA KEV | known exploited vulnerabilities catalog | CC0 1.0 (https://www.cisa.gov/known-exploited-vulnerabilities-catalog). Using the data doesn't allow use of the CISA logo or DHS seal |
| OSV (osv.dev) | package vulnerabilities, GHSA records | https://osv.dev. OSV aggregates many databases; each record keeps the terms of its source (listed at https://github.com/google/osv.dev/blob/master/source.yaml). GitHub Advisory Database records are CC-BY-4.0 |

---

## Not covered here

Anything you add yourself: extra tools in the Kali image, your own models or endpoints, client code, and the
services you test. Check those licences and agreements yourself.
