# Base is Kali rolling: apt packages track the rolling repo, so two builds a week apart can differ. Tools that
# matter for results (API tools, osv-scanner, grype, Joern) are pinned below; record the build date with results.
FROM kalilinux/kali-rolling
ARG TARGETARCH
ENV DEBIAN_FRONTEND=noninteractive
# Tooling by area. Add or remove packages to suit your engagements.
#   recon:          nmap naabu dnsx subfinder amass katana httpx-toolkit whatweb gowitness(+chromium)
#   web:            nuclei nikto ffuf feroxbuster gobuster arjun crlfuzz wafw00f wpscan zaproxy dalfox sqlmap
#                   commix testssl.sh sslscan
#   API:            schemathesis (OpenAPI/GraphQL fuzzing), jwt_tool, graphw00f, graphql-cop, clairvoyance
#   AI / LLM / MCP: rv-llm (probe library, MCP audit, injection payloads), garak (LLM vulnerability scanner)
#   code/secrets:   semgrep bandit gitleaks trufflehog joern (rv-joern)
#   supply chain:   pip-audit trivy syft grype osv-scanner
#   sandbox/policy: nftables dnsmasq-base util-linux iproute2 libcap2-bin
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-pip python3-venv git curl wget jq ca-certificates unzip \
      nmap dnsutils whois netcat-openbsd iputils-ping \
      naabu dnsx subfinder amass katana httpx-toolkit whatweb gowitness chromium \
      nuclei nikto ffuf arjun zaproxy dalfox sqlmap testssl.sh sslscan \
      feroxbuster gobuster wafw00f wpscan crlfuzz commix \
      gitleaks trufflehog seclists \
      trivy syft \
      nftables dnsmasq-base util-linux iproute2 libcap2-bin \
    && rm -rf /var/lib/apt/lists/*
# Python tools in their own venv (Kali's Debian-packaged Python libs must not be overwritten by pip)
# (linked into /usr/local/bin: the sandbox's login shell resets PATH)
RUN python3 -m venv /opt/venv && /opt/venv/bin/pip install --no-cache-dir "mcp==1.29.0" semgrep bandit pip-audit \
    && for t in semgrep pysemgrep bandit pip-audit; do ln -sf /opt/venv/bin/$t /usr/local/bin/$t; done

# API testing tools in their own venv. GitHub-only tools are pinned to a commit.
ARG SCHEMATHESIS_VERSION=4.32.4
ARG CLAIRVOYANCE_VERSION=2.5.5
ARG JWT_TOOL_COMMIT=3bc7407cf2222d6a821dcc19c776e5a1b1cb9a9b
ARG GRAPHQL_COP_COMMIT=2b7e086efae672f28b419c7fcdfe6b48d846c9dc
ARG GRAPHW00F_COMMIT=4901f824140a2da168876412593c213afbdd75fb
RUN set -eu; python3 -m venv /opt/apitools; \
    /opt/apitools/bin/pip install --no-cache-dir "schemathesis==${SCHEMATHESIS_VERSION}" \
      "clairvoyance==${CLAIRVOYANCE_VERSION}" termcolor cprint pycryptodomex requests ratelimit simplejson PySocks; \
    for r in "ticarpi/jwt_tool ${JWT_TOOL_COMMIT}" "dolevf/graphql-cop ${GRAPHQL_COP_COMMIT}" "dolevf/graphw00f ${GRAPHW00F_COMMIT}"; do \
      set -- $r; d=/opt/${1#*/}; git init -q "$d"; git -C "$d" fetch -q --depth 1 "https://github.com/$1" "$2"; \
      git -C "$d" checkout -q FETCH_HEAD; rm -rf "$d/.git"; done; \
    printf '#!/bin/sh\nexec /opt/apitools/bin/python3 /opt/jwt_tool/jwt_tool_wrap.py "$@"\n' > /usr/local/bin/jwt_tool; \
    printf '#!/bin/sh\nexec /opt/apitools/bin/python3 /opt/graphql-cop/graphql-cop.py "$@"\n' > /usr/local/bin/graphql-cop; \
    printf '#!/bin/sh\ncd /opt/graphw00f && exec /opt/apitools/bin/python3 main.py "$@"\n' > /usr/local/bin/graphw00f; \
    chmod 755 /usr/local/bin/jwt_tool /usr/local/bin/graphql-cop /usr/local/bin/graphw00f; \
    for t in schemathesis st clairvoyance; do ln -sf /opt/apitools/bin/$t /usr/local/bin/$t; done; \
    chmod -R a+rX /opt/apitools /opt/jwt_tool /opt/graphql-cop /opt/graphw00f

# garak (NVIDIA, Apache-2.0): LLM vulnerability scanner. CPU-only torch; Hugging Face downloads are off in the
# sandbox, so use probes whose detectors are string/regex based (see the ai-llm playbook).
ARG GARAK_VERSION=0.17.1
ARG TORCH_VERSION=2.14.1
RUN python3 -m venv /opt/garak && /opt/garak/bin/pip install --no-cache-dir \
      --index-url https://download.pytorch.org/whl/cpu "torch==${TORCH_VERSION}" \
    && /opt/garak/bin/pip install --no-cache-dir "garak==${GARAK_VERSION}" \
    && printf '#!/bin/sh\nexport HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 HF_DATASETS_OFFLINE=1\nexec /opt/garak/bin/python3 -m garak "$@"\n' \
       > /usr/local/bin/garak && chmod 755 /usr/local/bin/garak && chmod -R a+rX /opt/garak

# Pinned release binaries, verified against the publisher's SHA-256 checksums.
ARG OSV_VERSION=2.7.0
ARG OSV_SHA_amd64=160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b
ARG OSV_SHA_arm64=4061ef4c021ed3c47f203b818f337e351336cc5cd67c0274fc36bd1dfc728dd7
ARG GRYPE_VERSION=0.121.0
ARG GRYPE_SHA_amd64=64e07133d3486115de647a66581461dccf5c732748a0a3119077395565f15519
ARG GRYPE_SHA_arm64=86f570f75ca947ea3dd6486309232bcff6d78e44ba081ae75ab14eab72be3dae
RUN set -eu; arch="${TARGETARCH:-$(dpkg --print-architecture)}"; \
    eval osv_sha=\$OSV_SHA_$arch; eval grype_sha=\$GRYPE_SHA_$arch; cd /tmp; \
    curl -fsSLo osv-scanner "https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_linux_${arch}"; \
    echo "$osv_sha  osv-scanner" | sha256sum -c -; install -m 755 osv-scanner /usr/local/bin/osv-scanner; \
    curl -fsSLo grype.tgz "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_${arch}.tar.gz"; \
    echo "$grype_sha  grype.tgz" | sha256sum -c -; tar xzf grype.tgz grype; install -m 755 grype /usr/local/bin/grype; \
    rm -f osv-scanner grype grype.tgz

# Joern (Apache-2.0): code property graph / data-flow analysis. Pinned, checksum-verified; uses the system JDK.
ARG JOERN_VERSION=4.0.665
ARG JOERN_SHA_amd64=283530a4db8619ca79672403161b4a99713cf9f560f2f7dd9a62b292f59d0bd08e04b0054cc8f401640ef9d60f64563af1fcd18da534f4323041340e9f7af6d4
ARG JOERN_SHA_arm64=d746623928c2d2f362535903daf4ca26dabfbe7670b19a692377828128171f7a97c456efacfeaf70ea720a9dc857508dd69f85de1eb482665ad7a2ce4a479591
RUN set -eu; arch="${TARGETARCH:-$(dpkg --print-architecture)}"; eval sha=\$JOERN_SHA_$arch; \
    zarch=$([ "$arch" = amd64 ] && echo x86_64 || echo arm64); cd /tmp; \
    curl -fsSLo joern.zip "https://github.com/joernio/joern/releases/download/v${JOERN_VERSION}/joern-cli-linux-${zarch}.zip"; \
    echo "$sha  joern.zip" | sha512sum -c -; unzip -q joern.zip -d /opt; rm joern.zip; \
    (cd /opt/joern-cli && ./joern-scan --updatedb >/dev/null 2>&1 || true); chmod -R a+rX /opt/joern-cli

# Offline rule sets, readable by every engagement user. Refresh by rebuilding the image.
#   /opt/nuclei-templates: nuclei community templates (linked into each engagement's home)
#   /opt/semgrep-rules:    semgrep community rules, for "Network: offline" engagements
#                          (semgrep --config /opt/semgrep-rules/python ...). Check the Semgrep Rules License
#                          before using them in a commercial service.
RUN nuclei -update-template-dir /opt/nuclei-templates -update-templates -silent || true; \
    git clone -q --depth 1 https://github.com/semgrep/semgrep-rules /opt/semgrep-rules && rm -rf /opt/semgrep-rules/.git; \
    chmod -R a+rX /opt/nuclei-templates /opt/semgrep-rules

COPY core.py server.py rvctl.py infra_domains.txt rv-sandbox.sh /opt/kali-mcp/
COPY joern/ /opt/kali-mcp/joern/
COPY aitools/rv-llm /usr/local/bin/rv-llm
COPY aitools/jwt_tool_wrap.py /opt/jwt_tool/jwt_tool_wrap.py
RUN chmod 755 /opt/kali-mcp/rv-sandbox.sh /opt/kali-mcp/joern/rv-joern && chmod 700 /opt/kali-mcp/rvctl.py \
    && chmod 644 /opt/kali-mcp/joern/taint.sc && chmod 755 /usr/local/bin/rv-llm && ln -sf /opt/kali-mcp/joern/rv-joern /usr/local/bin/rv-joern
WORKDIR /work
EXPOSE 8090
CMD ["/opt/venv/bin/python3", "/opt/kali-mcp/server.py"]
