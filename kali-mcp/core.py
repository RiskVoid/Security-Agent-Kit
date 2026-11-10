"""Policy and sandbox core for kali-mcp: engagements, scope, rules, tiers, approvals, firewall, audit.

Trust model
  /control (named volume, root-only)  authoritative SCOPE.md / RULES.md / approvals / HALT / audit log.
                                      Only `rvctl` (driven by ./rvkit on the host) changes scope and rules.
  /work/<engagement> (host folder)    agent-visible working area. SCOPE.md / RULES.md there are mirrors;
                                      agent edits to them have no effect.
  Agent commands                      run via rv-sandbox.sh as an unprivileged per-engagement user, in their own
                                      mount + pid namespace, behind an nftables policy built from the scope.
The network policy is the hard boundary for scope. Tiers, rate caps and the regex pre-check are guardrails
against mistakes: a script could still send intrusive traffic to in-scope hosts.
"""
import datetime, difflib, fcntl, hashlib, ipaddress, json, os, re, shlex, shutil, signal, socket, subprocess, \
    threading, time, uuid

import policy as rvpolicy

WORK, CONTROL, HERE = "/work", "/control", os.path.dirname(os.path.abspath(__file__))
REGISTRY = os.path.join(CONTROL, "registry.json")
AUDIT = os.path.join(CONTROL, "audit.log")
UID_BASE, MAX_OUT = 20000, 30_000
TIERS = ("passive", "active", "intrusive")
DEFAULT_RULES = rvpolicy.DEFAULT_RULES  # worker: auto (fallback model allowed) | private (worker endpoint only)
# Never reachable by agent commands, even if a scope entry covers them (loopback, link-local/cloud metadata).
MCP_PORT = 8090  # server.py listens here; engagement commands must never reach it (they could call run for others)
# Who is acting, recorded on every audit entry: rvctl sets it from --actor (console:<user> or cli:<user>); commands
# that arrive through the MCP server are the agent's.
ACTOR = "agent:kali-mcp"
ACTOR_RX = re.compile(r"^(console|cli|agent|test):[A-Za-z0-9._@-]{1,64}$")
# Events another authority reports for the audit log (rvctl record): changes made through harness/ops.py.
RECORDABLE = {"finding-updated", "finding-recorded", "meta-updated", "summary-updated", "report-generated",
              "finding-not-reproducible", "observations-imported", "observation-added", "observations-linked",
              "observations-dismissed", "observations-duplicate", "observations-reopened", "plan-items-added",
              "coverage-updated", "coverage-reassessed", "objective-set", "handover-saved",
              "report-exception", "report-exception-revoked", "report-approved", "report-rebuilt",
              "report-transmitted", "retest-recorded", "cleanup-added", "cleanup-updated", "notice-prepared",
              "notice-reviewed", "findings-exported"}


class Conflict(ValueError):
    """The scope or rules changed since the caller read them."""


ALWAYS_BLOCKED = rvpolicy.ALWAYS_BLOCKED

# ---------------------------------------------------------------- tiers
# Program lists, subcommand rules, rate flags and strict mode live in tiers.yaml (checked at start-up).
import tierconf  # noqa: E402

POLICY = tierconf.load(os.path.join(HERE, "tiers.yaml"))
INTRUSIVE, ACTIVE = POLICY["intrusive"], POLICY["active"]
WRAPPERS = {"sudo", "env", "timeout", "nice", "nohup", "time", "stdbuf", "xargs", "command", "exec"}
SHELLS = {"sh", "bash", "dash", "zsh", "ksh"}
SPLIT = re.compile(r"\|\||&&|[|;&\n]|\$\(|`")
# code handed to a shell as a string: sh -c '...', bash -lc "...", eval '...'
INNER = re.compile(r"(?:^|[\s;&|(`])(?:(?:/\S*/)?(?:" + "|".join(sorted(SHELLS)) + r")\s+(?:-[A-Za-z]+\s+)*-[A-Za-z]*c[A-Za-z]*"
                   r"|eval)\s+(?:'([^']*)'|\"((?:[^\"\\]|\\.)*)\")")


def _segments(command):
    """(program, segment_text) for each simple command in a shell line (best effort)."""
    out = []
    for seg in SPLIT.split(command):
        words = seg.strip().split()
        i = 0
        while i < len(words) and (re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=\S*", words[i]) or words[i] in WRAPPERS
                                  or words[i].startswith("-") or re.fullmatch(r"\d+[smhd]?", words[i])):
            i += 1
        if i < len(words):
            out.append((os.path.basename(words[i].strip("'\"()")), seg))
    return out


def _interpreter(prog, seg):
    """True if this segment runs code through an interpreter (not just asks for its version or help)."""
    if prog not in POLICY["interpreters"] and re.sub(r"[\d.]+$", "", prog) not in POLICY["interpreters"]:
        return False
    rest = seg.split(prog, 1)[-1].split()
    return not (rest and all(w in ("--version", "-V", "-v", "--help", "-h") for w in rest))


def _max(a, b):
    return a if TIERS.index(a) >= TIERS.index(b) else b


def classify(command, strict=False, _depth=0):
    """The command's tier: the highest tier of the programs it runs. strict (RULES.md "Strict tiers: on") also
    counts interpreters running code, and requests that send data, from tiers.yaml's strict section."""
    tier = "passive"
    for prog, seg in _segments(command):
        t = None
        if strict:
            t = next((st for p, rx, st in POLICY["strict_subcommands"] if p == prog and rx.search(seg)), None)
        if t is None:
            t = next((st for p, rx, st in POLICY["subcommands"] if p == prog and rx.search(seg)), None)
        if t is None:
            t = "intrusive" if prog in INTRUSIVE else "active" if prog in ACTIVE else "passive"
        # a shell's -c string is classified below by what it runs; a shell running a script file is an interpreter
        if strict and _interpreter(prog, seg) and not (prog in SHELLS and re.search(r"\s-[A-Za-z]*c", seg)):
            t = _max(t, POLICY["interpreter_tier"])
        tier = _max(tier, t)
    if _depth < 3:  # what sh -c '...' and eval '...' run counts too
        for m in INNER.finditer(command):
            inner = m.group(1) if m.group(1) is not None else m.group(2).replace('\\"', '"')
            tier = _max(tier, classify(inner, strict, _depth + 1))
    return tier


def apply_rate(command, max_rate):
    """Insert the rate flag after each rate-limitable program, or refuse if a higher rate is set."""
    if not max_rate:
        return command, None
    for m in list(INNER.finditer(command)):  # tools run through sh -c '...' or eval get the cap too
        inner = m.group(1) if m.group(1) is not None else m.group(2)
        capped, err = apply_rate(inner, max_rate)
        if err:
            return None, err
        command = command.replace(inner, capped, 1)
    for prog, seg in _segments(command):
        spec = POLICY["rate_flags"].get(prog)
        if not spec:
            continue
        flags = spec["flags"]
        m = re.search(r"(?:^|\s)(" + "|".join(map(re.escape, flags)) + r")[= ](\d+)", seg)
        if m:
            if int(m.group(2)) > max_rate:
                return None, f"{prog} {m.group(1)} {m.group(2)} exceeds the engagement max rate ({max_rate}/s)"
            continue
        val = spec["format"].format(max_rate)
        if spec["after"]:  # the option belongs to a subcommand: add it there, and only when it's used
            if not re.search(rf"\b{re.escape(spec['after'])}\b", seg):
                continue
            new = re.sub(rf"\b{re.escape(spec['after'])}\b", f"{spec['after']} {flags[0]} {val}", seg, count=1)
        else:
            new = re.sub(rf"(^|\s|/)({re.escape(prog)})(\s|$)", rf"\1\2 {flags[0]} {val}\3", seg, count=1)
        command = command.replace(seg, new, 1)
    return command, None


# ---------------------------------------------------------------- engagements, scope, rules
def _name_ok(eng):
    return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", eng or ""))


def ctl_dir(eng):
    return os.path.join(CONTROL, "eng", eng)


def registry():
    try:
        return json.load(open(REGISTRY))
    except (OSError, ValueError):
        return {}


def engagements():
    return sorted(registry())


def require(eng):
    if not _name_ok(eng) or eng not in registry():
        raise ValueError(f"unknown engagement '{eng}'. Engagements are created on the host with ./rvkit engagement")
    return registry()[eng]


_entries = rvpolicy.entries


def parse_rules(text):
    """Rules as enforced. An invalid line keeps the default for that rule here; sync refuses to activate it."""
    return rvpolicy.parse_rules(text)[0]


def policy_of(eng=None, scope_text=None, rules_text=None):
    """The effective policy of the active SCOPE.md/RULES.md (or of the given texts)."""
    if scope_text is None:
        scope_text, rules_text = read_ctl(eng, "SCOPE.md"), read_ctl(eng, "RULES.md")
    return rvpolicy.effective(scope_text, rules_text or "")


def read_ctl(eng, name):
    try:
        return open(os.path.join(ctl_dir(eng), name)).read()
    except OSError:
        return ""


def revision(eng):
    """Short digest of the active SCOPE.md and RULES.md: changes whenever either one does."""
    return hashlib.sha256((read_ctl(eng, "SCOPE.md") + "\0" + read_ctl(eng, "RULES.md")).encode()).hexdigest()[:16]


POLICY_KEYS = ("hosts", "nets", "urls", "exclude", "paths", "limits", "errors")


def policy_version(eng):
    """Number of the active policy revision (1 = the first applied scope), 0 if none is recorded yet."""
    d = os.path.join(ctl_dir(eng), "policy")
    nums = [int(f[:-5]) for f in os.listdir(d) if re.fullmatch(r"\d{4,}\.json", f)] if os.path.isdir(d) else []
    return max(nums, default=0)


def info(eng):
    uid = require(eng)
    pol = policy_of(eng)
    rules = pol["rules"]
    return {"engagement": eng, "uid": uid, "revision": revision(eng), "policy_version": policy_version(eng),
            "scope": rvpolicy.legacy_scope(pol), "policy": {k: pol[k] for k in POLICY_KEYS},
            "rules": rules, "halted": os.path.exists(os.path.join(ctl_dir(eng), "HALT")), "usage": usage(eng),
            "infra_domains": (infra_domains() + rules.get("browser_support", []))
            if rules["network"] == "online" else []}


def infra_domains():
    path = os.path.join(CONTROL, "infra_domains.txt")
    src = path if os.path.exists(path) else os.path.join(HERE, "infra_domains.txt")
    return list(_entries(open(src).read()))


# ---------------------------------------------------------------- sync (host files -> control), firewall
def diff(eng):
    out = []
    for f in ("SCOPE.md", "RULES.md"):
        host = os.path.join(WORK, eng, f)
        new = open(host).read() if os.path.exists(host) else ""
        out += difflib.unified_diff(read_ctl(eng, f).splitlines(), new.splitlines(),
                                    f"active/{f}", f"{eng}/{f} (host)", lineterm="")
    return "\n".join(out)


def preview(eng, scope_text, rules_text):
    """What applying this SCOPE.md / RULES.md would change, without writing anything: unified diff against the
    active copies, the parsed result and the parser's warnings."""
    if not _name_ok(eng):
        raise ValueError(f"invalid engagement name: {eng}")
    out = []
    for f, new in (("SCOPE.md", scope_text), ("RULES.md", rules_text)):
        old = read_ctl(eng, f) if eng in registry() else ""
        out += difflib.unified_diff(old.splitlines(), new.splitlines(), f"active/{f}", f"proposed/{f}", lineterm="")
    pol = policy_of(scope_text=scope_text, rules_text=rules_text)
    return {"diff": "\n".join(out), "errors": pol["errors"], "warnings": pol["warnings"], "limits": pol["limits"],
            "rules": pol["rules"], "scope": rvpolicy.legacy_scope(pol), "allows": rvpolicy.describe(pol),
            "exclude": pol["exclude"], "policy_version": policy_version(eng) if eng in registry() else 0}


def sync(eng, expected=None, texts=None):
    """Import the host's SCOPE.md/RULES.md as the authoritative copy (rvkit only), then rebuild the firewall.
    expected: the revision the caller previewed; if the active scope changed since, Conflict and nothing changes.
    texts: {"scope": ..., "rules": ...} to write to the engagement folder first (the console's apply), so what is
    imported is exactly what was previewed."""
    if not _name_ok(eng):
        raise ValueError(f"invalid engagement name: {eng}")
    before = revision(eng) if eng in registry() else None
    if expected is not None and expected != before:
        raise Conflict(f"the scope or rules of {eng} changed since you opened them (revision {before}, you had "
                       f"{expected}): reload, check the change, then apply again")
    if texts is not None:
        os.makedirs(os.path.join(WORK, eng), exist_ok=True)
        for f, key in (("SCOPE.md", "scope"), ("RULES.md", "rules")):
            if key in texts:
                with open(os.path.join(WORK, eng, f), "w") as fh:
                    fh.write(str(texts[key]))
    if not os.path.isfile(os.path.join(WORK, eng, "SCOPE.md")):
        raise ValueError(f"/work/{eng}/SCOPE.md not found")
    rp = os.path.join(WORK, eng, "RULES.md")
    new = policy_of(scope_text=open(os.path.join(WORK, eng, "SCOPE.md")).read(),
                    rules_text=open(rp).read() if os.path.exists(rp) else "")
    if new["errors"]:  # nothing is activated that the kit can't enforce or doesn't understand
        raise ValueError("not applied, fix these lines first:\n  " + "\n  ".join(new["errors"]))
    os.makedirs(os.path.join(ctl_dir(eng), "approvals"), exist_ok=True)
    for f in ("SCOPE.md", "RULES.md"):
        src = os.path.join(WORK, eng, f)
        if os.path.exists(src):
            shutil.copyfile(src, os.path.join(ctl_dir(eng), f))
        elif f == "RULES.md":
            open(os.path.join(ctl_dir(eng), f), "w").write("")
    reg = registry()
    if eng not in reg:
        free = sorted(set(range(UID_BASE + 1, UID_BASE + 251)) - set(reg.values()))  # deleted engagements free uids
        if not free:
            raise ValueError("too many engagements (max 250): delete closed ones with ./rvkit eng delete")
        reg[eng] = free[0]
        json.dump(reg, open(REGISTRY, "w"), indent=1)
    apply_network()
    _grant(eng, reg[eng])
    pol, after = policy_of(eng), revision(eng)
    version = policy_version(eng)
    if after != before or not version:  # a new policy revision: keep it, with who activated it
        version += 1
        os.makedirs(os.path.join(ctl_dir(eng), "policy"), exist_ok=True)
        with open(os.path.join(ctl_dir(eng), "policy", f"{version:04d}.json"), "w") as f:
            json.dump({"version": version, "revision": after, "previous": before, "actor": ACTOR,
                       "activated": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
                       "scope_text": read_ctl(eng, "SCOPE.md"), "rules_text": read_ctl(eng, "RULES.md"),
                       "policy": {k: pol[k] for k in POLICY_KEYS}, "rules": pol["rules"]}, f, indent=1)
    _audit({"engagement": eng, "event": "scope-sync", "scope": rvpolicy.legacy_scope(pol),
            "rules": pol["rules"], "before": before, "after": after, "policy_version": version})
    if before and after != before:
        invalidate_approvals(eng, f"the scope or rules changed (policy revision {version})")
    publish_routes()
    return pol["warnings"]


def policy_history(eng):
    d = os.path.join(ctl_dir(eng), "policy")
    out = []
    for f in sorted(os.listdir(d)) if os.path.isdir(d) else []:
        if re.fullmatch(r"\d{4,}\.json", f):
            p = json.load(open(os.path.join(d, f)))
            out.append({k: p.get(k) for k in ("version", "revision", "previous", "actor", "activated")})
    return out


def _grant(eng, uid):
    """Let the engagement's sandbox user write its own folder. On Linux the folder belongs to the host user (on
    macOS Docker bind mounts ignore ownership): give the uid a read-write ACL, inherited by new subfolders (evidence/
    and report/ are created by root-run services), and its own tool home (.home)."""
    root = os.path.join(WORK, eng)
    home = os.path.join(root, ".home")
    os.makedirs(home, exist_ok=True)
    subprocess.run(["chown", "-R", f"{uid}:{uid}", home], capture_output=True)
    subprocess.run(["setfacl", "-R", "-m", f"u:{uid}:rwX", "-m", f"d:u:{uid}:rwX", "--", root],
                   capture_output=True)  # fails harmlessly where the filesystem has no ACLs


def _ensure_user(uid):
    if subprocess.run(["getent", "passwd", str(uid)], capture_output=True).returncode:
        subprocess.run(["useradd", "-M", "-u", str(uid), "-s", "/bin/bash", "-d", "/nonexistent", f"rv-{uid}"],
                       check=True, capture_output=True)


LAB_NET = os.environ.get("RVKIT_LAB_NET", "10.250.0.0/24")  # isolated practice-target network (compose: rvlab)


def _local_subnets():
    """Docker subnets this container is on (other services: always blocked). The lab network is the exception:
    it holds only practice targets, so it is treated like any other target and reachable only when in scope."""
    out = subprocess.run(["ip", "-4", "-o", "addr", "show"], capture_output=True, text=True).stdout
    nets = {str(ipaddress.ip_interface(m).network) for m in re.findall(r"inet (\S+)", out)}
    return sorted(n for n in nets if not n.startswith("127.") and n != LAB_NET)


def _host_addrs(blocked):
    """The Docker host's addresses as containers see them (Docker Desktop and OrbStack forward them to the host's
    loopback, where the console listens), unless a blocked network already covers them."""
    nets = [ipaddress.ip_network(b) for b in blocked]
    out = set()
    for h in ("host.docker.internal", "host.internal", "gateway.docker.internal"):
        try:
            out |= {ai[4][0] for ai in socket.getaddrinfo(h, None, socket.AF_INET)}
        except OSError:
            pass
    return sorted(f"{a}/32" for a in out if not any(ipaddress.ip_address(a) in n for n in nets))


def apply_network():
    """Rebuild nftables policy and per-engagement DNS for every registered engagement (idempotent)."""
    reg = registry()
    blocked = ALWAYS_BLOCKED + _local_subnets()  # other Docker services (LiteLLM, OpenHands, ...) included
    blocked += _host_addrs(blocked)  # the host itself (the console, other local services)
    online_infra = infra_domains()
    sets, chains, vmap, nat = [], [], [], []
    for eng, uid in sorted(reg.items(), key=lambda x: x[1]):
        _ensure_user(uid)
        i = info(eng)
        pol = policy_of(eng)
        dns_ip = f"127.0.1.{uid - UID_BASE}"
        # Raw commands reach: nets (by address, optionally ports) and host names (addresses added when the
        # engagement's resolver answers, one set per port list). Exclusions and hosts with URL-level rules (only
        # the request tool can enforce a path) are dropped first.
        drop = pol["exclude"]["nets"] + [u + "/32" for u in rvpolicy.url_hosts(pol) if rvpolicy._is_ip(u)]
        allnets = [n["cidr"] for n in pol["nets"] if n["ports"] is None]
        sets.append(f"  set e{uid}_net4 {{ type ipv4_addr; flags interval; auto-merge; "
                    + (f"elements = {{ {', '.join(allnets)} }}; " if allnets else "") + "}")
        # Loopback 127.0.0.1 on unprivileged ports, except this MCP server's own port: tools that start a helper
        # and talk to it over localhost (gowitness drives Chromium through its DevTools port) need it. Docker's
        # DNS (127.0.0.11) and the other engagements' resolvers (127.0.1.x) stay blocked.
        rules = [f"    ip daddr {dns_ip} meta l4proto {{ tcp, udp }} th dport 53 accept",
                 f"    oifname \"lo\" ip daddr 127.0.0.1 tcp dport {{ 1024-{MCP_PORT - 1}, {MCP_PORT + 1}-65535 }} accept",
                 f"    ip daddr {{ {', '.join(blocked)} }} counter drop"]
        if drop:
            rules.append(f"    ip daddr {{ {', '.join(drop)} }} counter drop")
        rules.append(f"    ip daddr @e{uid}_net4 accept")
        for n in pol["nets"]:
            if n["ports"] is not None:
                rules.append(f"    ip daddr {n['cidr']} meta l4proto {{ tcp, udp }} th dport {{ {_nft_ports(n['ports'])} }} accept")
        for k, ports in enumerate(_host_groups(pol)):
            sets.append(f"  set e{uid}_h{k} {{ type ipv4_addr; flags timeout; timeout 2h; }}")
            rules.append(f"    ip daddr @e{uid}_h{k} " + (f"meta l4proto {{ tcp, udp }} th dport {{ {_nft_ports(list(ports))} }} "
                                                         if ports else "") + "accept")
        if i["rules"]["network"] == "online":
            rules.append("    ip daddr @infra4 tcp dport { 80, 443 } accept")
        chains.append(f"  chain e{uid} {{\n" + "\n".join(rules) + "\n    counter drop\n  }")
        vmap.append(f"{uid} : jump e{uid}")
        nat.append(f"    meta skuid {uid} meta l4proto {{ tcp, udp }} th dport 53 dnat to {dns_ip}:53")
    script = "\n".join([
        "table inet rvkit", "delete table inet rvkit", "table ip rvkit_nat", "delete table ip rvkit_nat",
        "table inet rvkit {",
        "  set infra4 { type ipv4_addr; flags timeout; timeout 2h; }", *sets,
        "  chain out {", "    type filter hook output priority 0; policy accept;",
        f"    meta skuid {UID_BASE + 1}-{UID_BASE + 254} jump eng", "  }",
        "  chain eng {", "    ct state established,related accept", "    meta nfproto ipv6 drop",
        *([f"    meta skuid vmap {{ {', '.join(vmap)} }}"] if vmap else []), "    counter drop", "  }",
        *chains, "}",
        "table ip rvkit_nat {", "  chain out {", "    type nat hook output priority -150; policy accept;",
        *nat, "  }", "}", ""])
    p = subprocess.run(["nft", "-f", "-"], input=script, capture_output=True, text=True)
    if p.returncode:
        raise RuntimeError("nft failed: " + p.stderr[-2000:])
    subprocess.run(["pkill", "-f", "dnsmasq.*rvkit-dns"], capture_output=True)
    time.sleep(0.3)
    for eng, uid in reg.items():
        i = info(eng)
        args = ["dnsmasq", "-u", "root", "--conf-file=/dev/null", f"--listen-address=127.0.1.{uid - UID_BASE}",
                "--bind-interfaces", "--port=53", "--no-resolv", "--no-hosts", "--filter-AAAA",
                "--cache-size=0", f"--pid-file=/run/rvkit-dns-{uid}.pid"]
        args += _dns_args(policy_of(eng), uid)
        for d in i["infra_domains"]:
            args += [f"--server=/{d}/127.0.0.11", f"--nftset=/{d}/4#inet#rvkit#infra4"]
        # daemonises; refuses every name not listed. DEVNULL: a daemon holding a pipe would block run().
        subprocess.run(args, check=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _nft_ports(ports):
    return ", ".join(str(p) for p in ports)


def _host_groups(pol):
    """Distinct port lists of the raw-reachable host entries, in a stable order (None = every port)."""
    out = []
    for h in pol["hosts"]:
        key = tuple(h["ports"]) if h["ports"] else None
        if key not in out:
            out.append(key)
    return out


def _dns_args(pol, uid):
    """dnsmasq options for one engagement's resolver. A name resolves only when a host entry covers it; the
    answer's addresses go into the nft set for that entry's ports. dnsmasq matches the longest listed domain:
    '/name/' covers the name and its subdomains, '/*.name/' only the subdomains, and an --address with no
    address answers NXDOMAIN. So an exact entry gets '/*.name/' refused unless a wildcard covers its subdomains,
    and exclusions and hosts that only the request tool may reach are refused outright."""
    groups = _host_groups(pol)
    args, wild = [], [h["name"] for h in pol["hosts"] if h["wildcard"]]
    for h in pol["hosts"]:
        pattern = ("*." if h["wildcard"] else "") + h["name"]
        k = groups.index(tuple(h["ports"]) if h["ports"] else None)
        # --nftset has no '*.' form: '/name/' matches the subdomains too, and the apex never gets an answer
        # (no --server covers it) unless it is listed itself; policy.py refuses the two with different ports.
        nft = f"--nftset=/{h['name']}/4#inet#rvkit#e{uid}_h{k}"
        args += [f"--server=/{pattern}/127.0.0.11"] + ([nft] if nft not in args else [])
        if not h["wildcard"] and not any(h["name"] == w or h["name"].endswith("." + w) for w in wild):
            args.append(f"--address=/*.{h['name']}/")
    for e in pol["exclude"]["hosts"]:
        args.append(f"--address=/{'*.' if e['wildcard'] else ''}{e['name']}/")
    for name in rvpolicy.url_hosts(pol):
        if not rvpolicy._is_ip(name):
            args.append(f"--address=/{name}/")
    return args


# ---------------------------------------------------------------- approvals, halt, window, regex pre-check
def _cmd_hash(command):
    return hashlib.sha256(command.encode()).hexdigest()[:16]


SANDBOX_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"  # rv-sandbox.sh's PATH
_EXE_CACHE = {}


def _exe_digest(prog):
    """sha256 of the program the sandbox would run for this name (None if not found)."""
    path = shutil.which(prog, path=SANDBOX_PATH)
    if not path:
        return None
    path = os.path.realpath(path)
    st = os.stat(path)
    key = (path, st.st_mtime_ns, st.st_size)
    if key not in _EXE_CACHE:
        _EXE_CACHE[key] = sha256_file(path)[:32]
    return _EXE_CACHE[key]


def _input_files(eng, command):
    """Files the command names that exist in the engagement folder or in-scope source: their digests are part of
    what an approval covers, so changing a script or wordlist after approval invalidates it."""
    out, root = {}, os.path.join(WORK, eng)
    try:
        words = shlex.split(command)
    except ValueError:
        words = command.split()
    for w in words:
        for cand in ([w] if w.startswith("/") else [os.path.join(root, w)]):
            p = os.path.normpath(cand)
            if (p.startswith(root + "/") or p.startswith("/src/")) and os.path.isfile(p) and len(out) < 50:
                if os.path.getsize(p) <= 64 * 1024 * 1024:
                    out[os.path.relpath(p, root) if p.startswith(root + "/") else p] = sha256_file(p)[:32]
    return out


def run_action(eng, command):
    """What an approval of a run command is bound to: the exact text, the programs it runs and its input files."""
    return {"kind": "run", "command": command,
            "executables": {prog: _exe_digest(prog) for prog, _ in _segments(command)},
            "inputs": _input_files(eng, command)}


def action_digest(action):
    return hashlib.sha256(json.dumps(action, sort_keys=True).encode()).hexdigest()[:32]


def _write_json(path, data):
    tmp = f"{path}.{os.getpid()}.{threading.get_ident()}.tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=1)
    os.replace(tmp, path)


def approvals(eng, status=None):
    d = os.path.join(ctl_dir(eng), "approvals")
    out = []
    for f in sorted(os.listdir(d)) if os.path.isdir(d) else []:
        if not f.endswith(".json"):
            continue
        a = json.load(open(os.path.join(d, f)))
        if not status or a["status"] == status:
            out.append(a)
    return out


def _approval_path(eng, aid):
    if not re.fullmatch(r"[a-f0-9]{8}", aid or ""):
        raise ValueError("invalid approval id")
    return os.path.join(ctl_dir(eng), "approvals", aid + ".json")


def request_approval(eng, action, tier, display, task=None):
    """A pending approval for exactly this action under the current policy revision (reused if one is pending)."""
    digest = action_digest(action)
    for a in approvals(eng, "pending"):
        if a.get("digest") == digest and a.get("policy") == revision(eng):
            return a
    a = {"id": uuid.uuid4().hex[:8], "engagement": eng, "kind": action["kind"], "command": display,
         "hash": _cmd_hash(display), "digest": digest, "action": action, "tier": tier, "status": "pending",
         "created": time.time(), "policy": revision(eng), "policy_version": policy_version(eng),
         "requested_by": ACTOR, "task": task}
    _write_json(_approval_path(eng, a["id"]), a)
    _audit({"engagement": eng, "event": "approval-requested", "approval": a["id"], "command": display,
            "digest": digest, "policy": a["policy"], "task": task})
    return a


def decide(eng, aid, approve):
    path = _approval_path(eng, aid)
    a = json.load(open(path))
    if a["status"] != "pending":
        raise ValueError(f"approval {aid} is {a['status']}")
    if approve and a.get("policy") != revision(eng):
        _stale(eng, a, "the scope or rules changed after it was requested")
        raise ValueError(f"approval {aid} is stale: the scope or rules changed after it was requested; the agent "
                         f"has to ask again")
    a.update(status="approved" if approve else "denied", decided=time.time(), decided_by=ACTOR)
    _write_json(path, a)
    _audit({"engagement": eng, "event": "approval-" + a["status"], "approval": aid, "command": a["command"],
            "digest": a.get("digest"), "policy": a.get("policy")})
    return a


def approval_status(eng, aid):
    """Where an approval stands (for the worker waiting on it); a stale one is marked stale here."""
    require(eng)
    path = _approval_path(eng, aid)
    if not os.path.exists(path):
        raise ValueError(f"no approval {aid} in {eng}")
    a = json.load(open(path))
    if a["status"] in ("pending", "approved") and a.get("policy") != revision(eng):
        _stale(eng, a, "the scope or rules changed")
    return {k: a.get(k) for k in ("id", "status", "stale_reason", "command", "task", "decided_by", "kind")}


def _stale(eng, a, why):
    a.update(status="stale", stale_reason=why, staled=time.time())
    _write_json(_approval_path(eng, a["id"]), a)
    _audit({"engagement": eng, "event": "approval-stale", "approval": a["id"], "command": a["command"], "reason": why})


def invalidate_approvals(eng, why):
    """Pending and approved-but-unused approvals stop being valid when the policy they were made under changes."""
    n = 0
    for a in approvals(eng):
        if a["status"] in ("pending", "approved") and a.get("policy") != revision(eng):
            _stale(eng, a, why)
            n += 1
    return n


def consume_approval(eng, aid, action, rules):
    """Use an approval for this action exactly once. None when it may run, else why not."""
    path = _approval_path(eng, aid)
    if not os.path.exists(path):
        return "no such approval"
    a = json.load(open(path))
    if a["status"] != "approved":
        return f"approval {aid} is {a['status']}" + (f" ({a['stale_reason']})" if a.get("stale_reason") else "")
    if "digest" not in a:
        return "approval was made before approvals were bound to the action; ask for a new one"
    if a.get("policy") != revision(eng):
        _stale(eng, a, "the scope or rules changed after it was approved")
        return "approval is stale: the scope or rules changed after it was approved; ask for a new one"
    if a["digest"] != action_digest(action):
        old = a.get("action") or {}
        what = [k for k in sorted(set(old) | set(action)) if old.get(k) != action.get(k)]
        return ("approval was for a different action (" + ", ".join(what or ["action"]) + " differ); it must "
                "match exactly, including the programs and input files it uses")
    if time.time() - a.get("decided", 0) > rules.get("approval_hours", 24) * 3600:
        return f"approval expired ({rules.get('approval_hours', 24)} h)"
    try:  # exactly once, also when two calls race for the same approval
        os.close(os.open(path[:-5] + ".used", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
    except FileExistsError:
        return f"approval {aid} is used"
    a.update(status="used", used=time.time())
    _write_json(path, a)
    return None


# ---------------------------------------------------------------- budgets and concurrency
def _usage_path(eng):
    return os.path.join(ctl_dir(eng), "usage.json")


def usage(eng):
    try:
        return json.load(open(_usage_path(eng)))
    except (OSError, ValueError):
        return {"requests": 0, "commands": 0}


def take_budget(eng, key, limit):
    """Count one request or command against the engagement-wide budget. False when the budget is used up."""
    with open(_usage_path(eng) + ".lock", "a") as lk:
        fcntl.flock(lk, fcntl.LOCK_EX)
        u = usage(eng)
        if limit is not None and u.get(key, 0) >= limit:
            return False
        u[key] = u.get(key, 0) + 1
        _write_json(_usage_path(eng), u)
        return True


_RATE_LOCK = threading.Lock()
_NEXT_SLOT = {}


def rate_wait(eng, per_second):
    """Space requests from the request tool to the engagement's max rate, across all callers of this server."""
    with _RATE_LOCK:
        now = time.monotonic()
        slot = max(now, _NEXT_SLOT.get(eng, 0.0))
        _NEXT_SLOT[eng] = slot + 1.0 / max(1, per_second)
    if slot > now:
        time.sleep(slot - now)


def halt(eng, on):
    """Halt: kill the engagement's commands, refuse new ones, and (through the routing table) stop model calls of
    its bound conversations and worker tasks. Resume undoes the block; killed work is not restarted."""
    uid = require(eng)
    flag = os.path.join(ctl_dir(eng), "HALT")
    if on:
        open(flag, "w").write(datetime.datetime.now(datetime.timezone.utc).isoformat())
        publish_routes()  # first: model calls stop before the commands are killed
        subprocess.run(["pkill", "-KILL", "-u", str(uid)], capture_output=True)
    elif os.path.exists(flag):
        os.remove(flag)
        publish_routes()
    _audit({"engagement": eng, "event": "halt" if on else "resume"})


def cancel_task(eng, task):
    """Kill the commands a worker task is running now (the worker stops the task itself)."""
    require(eng)
    n = 0
    for r in running(eng):
        if task and r.get("task") == task:
            try:
                os.killpg(int(r["pid"]), signal.SIGKILL)
                n += 1
            except (OSError, ValueError):
                pass
    _audit({"engagement": eng, "event": "task-cancelled", "task": task, "killed": n})
    return n


# ---------------------------------------------------------------- routing table for the model gateway (RW-006/7)
ROUTES = os.environ.get("RV_ROUTES_DIR", "/routes")


def conversations(eng):
    try:
        return json.load(open(os.path.join(ctl_dir(eng), "conversations.json")))
    except (OSError, ValueError):
        return []


CONV_RX = re.compile(r"^[0-9a-fA-F-]{8,64}$")


def bind_conversation(eng, cid, title=""):
    """Tie an OpenHands conversation to an engagement: its model calls then follow the engagement's Client data
    rule and stop when it is halted. Host only (rvctl); a conversation belongs to one engagement."""
    require(eng)
    if not CONV_RX.match(cid or ""):
        raise ValueError("conversation id must be the OpenHands conversation id (hex and dashes)")
    cid = cid.lower()
    for e in engagements():
        if e != eng and any(c["id"] == cid for c in conversations(e)):
            raise ValueError(f"conversation {cid} already belongs to engagement {e}")
    rows = [c for c in conversations(eng) if c["id"] != cid]
    rows.append({"id": cid, "title": str(title or "")[:200], "bound_by": ACTOR,
                 "bound": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")})
    _write_json(os.path.join(ctl_dir(eng), "conversations.json"), rows)
    publish_routes()
    _audit({"engagement": eng, "event": "conversation-bound", "conversation": cid})
    return rows[-1]


def unbind_conversation(eng, cid):
    require(eng)
    rows = conversations(eng)
    keep = [c for c in rows if c["id"] != (cid or "").lower()]
    if len(keep) == len(rows):
        raise ValueError(f"conversation {cid} is not bound to {eng}")
    _write_json(os.path.join(ctl_dir(eng), "conversations.json"), keep)
    publish_routes()
    _audit({"engagement": eng, "event": "conversation-unbound", "conversation": cid})


def routes():
    out = {"engagements": {}, "conversations": {}, "generated": time.time()}
    for e in engagements():
        try:
            pol = policy_of(e)
        except Exception:  # noqa: BLE001 - one bad engagement must not drop the table
            continue
        out["engagements"][e] = {"client_data": pol["rules"].get("client_data"), "paths": pol["paths"],
                                 "halted": os.path.exists(os.path.join(ctl_dir(e), "HALT"))}
        for c in conversations(e):
            out["conversations"][c["id"].replace("-", "")] = e  # OpenHands sends it with or without dashes
    return out


def publish_routes():
    """Write the routing table the LiteLLM hook reads (kali-routes volume, read-only there)."""
    try:
        os.makedirs(ROUTES, exist_ok=True)
        _write_json(os.path.join(ROUTES, "routes.json"), routes())
        os.chmod(os.path.join(ROUTES, "routes.json"), 0o644)
    except OSError:
        pass


# ---------------------------------------------------------------- credential vault (RW-006, RW-008)
# Values live in the control volume only, encrypted with the vault key (/control/vault.key, root only; host
# controlled: `./rvkit vault rotate` replaces it). Commands use $RV_CRED_<NAME> (set in the sandbox), requests use
# {{cred:NAME}} in the URL, headers or body, and identities (identities.py) name the credentials they log in with.
# Values are replaced by the reference in what is returned to the model, in kali-mcp's own evidence files and in
# the audit log. A credential can expire: an expired one is refused rather than sent.
CRED_NAME = re.compile(r"^[A-Z][A-Z0-9_]{0,31}$")
CRED_REF = re.compile(r"\{\{cred:([A-Za-z][A-Za-z0-9_]{0,31})\}\}")
_VAULT_LOCK = threading.RLock()


def _vault_key_file():
    return os.path.join(CONTROL, "vault.key")


def _fernet():
    from cryptography.fernet import Fernet  # in kali-mcp's venv; imported here so other users of core don't need it
    path = _vault_key_file()
    with _VAULT_LOCK:
        if not os.path.exists(path):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(Fernet.generate_key())
        return Fernet(open(path, "rb").read().strip())


def seal(value):
    """Encrypt a string with the vault key (str token)."""
    return _fernet().encrypt(value.encode()).decode()


def unseal(token):
    from cryptography.fernet import InvalidToken
    try:
        return _fernet().decrypt(token.encode()).decode()
    except InvalidToken:
        raise ValueError("a vault entry can't be decrypted with the current vault key")


def _cred_file(eng):
    return os.path.join(ctl_dir(eng), "credentials.vault.json")


def _now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def _expired(stamp):
    if not stamp:
        return False
    try:
        when = datetime.datetime.fromisoformat(stamp if "T" in stamp else stamp + "T23:59:59+00:00")
    except ValueError:
        return True
    if when.tzinfo is None:
        when = when.replace(tzinfo=datetime.timezone.utc)
    return when < datetime.datetime.now(datetime.timezone.utc)


def _migrate_plain(eng):
    """credentials.json from RW-006 (plain text in the control volume) -> the encrypted vault file."""
    old = os.path.join(ctl_dir(eng), "credentials.json")
    if not os.path.exists(old):
        return
    try:
        plain = json.load(open(old))
    except (OSError, ValueError):
        plain = {}
    sealed = _sealed(eng)
    for n, v in plain.items():
        sealed.setdefault(n, {"token": seal(v["value"]), "set_by": v.get("set_by"), "set_at": v.get("set_at")})
    _write_json(_cred_file(eng), sealed)
    os.chmod(_cred_file(eng), 0o600)
    os.remove(old)
    _audit({"engagement": eng, "event": "credentials-encrypted", "names": sorted(plain)})


def _sealed(eng):
    try:
        return json.load(open(_cred_file(eng)))
    except (OSError, ValueError):
        return {}


def _creds(eng):
    """{NAME: {"value", "set_by", "set_at", "expires"}} decrypted (never returned to the model)."""
    with _VAULT_LOCK:
        if os.path.exists(os.path.join(ctl_dir(eng), "credentials.json")):
            _migrate_plain(eng)
        out = {}
        for n, v in _sealed(eng).items():
            out[n] = {**{k: v.get(k) for k in ("set_by", "set_at", "expires")}, "value": unseal(v["token"])}
        return out


def cred_set(eng, name, value, expires=None):
    require(eng)
    name = (name or "").upper()
    if not CRED_NAME.match(name):
        raise ValueError("credential names are letters, digits and _ (start with a letter, up to 32)")
    value = (value or "").rstrip("\r\n")
    if len(value) < 4 or len(value) > 8192:
        raise ValueError("the value must be 4 to 8192 characters")
    if expires and _expired(expires):
        raise ValueError(f"expiry {expires} is in the past (or not YYYY-MM-DD / ISO time)")
    with _VAULT_LOCK:
        _creds(eng)  # migrates a plain-text file first
        c = _sealed(eng)
        c[name] = {"token": seal(value), "set_by": ACTOR, "set_at": _now_iso(), "expires": expires or None}
        _write_json(_cred_file(eng), c)
        os.chmod(_cred_file(eng), 0o600)
    _audit({"engagement": eng, "event": "credential-set", "name": name, **({"expires": expires} if expires else {})})


def cred_remove(eng, name):
    require(eng)
    with _VAULT_LOCK:
        _creds(eng)
        c = _sealed(eng)
        if c.pop((name or "").upper(), None) is None:
            raise ValueError(f"no credential {name} in {eng}")
        _write_json(_cred_file(eng), c)
    _audit({"engagement": eng, "event": "credential-removed", "name": name.upper()})


def cred_list(eng):
    require(eng)
    return [{"name": k, "set_by": v.get("set_by"), "set_at": v.get("set_at"), "expires": v.get("expires"),
             "expired": _expired(v.get("expires")), "env": f"RV_CRED_{k}", "ref": "{{cred:%s}}" % k}
            for k, v in sorted(_creds(eng).items())]


def cred_value(eng, name):
    """One credential's value, for the identity broker. Unknown or expired names raise ValueError."""
    c = _creds(eng).get((name or "").upper())
    if not c:
        raise ValueError(f"no credential {name} in {eng} (set it on the host: ./rvkit cred {eng} set {name})")
    if _expired(c.get("expires")):
        raise ValueError(f"credential {name.upper()} expired on {c['expires']} (renew it: ./rvkit cred {eng} set {name})")
    return c["value"]


def cred_env(eng):
    return {f"RV_CRED_{k}": v["value"] for k, v in _creds(eng).items() if not _expired(v.get("expires"))}


def _used_creds(eng, command):
    """Only the credentials a command names reach its environment: agent code in the same sandbox can read every
    variable it gets (and print it encoded, past the scrubber), so the others stay out."""
    used = set(cred_used(eng, command))
    return {k: v for k, v in cred_env(eng).items() if k[len("RV_CRED_"):] in used}


def cred_used(eng, text):
    """Names of this engagement's credentials a command or request refers to."""
    names = set(_creds(eng))
    used = {m.group(1).upper() for m in CRED_REF.finditer(text or "")}
    used |= {n for n in names if re.search(r"\$\{?RV_CRED_" + n + r"\b", text or "")}
    return sorted(used)


def cred_expand(eng, text):
    """{{cred:NAME}} -> the value. Unknown or expired names raise ValueError (nothing is sent)."""
    return CRED_REF.sub(lambda m: cred_value(eng, m.group(1)), text or "")


_EXTRA_SECRETS = {}  # eng -> {value: reference}: identity sessions registered by identities.py


def register_secret(eng, value, ref):
    """Have scrub() replace a value that isn't a stored credential (an identity's session cookie or token)."""
    if value and len(value) >= 4:
        _EXTRA_SECRETS.setdefault(eng, {})[value] = ref


def secret_values(eng):
    """{value: reference} for everything scrub() replaces."""
    out = {v["value"]: "{{cred:%s}}" % n for n, v in _creds(eng).items()}
    out.update(_EXTRA_SECRETS.get(eng, {}))
    try:
        import identities
        out.update(identities.session_secrets(eng))
    except Exception:
        pass
    return out


def scrub(eng, data):
    """Replace credential and session values with their reference (str or bytes)."""
    if not data:
        return data
    vals = secret_values(eng)
    for val, ref in sorted(vals.items(), key=lambda kv: -len(kv[0])):
        if isinstance(data, bytes):
            data = data.replace(val.encode(), ref.encode())
        else:
            data = data.replace(val, ref)
    return data


def vault_rotate():
    """Re-encrypt every engagement's vault entries with a new key. Returns how many entries were re-encrypted."""
    from cryptography.fernet import Fernet
    with _VAULT_LOCK:
        old = _fernet()
        new_key = Fernet.generate_key()
        new = Fernet(new_key)
        files, n = [], 0
        for eng in engagements():
            for fn in ("credentials.vault.json", "identities.json"):
                path = os.path.join(ctl_dir(eng), fn)
                if not os.path.exists(path):
                    continue
                data = json.load(open(path))
                n += _reseal(data, old, new)
                files.append((path, data))
        for path, data in files:
            _write_json(path, data)
            os.chmod(path, 0o600)
        tmp = _vault_key_file() + ".new"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(new_key)
        os.replace(tmp, _vault_key_file())
    _audit({"event": "vault-rotated", "entries": n})
    return n


def _reseal(node, old, new):
    """Re-encrypt every "token"/"sealed" string in a JSON tree."""
    n = 0
    if isinstance(node, dict):
        for k, v in list(node.items()):
            if k in ("token", "sealed") and isinstance(v, str):
                node[k] = new.encrypt(old.decrypt(v.encode())).decode()
                n += 1
            else:
                n += _reseal(v, old, new)
    elif isinstance(node, list):
        for v in node:
            n += _reseal(v, old, new)
    return n


# a host never starts inside a path, a word or a dotted name: "10.0.0.1/login.php" yields only the IP
HOST_RE = re.compile(r"(?<![\w./-])(?:https?://)?((?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?|(?:[a-z0-9-]+\.)+[a-z]{2,})",
                     re.I)
FILE_EXT = re.compile(r"\.(txt|json|jsonl|md|py|js|ts|yml|yaml|xml|html|log|csv|err|out|sh|conf|cfg|ini|toml|lock|"
                      r"gz|zip|tar|pem|key|crt|db|sqlite|nmap|gnmap|xsl)$", re.I)


# Tools that name their target as user@host: there a name after "@" is the target, never an email address.
USER_AT_HOST = {"ssh", "scp", "sftp", "rsync", "sshpass", "evil-winrm", "nxc", "netexec", "crackmapexec", "hydra",
                "medusa", "ncrack"}
EMAIL = re.compile(r"[A-Za-z0-9._+-]+(?:@|%40)(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}", re.I)
WORD_END = re.compile(r"[\s'\"=&?,;:{}\[\]()<>]")


def _email_domain(seg, start, prog):
    """True when the name starting at seg[start] is part of an email address (alice@acme.test, or URL-encoded
    alice%40acme.test in form data) rather than a target. A URL's user part (http://user@host) and user@host tools
    still name a target."""
    if prog in USER_AT_HOST or prog.startswith("impacket-"):
        return False
    a = start
    while a > 0 and not WORD_END.match(seg[a - 1]):
        a -= 1
    b = start
    while b < len(seg) and not WORD_END.match(seg[b]):
        b += 1
    return EMAIL.fullmatch(seg[a:b].rstrip(".")) is not None


def precheck(command, info_, pol=None):
    """Early, readable refusal for obvious out-of-scope targets in network-tool commands. The firewall is the
    real enforcement; this only looks at segments that run network tools (no false positives on grep/python).
    Excluded hosts, and hosts only the request tool may reach, count as out of scope here."""
    pol = pol or info_.get("_policy") or policy_of(info_["engagement"])
    infra, bad = info_.get("infra_domains", []), []
    for prog, seg in _segments(command):
        if prog not in ACTIVE and prog not in INTRUSIVE:
            continue
        for m in HOST_RE.finditer(seg):
            t = m.group(1).lower()
            if _email_domain(seg, m.start(1), prog):
                continue
            if FILE_EXT.search(t) or any(t == d or t.endswith("." + d) for d in infra):
                continue
            if re.fullmatch(r"[\d./]+", t):
                ok = rvpolicy.raw_net(pol, t) is not None
            else:
                ok = rvpolicy.raw_host(pol, t) is not None
            if not ok:
                bad.append(t)
    return sorted(set(bad))


# ---------------------------------------------------------------- evidence integrity
SKIP_DIRS = {".home", ".rv", "workspace", "node_modules", ".git"}  # tool caches, the kit's own state, Joern CPG workspace
MAX_HASH = 512 * 1024 * 1024


def _snapshot(root):
    """{relpath: (mtime_ns, size)} for files in an engagement folder (skips caches)."""
    snap = {}
    for d, dirs, files in os.walk(root):
        dirs[:] = [x for x in dirs if x not in SKIP_DIRS]
        for f in files:
            p = os.path.join(d, f)
            try:
                st = os.stat(p, follow_symlinks=False)
            except OSError:
                continue
            snap[os.path.relpath(p, root)] = (st.st_mtime_ns, st.st_size)
    return snap


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _outputs(root, before):
    """Hashes of files created or changed since the snapshot."""
    out = {}
    for rel, meta in _snapshot(root).items():
        if before.get(rel) != meta and rel not in ("SCOPE.md", "RULES.md", "audit.log"):
            p = os.path.join(root, rel)
            out[rel] = sha256_file(p) if meta[1] <= MAX_HASH else f"not hashed (>{MAX_HASH >> 20} MB)"
    return out


def _produced_by(e):
    """What produced an audited output: a command line, or for HTTP requests and matrix runs (which audit no
    command line) the request or the matrix."""
    if e.get("command"):
        return e["command"]
    if e.get("event") == "authz-run":
        return f"authz run {e.get('matrix') or e.get('name') or ''}".strip()
    return " ".join(str(x) for x in (e.get("action"), e.get("method"), e.get("url"),
                                     f"as {e['identity']}" if e.get("identity") else None) if x)


def provenance(eng, paths):
    """For each evidence path: current SHA-256 and the audited command that produced exactly this content."""
    require(eng)
    root = os.path.join(WORK, eng)
    entries = [json.loads(l) for l in open(AUDIT)] if os.path.exists(AUDIT) else []
    entries = [e for e in entries if e.get("engagement") == eng and e.get("outputs")]
    res = []
    for raw in paths:
        p = str(raw).split()[0] if str(raw).strip() else ""
        rel = os.path.relpath(os.path.normpath(p if p.startswith("/") else os.path.join(root, p)), root)
        item = {"path": f"/work/{eng}/{rel}", "given": raw}
        full = os.path.join(root, rel)
        if rel.startswith("..") or not os.path.isfile(full):
            item["status"] = "not an engagement file" if rel.startswith("..") else "missing"
            res.append(item); continue
        item["sha256"] = sha256_file(full)
        hit = next((e for e in reversed(entries) if e["outputs"].get(rel) == item["sha256"]), None)
        if hit:
            item.update(status="verified", produced_by=_produced_by(hit), at=hit["ts"], tier=hit.get("tier"),
                        exit=hit.get("exit"))
        elif any(rel in e["outputs"] for e in entries):
            item["status"] = "MODIFIED after it was produced (hash differs from the audited output)"
        else:
            item["status"] = "not produced by an audited kali command (e.g. worker step file or manual)"
        res.append(item)
    return res


def activity(eng):
    """Summary of the authoritative audit log for one engagement (for reports)."""
    require(eng)
    rows = [json.loads(l) for l in open(AUDIT)] if os.path.exists(AUDIT) else []
    rows = [r for r in rows if r.get("engagement") == eng]
    cmds = [r for r in rows if "command" in r and "event" not in r]
    ran = [r for r in cmds if "exit" in r]
    tools = {}
    for r in ran:
        for prog, _ in _segments(r["command"]):
            if prog and prog not in ("echo", "cat", "head", "tail", "ls", "cd", "mkdir", "grep", "jq", "wc", "sort",
                                     "sed", "awk", "tee", "true", "test", "["):
                tools[prog] = tools.get(prog, 0) + 1
    ev = lambda e: sum(1 for r in rows if r.get("event") == e)
    return {"first": rows[0]["ts"] if rows else None, "last": rows[-1]["ts"] if rows else None,
            "commands_run": len(ran), "commands_refused": len(cmds) - len(ran),
            "by_tier": {t: sum(1 for r in ran if r.get("tier") == t) for t in TIERS},
            "tools": dict(sorted(tools.items(), key=lambda kv: -kv[1])),
            "evidence_files": sum(len(r.get("outputs", {})) for r in ran),
            "approvals": {"requested": ev("approval-requested"), "approved": ev("approval-approved"),
                          "denied": ev("approval-denied")},
            "halts": ev("halt"), "scope_changes": ev("scope-sync")}


# ---------------------------------------------------------------- run
def record(eng, event):
    """Add a change another authority made (harness/ops.py: findings, report details) to the audit log, so the
    engagement's history shows who changed what. Only known events, with a valid actor, are accepted."""
    require(eng)
    if not isinstance(event, dict) or event.get("event") not in RECORDABLE:
        raise ValueError(f"event must be one of {sorted(RECORDABLE)}")
    actor = event.get("actor")
    if not isinstance(actor, str) or not ACTOR_RX.match(actor):
        raise ValueError("event needs an actor: <console|cli|agent>:<name>")
    keep = {k: event[k] for k in ("event", "actor", "target", "before", "after", "fields", "files", "findings",
                                  "reason", "method", "state", "parser", "observations", "new", "errors", "count",
                                  "stale", "build", "policy_revision", "tool") if k in event}
    if len(json.dumps(keep, default=str)) > 4000:  # keep audit lines small: drop the details, not the event
        keep = {k: keep[k] for k in ("event", "actor", "target") if k in keep}
    entry = {"engagement": eng, **json.loads(json.dumps(keep, default=str))}
    _audit(entry)
    return entry


def _audit(entry):
    entry = {"ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"), "actor": ACTOR,
             **entry}
    line = json.dumps(entry) + "\n"
    with open(AUDIT, "a") as f:
        f.write(line)
    try:  # convenience mirror on the host; the authoritative log is /control/audit.log
        with open(os.path.join(WORK, "audit.log"), "a") as f:
            f.write(line)
    except OSError:
        pass


# Passive tools that need the network (DNS and registry lookups). With Execution: controlled, a passive command gets
# network only when it runs one of these; everything else passive (code review, parsing output) runs with none.
PASSIVE_NET = {"dig", "host", "nslookup", "delv", "drill", "whois", "dnsx", "subfinder", "assetfinder", "shuffledns",
               "puredns", "asnmap", "cdncheck"}


def _tier_over(tier, max_tier):
    return max_tier in TIERS and TIERS.index(tier) > TIERS.index(max_tier)


def run(command, eng, timeout_s=600, approval_id=None, max_tier=None, task=None):
    """Run one command in the engagement's sandbox after every policy check. max_tier: the calling task's tier
    (the worker passes it), never above the engagement's. Execution: controlled runs passive commands with no
    network at all and counts scripts and interpreters as intrusive (an approval each)."""
    i = info(eng)
    uid, rules = i["uid"], i["rules"]
    controlled = rules.get("execution") == "controlled"
    entry = {"engagement": eng, "uid": uid, "command": command, **({"task": task} if task else {})}

    def refuse(msg, **extra):
        _audit({**entry, "refused": msg, **extra})
        return f"REFUSED: {msg}"

    if i["halted"]:
        return refuse("engagement is halted (./rvkit resume <engagement> on the host)")
    late = rvpolicy.time_refusal(rules)
    if late:
        return refuse(late + " (RULES.md)")
    tier = classify(command, rules.get("strict", False) or controlled)
    entry["tier"] = tier
    if tier not in rules["tiers"]:
        return refuse(f"this command is tier '{tier}', RULES.md allows only {rules['tiers']}", tier=tier)
    if _tier_over(tier, max_tier):
        return refuse(f"this command is tier '{tier}' and this task may only use '{max_tier}'", tier=tier)
    pol = policy_of(eng)
    bad = precheck(command, i, pol)
    if bad:
        return refuse(f"targets not in scope for {eng}: {bad}")
    network = not (controlled and tier == "passive" and not any(p in PASSIVE_NET for p, _ in _segments(command)))
    parallel = network and tier != "passive"
    if parallel and _busy(eng) >= rules["max_parallel"]:
        return refuse(f"{_busy(eng)} network command(s) already running for {eng} (Max parallel: "
                      f"{rules['max_parallel']}); wait for one to finish")
    if tier == "intrusive":
        action = run_action(eng, command)
        if not approval_id:
            a = request_approval(eng, action, tier, command, task)
            return (f"APPROVAL REQUIRED (intrusive). Approval id: {a['id']}. Ask the user to review and run on the "
                    f"host:  ./rvkit approve {eng} {a['id']}   Then call run again with the same command and "
                    f"approval_id='{a['id']}'. Approvals are bound to this exact command, the programs and input "
                    f"files it uses and the current scope: a change to any of them needs a new approval.")
        err = consume_approval(eng, approval_id, action, rules)
        if err:
            return refuse(err, approval=approval_id)
        entry["approval"] = approval_id
    share = max(1, rules["max_rate"] // max(1, rules["max_parallel"]))  # parallel commands share the max rate
    final, err = apply_rate(command, share if network else None)
    if err:
        return refuse(err)
    if not take_budget(eng, "commands", rules.get("max_commands")):
        return refuse(f"the engagement's command budget is used up (Max commands: {rules['max_commands']})")
    entry["command"] = final
    if final != command:
        entry["original"] = command
    if not network:
        entry["network"] = "none"
    used = cred_used(eng, command)
    if used:
        entry["credentials"] = used
    if parallel:  # tools run in threads: check and reserve a slot atomically, released once its marker exists
        with _PAR_LOCK:
            if _busy(eng) >= rules["max_parallel"]:
                return refuse(f"{_busy(eng)} network command(s) already running for {eng} (Max parallel: "
                              f"{rules['max_parallel']}); wait for one to finish")
            _RESERVED[eng] = _RESERVED.get(eng, 0) + 1
    return _execute(eng, i, entry, final, tier, timeout_s, network, approval_id,
                    note=f"[rate limit applied: {final}]\n" if final != command else "", task=task,
                    reserved=parallel)


_PAR_LOCK = threading.Lock()
_RESERVED = {}


def _busy(eng):
    """Network commands above passive running now for eng, plus slots reserved by calls about to start one."""
    return sum(1 for r in running(eng) if r.get("network") and r.get("tier", "passive") != "passive") + \
        _RESERVED.get(eng, 0)


def _execute(eng, i, entry, final, tier, timeout_s, network, approval_id, note="", task=None, reserved=False,
             extra_env=None):
    """Run a checked command in the sandbox, save its output as verified evidence and audit it."""
    uid = i["uid"]
    env = {"RV_ENG": eng, "RV_UID": str(uid), "RV_HOME": f"/work/{eng}/.home",
           "RV_SRC": "\n".join(i["scope"]["paths"]), "RV_CMD": final, "PATH": os.environ.get("PATH", ""),
           **(_used_creds(eng, final) if network else {}), **(extra_env or {})}
    root = os.path.join(WORK, eng)
    before = _snapshot(root)
    t0 = time.time()
    ns = ["unshare", "-m", "-p", "-f"] + ([] if network else ["-n"]) + ["--mount-proc", "--propagation", "private"]
    try:
        p = subprocess.Popen(ns + [os.path.join(HERE, "rv-sandbox.sh")], env=env, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True, start_new_session=True)
        marker = _running_mark(eng, p.pid, {"command": final, "tier": tier, "started": t0, "network": network,
                                            "timeout_s": min(int(timeout_s or 600), 3600), "approval": approval_id,
                                            "task": task})
    finally:
        if reserved:  # the marker counts it from now on
            with _PAR_LOCK:
                _RESERVED[eng] = max(0, _RESERVED.get(eng, 0) - 1)
    try:
        out, errout = p.communicate(timeout=min(int(timeout_s or 600), 3600))
        code = p.returncode
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        out, errout = p.communicate()
        out, code = f"TIMEOUT after {timeout_s}s\n{(out or '')[-5000:]}", -1
    finally:
        try:
            os.remove(marker)
        except OSError:
            pass
    outputs = _outputs(root, before)
    seconds = round(time.time() - t0, 1)
    res = scrub(eng, (out or "") + ("\n[stderr]\n" + errout if errout else ""))
    # The command's own output, saved by kali-mcp (not the sandbox) and hashed in the same audit entry: it is
    # verified evidence the agent can cite, instead of a copy it would write itself (which can't be verified).
    rel = run_output_path(entry["command"])
    full = os.path.join(root, rel)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    # root writes here, in a folder the sandbox can change: refuse a link that leads out, and never follow one
    real_root, real_dir = os.path.realpath(root), os.path.realpath(os.path.dirname(full))
    if os.path.commonpath([real_root, real_dir]) != real_root:
        raise ValueError(f"/work/{eng}/{RUNS_DIR} leads outside the engagement folder (a link?)")
    full = os.path.join(real_dir, os.path.basename(full))
    with os.fdopen(os.open(full, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644), "w") as f:
        f.write(f"# {entry['command']}\n# exit={code} tier={tier} seconds={seconds} "
                f"at={datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')}"
                f"{'' if network else ' network=none'}\n\n{res}")
    outputs[rel] = sha256_file(full)
    _audit({**entry, "exit": code, "seconds": seconds, "outputs": outputs})
    res = note + res
    files = sorted(k for k in outputs if k != rel)
    if files:
        res += "\n[evidence recorded: " + ", ".join(files[:20]) + (" …" if len(files) > 20 else "") + "]"
    if len(res) > MAX_OUT:
        res = res[:MAX_OUT] + "\n... truncated"
    return f"exit={code} tier={tier}\n{res}\n[output saved as verified evidence: /work/{eng}/{rel}]"


RUNS_DIR = os.path.join("evidence", "runs")


def _running_mark(eng, pid, data):
    """A file per running command in /control/<eng>/running/, removed when it ends (for the console's live view)."""
    d = os.path.join(ctl_dir(eng), "running")
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, f"{pid}.json")
    with open(path, "w") as f:
        json.dump({**data, "engagement": eng, "pid": pid}, f)
    return path


def running(eng=None):
    """Commands running now, oldest first. Markers left by a restarted server (process gone) are removed."""
    if eng:
        require(eng)
    out = []
    for e in ([eng] if eng else engagements()):
        d = os.path.join(ctl_dir(e), "running")
        for name in (os.listdir(d) if os.path.isdir(d) else []):
            path = os.path.join(d, name)
            try:
                r = json.load(open(path))
                os.kill(int(r["pid"]), 0)
            except (OSError, ValueError, KeyError):
                try:
                    os.remove(path)
                except OSError:
                    pass
                continue
            out.append(r)
    return sorted(out, key=lambda r: r.get("started", 0))


def run_output_path(command):
    """evidence/runs/<UTC time>-<program>-<short id>.txt (relative to the engagement folder)."""
    prog = next((p for p, _ in _segments(command)), "cmd")
    prog = re.sub(r"[^A-Za-z0-9._-]", "", prog)[:24] or "cmd"
    return os.path.join(RUNS_DIR, f"{datetime.datetime.utcnow():%Y%m%dT%H%M%S}-{prog}-{uuid.uuid4().hex[:6]}.txt")


# ---------------------------------------------------------------- close-out
def close(eng):
    """Export the authoritative audit extract, write a SHA-256 manifest, archive the folder, halt the engagement."""
    require(eng)
    root = os.path.join(WORK, eng)
    entries = [l for l in open(AUDIT)] if os.path.exists(AUDIT) else []
    with open(os.path.join(root, "audit.jsonl"), "w") as f:
        f.writelines(l for l in entries if json.loads(l).get("engagement") == eng)
    for f in ("SCOPE.md", "RULES.md"):
        shutil.copyfile(os.path.join(ctl_dir(eng), f), os.path.join(root, f))
    rows = []
    for rel in sorted(_snapshot(root)):
        if rel in ("MANIFEST.sha256",):
            continue
        p = os.path.join(root, rel)
        rows.append(f"{sha256_file(p)}  {rel}")
    open(os.path.join(root, "MANIFEST.sha256"), "w").write("\n".join(rows) + "\n")
    os.makedirs(os.path.join(WORK, "_archive"), exist_ok=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    arc = os.path.join(WORK, "_archive", f"{eng}-{stamp}.tar.gz")
    subprocess.run(["tar", "-czf", arc, "--exclude=./.home", "--exclude=./workspace", "-C", root, "."], check=True)
    digest = sha256_file(arc)
    open(arc + ".sha256", "w").write(f"{digest}  {os.path.basename(arc)}\n")
    halt(eng, True)
    _audit({"engagement": eng, "event": "closed", "archive": os.path.basename(arc), "sha256": digest,
            "files": len(rows)})
    return {"archive": f"_archive/{os.path.basename(arc)}", "sha256": digest, "files": len(rows)}


def archives(eng):
    d = os.path.join(WORK, "_archive")
    return sorted(f for f in os.listdir(d) if f.startswith(eng + "-") and f.endswith(".tar.gz")) \
        if os.path.isdir(d) else []


def delete(eng, force=False):
    """Unregister an engagement: kill its commands, drop its scope, approvals and firewall rules, free its uid.
    The audit log keeps its history. Its folder is renamed to _deleted-<eng>-<time> (nothing is removed), so the
    name can be used again. Only closed engagements (halted, with an archive), unless force."""
    uid = require(eng)
    closed = info(eng)["halted"] and archives(eng)
    if not closed and not force:
        raise ValueError(f"{eng} is not closed. Close it first (./rvkit close {eng}: archive + manifest), "
                         "or pass --force to delete it without an archive")
    subprocess.run(["pkill", "-KILL", "-u", str(uid)], capture_output=True)
    reg = registry()
    reg.pop(eng, None)
    json.dump(reg, open(REGISTRY, "w"), indent=1)
    shutil.rmtree(ctl_dir(eng), ignore_errors=True)
    moved = None
    src = os.path.join(WORK, eng)
    if os.path.isdir(src):
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        moved = f"_deleted-{eng}-{stamp}"
        os.rename(src, os.path.join(WORK, moved))
    apply_network()
    publish_routes()
    _audit({"engagement": eng, "event": "deleted", "uid": uid, "forced": bool(force and not closed),
            "folder": moved})
    return {"folder": moved, "archives": archives(eng), "closed": bool(closed)}


# ---------------------------------------------------------------- semgrep community rules
RULES_DIR = "/opt/semgrep-rules"


def fetch_rules():
    """Download the semgrep community rules at the pinned commit into their volume (first start only). They are
    not baked into the image because the Semgrep Rules License doesn't allow redistributing them."""
    commit = os.environ.get("SEMGREP_RULES_COMMIT", "")
    marker = os.path.join(RULES_DIR, ".commit")
    if not commit or (os.path.exists(marker) and open(marker).read().strip() == commit):
        return
    tmp = RULES_DIR + "/.download"
    shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)
    url = f"https://codeload.github.com/semgrep/semgrep-rules/tar.gz/{commit}"
    r = subprocess.run(f"curl -fsSL --retry 3 '{url}' | tar xz -C '{tmp}' --strip-components 1",
                       shell=True, capture_output=True, text=True, timeout=600)
    if r.returncode:
        shutil.rmtree(tmp, ignore_errors=True)
        raise RuntimeError(f"semgrep rules download failed: {r.stderr.strip()[:300]}")
    for name in os.listdir(RULES_DIR):  # replace the old set
        if name != ".download":
            p = os.path.join(RULES_DIR, name)
            shutil.rmtree(p) if os.path.isdir(p) and not os.path.islink(p) else os.remove(p)
    for name in os.listdir(tmp):
        os.rename(os.path.join(tmp, name), os.path.join(RULES_DIR, name))
    os.rmdir(tmp)
    subprocess.run(["chmod", "-R", "a+rX", RULES_DIR])
    open(marker, "w").write(commit + "\n")


def fetch_rules_background():
    import sys, threading

    def go():
        try:
            fetch_rules()
        except Exception as e:
            print(f"WARNING: {e}. Offline semgrep scans need /opt/semgrep-rules; restart kali-mcp to retry.",
                  file=sys.stderr)
    threading.Thread(target=go, daemon=True).start()
