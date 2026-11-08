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
import datetime, difflib, hashlib, ipaddress, json, os, re, shutil, signal, subprocess, time, uuid

WORK, CONTROL, HERE = "/work", "/control", os.path.dirname(os.path.abspath(__file__))
REGISTRY = os.path.join(CONTROL, "registry.json")
AUDIT = os.path.join(CONTROL, "audit.log")
UID_BASE, MAX_OUT = 20000, 30_000
TIERS = ("passive", "active", "intrusive")
DEFAULT_RULES = {"tiers": ["passive", "active"], "max_rate": 100, "network": "online", "window": None,
                 "worker": "auto", "strict": False}  # worker: auto (fallback model allowed) | private (worker endpoint only)
# Never reachable by agent commands, even if a scope entry covers them (loopback, link-local/cloud metadata).
ALWAYS_BLOCKED = ["127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/8", "224.0.0.0/4"]

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


def _entries(text):
    for line in text.splitlines():
        s = line.strip().lstrip("-* ").split("#")[0].strip()
        if s:
            yield s


def parse_scope(text):
    """-> dict(nets=[...], domains=[...], paths=[...], warnings=[...])"""
    sc = {"nets": [], "domains": [], "paths": [], "warnings": []}
    for s in _entries(text):
        if s.startswith("/"):
            p = os.path.normpath(s)
            (sc["paths"].append(p) if p.startswith("/src/") or p == "/src"
             else sc["warnings"].append(f"path outside /src ignored: {s}"))
            continue
        host = re.sub(r"^[a-z]+://", "", s.lower())
        if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}/\d{1,2}", host):  # keep a CIDR's prefix; drop a URL's path
            host = host.split("/")[0]
        host = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
        try:
            net = ipaddress.ip_network(host, strict=False)
            if net.version == 6:
                sc["warnings"].append(f"IPv6 not supported yet, ignored: {s}")
            elif any(net.overlaps(ipaddress.ip_network(b)) for b in ALWAYS_BLOCKED):
                sc["warnings"].append(f"loopback/link-local/multicast is never reachable, ignored: {s}")
            else:
                sc["nets"].append(str(net))
            continue
        except ValueError:
            pass
        d = host.lstrip("*.").strip(".")
        if re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z][a-z0-9-]+", d):
            sc["domains"].append(d)
        else:
            sc["warnings"].append(f"unrecognised scope entry ignored: {s}")
    return sc


def parse_rules(text):
    r = dict(DEFAULT_RULES, tiers=list(DEFAULT_RULES["tiers"]))
    for s in _entries(text or ""):
        k, _, v = s.partition(":")
        k, v = k.strip().lower(), v.strip().lower()
        if k.startswith("allowed tier"):
            r["tiers"] = [t for t in re.split(r"[,\s]+", v) if t in TIERS] or ["passive"]
        elif k.startswith("max rate"):
            m = re.search(r"\d+", v); r["max_rate"] = int(m.group()) if m else r["max_rate"]
        elif k == "network":
            r["network"] = "offline" if "offline" in v else "online"
        elif k.startswith("strict"):
            r["strict"] = v.split()[0] in ("on", "yes", "true") if v else False
        elif k.startswith("worker"):
            r["worker"] = "private" if "private" in v else "auto"
        elif k.startswith("window"):
            m = re.search(r"(\d{1,2}):(\d{2})\s*-\s*(\d{1,2}):(\d{2})", v)
            r["window"] = [int(x) for x in m.groups()] if m else None
    return r


def read_ctl(eng, name):
    try:
        return open(os.path.join(ctl_dir(eng), name)).read()
    except OSError:
        return ""


def info(eng):
    uid = require(eng)
    sc, rules = parse_scope(read_ctl(eng, "SCOPE.md")), parse_rules(read_ctl(eng, "RULES.md"))
    return {"engagement": eng, "uid": uid, "scope": {k: sc[k] for k in ("nets", "domains", "paths")},
            "rules": rules, "halted": os.path.exists(os.path.join(ctl_dir(eng), "HALT")),
            "infra_domains": infra_domains() if rules["network"] == "online" else []}


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
    sc, rules = parse_scope(scope_text), parse_rules(rules_text)
    return {"diff": "\n".join(out), "warnings": sc["warnings"], "rules": rules,
            "scope": {k: sc[k] for k in ("nets", "domains", "paths")}}


def sync(eng):
    """Import the host's SCOPE.md/RULES.md as the authoritative copy (rvkit only), then rebuild the firewall."""
    if not _name_ok(eng):
        raise ValueError(f"invalid engagement name: {eng}")
    if not os.path.isfile(os.path.join(WORK, eng, "SCOPE.md")):
        raise ValueError(f"/work/{eng}/SCOPE.md not found")
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
    sc = parse_scope(read_ctl(eng, "SCOPE.md"))
    _audit({"engagement": eng, "event": "scope-sync", "scope": {k: sc[k] for k in ("nets", "domains", "paths")},
            "rules": parse_rules(read_ctl(eng, "RULES.md"))})
    return sc["warnings"]


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


def apply_network():
    """Rebuild nftables policy and per-engagement DNS for every registered engagement (idempotent)."""
    reg = registry()
    blocked = ALWAYS_BLOCKED + _local_subnets()  # other Docker services (LiteLLM, OpenHands, ...) included
    online_infra = infra_domains()
    sets, chains, vmap, nat = [], [], [], []
    for eng, uid in sorted(reg.items(), key=lambda x: x[1]):
        _ensure_user(uid)
        i = info(eng)
        dns_ip = f"127.0.1.{uid - UID_BASE}"
        nets = i["scope"]["nets"]
        sets.append(f"  set e{uid}_dns4 {{ type ipv4_addr; flags timeout; timeout 2h; }}")
        sets.append(f"  set e{uid}_net4 {{ type ipv4_addr; flags interval; auto-merge; "
                    + (f"elements = {{ {', '.join(nets)} }}; " if nets else "") + "}")
        rules = [f"    ip daddr {dns_ip} meta l4proto {{ tcp, udp }} th dport 53 accept",
                 f"    ip daddr {{ {', '.join(blocked)} }} counter drop",
                 f"    ip daddr @e{uid}_net4 accept", f"    ip daddr @e{uid}_dns4 accept"]
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
        for d in i["scope"]["domains"]:
            args += [f"--server=/{d}/127.0.0.11", f"--nftset=/{d}/4#inet#rvkit#e{uid}_dns4"]
        for d in i["infra_domains"]:
            args += [f"--server=/{d}/127.0.0.11", f"--nftset=/{d}/4#inet#rvkit#infra4"]
        # daemonises; refuses every name not listed. DEVNULL: a daemon holding a pipe would block run().
        subprocess.run(args, check=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


# ---------------------------------------------------------------- approvals, halt, window, regex pre-check
def _cmd_hash(command):
    return hashlib.sha256(command.encode()).hexdigest()[:16]


def approvals(eng, status=None):
    d = os.path.join(ctl_dir(eng), "approvals")
    out = []
    for f in sorted(os.listdir(d)) if os.path.isdir(d) else []:
        a = json.load(open(os.path.join(d, f)))
        if not status or a["status"] == status:
            out.append(a)
    return out


def _approval_path(eng, aid):
    if not re.fullmatch(r"[a-f0-9]{8}", aid or ""):
        raise ValueError("invalid approval id")
    return os.path.join(ctl_dir(eng), "approvals", aid + ".json")


def request_approval(eng, command, tier):
    for a in approvals(eng, "pending"):
        if a["hash"] == _cmd_hash(command):
            return a
    a = {"id": uuid.uuid4().hex[:8], "engagement": eng, "command": command, "hash": _cmd_hash(command),
         "tier": tier, "status": "pending", "created": time.time()}
    json.dump(a, open(_approval_path(eng, a["id"]), "w"), indent=1)
    _audit({"engagement": eng, "event": "approval-requested", "approval": a["id"], "command": command})
    return a


def decide(eng, aid, approve):
    path = _approval_path(eng, aid)
    a = json.load(open(path))
    if a["status"] != "pending":
        raise ValueError(f"approval {aid} is {a['status']}")
    a.update(status="approved" if approve else "denied", decided=time.time())
    json.dump(a, open(path, "w"), indent=1)
    _audit({"engagement": eng, "event": "approval-" + a["status"], "approval": aid, "command": a["command"]})
    return a


def _use_approval(eng, aid, command):
    path = _approval_path(eng, aid)
    if not os.path.exists(path):
        return "no such approval"
    a = json.load(open(path))
    if a["status"] != "approved":
        return f"approval {aid} is {a['status']}"
    if a["hash"] != _cmd_hash(command):
        return "approval was for a different command; it must match exactly"
    if time.time() - a.get("decided", 0) > 86400:
        return "approval expired (24 h)"
    a.update(status="used", used=time.time())
    json.dump(a, open(path, "w"), indent=1)
    return None


def halt(eng, on):
    uid = require(eng)
    flag = os.path.join(ctl_dir(eng), "HALT")
    if on:
        open(flag, "w").write(datetime.datetime.now(datetime.timezone.utc).isoformat())
        subprocess.run(["pkill", "-KILL", "-u", str(uid)], capture_output=True)
    elif os.path.exists(flag):
        os.remove(flag)
    _audit({"engagement": eng, "event": "halt" if on else "resume"})


def _in_window(window):
    if not window:
        return True
    h1, m1, h2, m2 = window
    now = datetime.datetime.now(datetime.timezone.utc)
    cur, a, b = now.hour * 60 + now.minute, h1 * 60 + m1, h2 * 60 + m2
    return a <= cur < b if a <= b else (cur >= a or cur < b)


# a host never starts inside a path, a word or a dotted name: "10.0.0.1/login.php" yields only the IP
HOST_RE = re.compile(r"(?<![\w./-])(?:https?://)?((?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?|(?:[a-z0-9-]+\.)+[a-z]{2,})",
                     re.I)
FILE_EXT = re.compile(r"\.(txt|json|jsonl|md|py|js|ts|yml|yaml|xml|html|log|csv|err|out|sh|conf|cfg|ini|toml|lock|"
                      r"gz|zip|tar|pem|key|crt|db|sqlite|nmap|gnmap|xsl)$", re.I)


def precheck(command, info_):
    """Early, readable refusal for obvious out-of-scope targets in network-tool commands. The firewall is the
    real enforcement; this only looks at segments that run network tools (no false positives on grep/python)."""
    sc, bad = info_["scope"], []
    for prog, seg in _segments(command):
        if prog not in ACTIVE and prog not in INTRUSIVE:
            continue
        for tok in set(HOST_RE.findall(seg)):
            t = tok.lower()
            if FILE_EXT.search(t) or any(t == d or t.endswith("." + d) for d in sc["domains"] + info_["infra_domains"]):
                continue
            try:
                ok = any(ipaddress.ip_network(t, strict=False).subnet_of(ipaddress.ip_network(n)) for n in sc["nets"])
            except ValueError:
                ok = False
            if not ok:
                bad.append(t)
    return sorted(set(bad))


# ---------------------------------------------------------------- evidence integrity
SKIP_DIRS = {".home", "workspace", "node_modules", ".git"}  # tool caches, Joern CPG workspace
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
            item.update(status="verified", produced_by=hit["command"], at=hit["ts"], tier=hit.get("tier"),
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
def _audit(entry):
    entry = {"ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"), **entry}
    line = json.dumps(entry) + "\n"
    with open(AUDIT, "a") as f:
        f.write(line)
    try:  # convenience mirror on the host; the authoritative log is /control/audit.log
        with open(os.path.join(WORK, "audit.log"), "a") as f:
            f.write(line)
    except OSError:
        pass


def run(command, eng, timeout_s=600, approval_id=None):
    i = info(eng)
    uid, rules = i["uid"], i["rules"]
    entry = {"engagement": eng, "uid": uid, "command": command}

    def refuse(msg, **extra):
        _audit({**entry, "refused": msg, **extra})
        return f"REFUSED: {msg}"

    if i["halted"]:
        return refuse("engagement is halted (./rvkit resume <engagement> on the host)")
    if not _in_window(rules["window"]):
        return refuse("outside the testing window in RULES.md (UTC)")
    tier = classify(command, rules.get("strict", False))
    entry["tier"] = tier
    if tier not in rules["tiers"]:
        return refuse(f"this command is tier '{tier}', RULES.md allows only {rules['tiers']}", tier=tier)
    bad = precheck(command, i)
    if bad:
        return refuse(f"targets not in scope for {eng}: {bad}")
    if tier == "intrusive":
        if not approval_id:
            a = request_approval(eng, command, tier)
            return (f"APPROVAL REQUIRED (intrusive). Approval id: {a['id']}. Ask the user to review and run on the "
                    f"host:  ./rvkit approve {eng} {a['id']}   Then call run again with the same command and "
                    f"approval_id='{a['id']}'.")
        err = _use_approval(eng, approval_id, command)
        if err:
            return refuse(err, approval=approval_id)
        entry["approval"] = approval_id
    final, err = apply_rate(command, rules["max_rate"])
    if err:
        return refuse(err)
    entry["command"] = final
    if final != command:
        entry["original"] = command

    env = {"RV_ENG": eng, "RV_UID": str(uid), "RV_HOME": f"/work/{eng}/.home",
           "RV_SRC": "\n".join(i["scope"]["paths"]), "RV_CMD": final, "PATH": os.environ.get("PATH", "")}
    root = os.path.join(WORK, eng)
    before = _snapshot(root)
    t0 = time.time()
    p = subprocess.Popen(["unshare", "-m", "-p", "-f", "--mount-proc", "--propagation", "private",
                          os.path.join(HERE, "rv-sandbox.sh")], env=env, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        out, errout = p.communicate(timeout=min(int(timeout_s or 600), 3600))
        code = p.returncode
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        out, errout = p.communicate()
        out, code = f"TIMEOUT after {timeout_s}s\n{(out or '')[-5000:]}", -1
    outputs = _outputs(root, before)
    seconds = round(time.time() - t0, 1)
    res = (out or "") + ("\n[stderr]\n" + errout if errout else "")
    # The command's own output, saved by kali-mcp (not the sandbox) and hashed in the same audit entry: it is
    # verified evidence the agent can cite, instead of a copy it would write itself (which can't be verified).
    rel = run_output_path(entry["command"])
    full = os.path.join(root, rel)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w") as f:
        f.write(f"# {entry['command']}\n# exit={code} tier={tier} seconds={seconds} "
                f"at={datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')}\n\n{res}")
    outputs[rel] = sha256_file(full)
    _audit({**entry, "exit": code, "seconds": seconds, "outputs": outputs})
    if final != command:
        res = f"[rate limit applied: {final}]\n" + res
    files = sorted(k for k in outputs if k != rel)
    if files:
        res += "\n[evidence recorded: " + ", ".join(files[:20]) + (" …" if len(files) > 20 else "") + "]"
    if len(res) > MAX_OUT:
        res = res[:MAX_OUT] + "\n... truncated"
    return f"exit={code} tier={tier}\n{res}\n[output saved as verified evidence: /work/{eng}/{rel}]"


RUNS_DIR = os.path.join("evidence", "runs")


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
