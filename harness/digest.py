"""What the worker model sees of a tool's output (epic #52, issue #32). Pure functions: no I/O.

The full output is always on disk (the kali evidence file and the task's step file). The model gets:
  - a digest for outputs the kit can read: JSON from semgrep, OSV-Scanner, pip-audit, bandit and gitleaks
    (parsed by observations.py: counts by severity and rule, the top items) instead of the raw JSON, and for
    nmap, sqlmap and nuclei text the lines that carry the verdict (open ports, injection points, matches);
  - otherwise the head and the tail of the output with the cut marked: many tools print their verdict last
    (sqlmap's summary, a scan's totals), so a head-only cut loses it.
The first line of a digest is a one-line summary; old results shrink to it (worker.compact).
"""
import collections, json, re

import observations

HEAD, TAIL = 4000, 2000
EVIDENCE_RX = re.compile(r"\[output saved as verified evidence: (\S+?)\]")


def clip(text, head=HEAD, tail=TAIL, path=None):
    """The head and the tail of text, with the cut marked."""
    if len(text) <= head + tail + 200:
        return text
    cut = len(text) - head - tail
    where = f": full output in {path}" if path else ""
    return f"{text[:head]}\n\n…[{cut} characters cut{where}]…\n\n{text[-tail:]}"


def _body(out):
    """A kali result without its first line (exit=… tier=…) and its evidence line."""
    lines = out.split("\n")
    if lines and re.match(r"exit=-?\d+", lines[0]):
        lines = lines[1:]
    return "\n".join(l for l in lines if not EVIDENCE_RX.search(l)).strip()


def _exit(out):
    m = re.match(r"exit=(-?\d+)", out)
    return int(m.group(1)) if m else None


def _obs_digest(name, obs, errors):
    sev = collections.Counter(o.get("severity") or "unknown" for o in obs)
    rules = collections.Counter(o.get("rule_id") or "" for o in obs)
    order = ["critical", "high", "medium", "low", "info", "unknown"]
    counts = ", ".join(f"{sev[s]} {s}" for s in order if sev[s]) or "no results"
    lines = [f"DIGEST ({name}): {len(obs)} result(s): {counts}"]
    if rules and obs:
        lines.append("top rules: " + "; ".join(f"{r} x{n}" for r, n in rules.most_common(5)))
    rank = {s: i for i, s in enumerate(order)}
    for o in sorted(obs, key=lambda o: rank.get(o.get("severity"), 9))[:8]:
        lines.append(f"- [{o.get('severity')}] {o.get('rule_id')} at {o.get('location')}: {o.get('title', '')[:120]}")
    if len(obs) > 8:
        lines.append(f"… {len(obs) - 8} more in the evidence file")
    if errors:
        lines.append(f"parser notes: {len(errors)} (see the evidence file)")
    return "\n".join(lines)


def _nmap(body):
    hosts = re.findall(r"^Nmap scan report for (.+)$", body, re.M)
    ports = re.findall(r"^(\d+/(?:tcp|udp))\s+(open\S*)\s+(\S+)(?:\s+(.*))?$", body, re.M)
    done = re.search(r"^Nmap done: .*$", body, re.M)
    if not hosts and not done:
        return None   # no scan in the output (it failed): show the output itself
    lines = [f"DIGEST (nmap): {len(hosts)} host(s), {len(ports)} open port(s)"
             + (f"; {done.group(0)}" if done else "")]
    lines += [f"host {h}" for h in hosts[:10]]
    lines += [f"{p} {st} {svc} {(ver or '').strip()}".rstrip() for p, st, svc, ver in ports[:30]]
    return "\n".join(lines)


SQLMAP_KEEP = re.compile(r"(Parameter: |^\s+Type: |^\s+Title: |^\s+Payload: |back-end DBMS|is vulnerable|"
                         r"appears to be .*injectable|might be injectable|do not appear to be injectable|"
                         r"\[CRITICAL\]|identified the following injection point|fetched data logged|"
                         r"^Database: |^Table: |\[\d+ entries\]|available databases)", re.I)


def _sqlmap(body):
    keep = [l.rstrip() for l in body.split("\n") if SQLMAP_KEEP.search(l)]
    injectable = any(re.search(r"Parameter: |identified the following injection point", l) for l in keep)
    clean = any("do not appear to be injectable" in l for l in keep)
    if not injectable and not clean:
        return None   # no verdict yet (it failed, or stopped early): show the output itself
    verdict = "injection point(s) found" if injectable else "no injection found"
    return "\n".join([f"DIGEST (sqlmap): {verdict}"] + keep[:40])


NUCLEI_RX = re.compile(r"^\[([^\]]+)\] \[([^\]]+)\] \[(info|low|medium|high|critical|unknown)\] (\S+)(.*)$", re.M)


def _nuclei(body):
    hits = NUCLEI_RX.findall(body)
    if not hits:   # JSON lines (-jsonl)
        for line in body.split("\n"):
            try:
                d = json.loads(line)
            except ValueError:
                continue
            if isinstance(d, dict) and "template-id" in d:
                hits.append((d["template-id"], d.get("type", ""), (d.get("info") or {}).get("severity", "unknown"),
                             d.get("matched-at", ""), ""))
    sev = collections.Counter(h[2] for h in hits)
    order = ["critical", "high", "medium", "low", "info", "unknown"]
    lines = [f"DIGEST (nuclei): {len(hits)} match(es): " + (", ".join(f"{sev[s]} {s}" for s in order if sev[s])
                                                             or "none")]
    rank = {s: i for i, s in enumerate(order)}
    for t, kind, s, url, extra in sorted(hits, key=lambda h: rank.get(h[2], 9))[:15]:
        lines.append(f"- [{s}] {t} {url}{extra[:80]}")
    return "\n".join(lines)


def digest(tool, args, out):
    """A digest of a tool result, or None when the kit has no reader for it. Returns (text, kind): kind "json" means
    the digest replaces the output, "text" means it goes on top of the head and tail."""
    if tool not in ("kali_run", "analyze_source"):
        return None, None
    body = _body(out)
    cmd = str((args or {}).get("command") or (args or {}).get("tool") or "")
    first = re.split(r"[\s;|&]+", cmd.strip())[0].split("/")[-1] if cmd.strip() else ""
    if body[:1] in "{[":
        try:
            parsed = observations.parse("output.json", body)
        except Exception:  # noqa: BLE001 - a digest is a convenience, the output is still shown
            parsed = {"parser": None}
        if parsed.get("parser"):
            return _obs_digest(parsed["parser"], parsed["observations"], parsed.get("errors")), "json"
    if first == "sqlmap" or "sqlmap identified" in body or "[CRITICAL] all tested parameters" in body:
        d = _sqlmap(body)
        return (d, "text") if d else (None, None)
    if first == "nmap" or "Nmap scan report for" in body:
        d = _nmap(body)
        return (d, "text") if d else (None, None)
    if first == "nuclei" or NUCLEI_RX.search(body):
        return _nuclei(body), "text"
    return None, None


def shown(tool, args, out, path=None):
    """What the model sees of one tool result."""
    d, kind = digest(tool, args, out)
    ev = EVIDENCE_RX.search(out)
    where = (ev.group(1) if ev else None) or path
    if kind == "json":
        head = out.split("\n", 1)[0] if _exit(out) is not None else ""
        return "\n".join(x for x in (head, d, f"(full output: {where})" if where else "") if x)
    if kind == "text":
        return d + "\n\n" + clip(out, 1500, 1500, where)
    return clip(out, HEAD, TAIL, where)


def one_line(tool, args, out):
    """One line for an old result: the tool, what it ran, the exit status, the digest's summary, the evidence."""
    what = str((args or {}).get("command") or (args or {}).get("url") or (args or {}).get("query")
               or (args or {}).get("path") or (args or {}).get("title") or "")
    what = re.sub(r"\s+", " ", what)[:160]
    ex = _exit(out)
    d, _ = digest(tool, args, out)
    summary = d.split("\n", 1)[0] if d else re.sub(r"\s+", " ", _body(out))[:160]
    ev = EVIDENCE_RX.search(out)
    parts = [f"{tool} {what}".strip(), f"exit={ex}" if ex is not None else None, summary,
             f"full output: {ev.group(1)}" if ev else None]
    return "[shrunk] " + " | ".join(p for p in parts if p)
