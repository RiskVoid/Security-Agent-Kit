"""What a confirmed finding quotes, compared with its evidence (epic #52, issue #41).

When the planner confirms a finding, every quote in its description and reproduction (inline code and code-block
lines) is looked up in the cited evidence files and the source files it refers to, and every
/src/<repo>/<file>:<line> must point at a line that exists.

  A source reference that doesn't exist   the confirmation is refused. It is a fact with one fix (the right file
                                          or line), and in 48 saved benchmark runs it was never the reason.
  A quote that isn't in the evidence      the finding is confirmed and the quotes are listed in what the tool
                                          returns, in get_finding and as a warning before delivery.

Missing quotes were a refusal until 2026-11-16. In 48 saved benchmark runs that refusal came 79 times, in 23 of the
runs, and named 76 different texts. A reading of 60 of them found example attack inputs (`' OR 1=1 --`,
`../../../etc/passwd`), names of protections that are missing (`@login_required`), data flows written with arrows,
and lines of the code under review that the finding cited by another file. It found no response that the target
clearly never gave, which is what the check was built to catch. Each refusal cost the planner a turn or more, one
run that ended with 0 of 6 found had 25 of them, and the fix the planner was given ("no backticks") makes the
report worse. The disprove-only validator (validator.py) reads the same
files with judgement and is the guard against a finding whose evidence doesn't show what it says.

Not quotes, so not looked up: commands (a line or span that starts with a program or "$ "), spans shorter than
MIN_QUOTE characters, and spans with placeholders (<id>, {{cred:NAME}}, ...). Whitespace is normalised and HTML
entities are decoded on both sides; a redaction marker ([REDACTED ...]) and a credential reference ({{cred:NAME}})
in a quote match any text in the evidence.

Run as a script to replay past runs: python3 harness/quotecheck.py <engagements dir> [--json]
lists the confirmed findings with quotes that are not in their evidence.
"""
import html, json, os, re, sys, urllib.parse

MIN_QUOTE = 6
GAP = 24   # characters allowed between the words of a paraphrased quote
MAX_READ = 5_000_000
SRC = os.environ.get("RV_SRC", "/src")
WORK = "/work"

INLINE = re.compile(r"(?<!`)`([^`\n]+)`(?!`)")
BLOCK = re.compile(r"```([^\n]*)\n(.*?)```", re.S)
CODE_LANGS = ("bash", "sh", "shell", "console", "zsh", "python", "py", "javascript", "js", "powershell", "ps1")
NAME = re.compile(r"^(?:[A-Za-z_$][\w.$-]*|/[\w./%~-]*|https?://\S+)$")   # a name, a path or a URL: not a quote
SHELL = re.compile(r"\$\(|^\s*(?:for|do|done|if|then|fi|while|export)\b|^\s*-{1,2}\w|\\\s*$|^\s*[A-Z_]+=")
FILE_REF = re.compile(r"^[\w./-]+\.\w+:\d+(?:-\d+)?$")   # settings.py:4: a reference, not a quote
SRC_REF = re.compile(r"(/src/[^\s:`'\"()<>]+):(\d+)(?:-(\d+))?")
WILD = re.compile(r"\[REDACTED[^\]]*\]|\{\{cred:[A-Za-z0-9_.-]+\}\}|\$RV_CRED_[A-Z0-9_]+")
PLACEHOLDER = re.compile(r"<[A-Za-z_][\w -]{0,30}>|\.\.\.|…|\{\{(?!cred:)[^}]*\}\}")
COMMANDS = ("curl", "wget", "sqlmap", "nmap", "nuclei", "ffuf", "http", "httpx", "python", "python3", "bash", "sh",
            "rv-llm", "semgrep", "gitleaks", "trufflehog", "bandit", "dalfox", "nikto", "hydra", "jwt_tool",
            "schemathesis", "gobuster", "feroxbuster", "whatweb", "sudo", "echo", "cat", "grep", "jq", "openssl",
            "nc", "ncat", "ssh", "mysql", "psql", "sqlite3", "node", "php", "ruby", "go", "docker", "kubectl",
            "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")


def _norm(text):
    return re.sub(r"\s+", " ", html.unescape(text)).strip()


def _is_command(span):
    s = span.strip()
    if s.startswith("$ ") or s.startswith("# ") or SHELL.search(s):
        return True
    first = re.split(r"\s+", s, maxsplit=1)[0]
    return first in COMMANDS and len(s.split()) > 1


def quotes(text):
    """The quoted strings of a finding's text that must be in its evidence."""
    out = []
    text = text or ""
    for lang, block in BLOCK.findall(text):
        lines = block.split("\n")
        first = next((l for l in lines if l.strip()), "")
        if lang.strip().lower() in CODE_LANGS or _is_command(first):
            continue   # a script or a command to run, not something the target returned
        cont = False
        for line in lines:   # a command's continuation lines are not quotes either
            if not cont:
                out.append(line)
            cont = line.rstrip().endswith("\\")
    out += INLINE.findall(BLOCK.sub("", text))
    keep = []
    for q in out:
        q = q.strip()
        if len(q) < MIN_QUOTE or _is_command(q) or PLACEHOLDER.search(q) or SRC_REF.fullmatch(q) or NAME.match(q) \
                or FILE_REF.match(q):
            continue
        if q not in keep:
            keep.append(q)
    return keep


def _pattern(quote, loose=False):
    """A quote as a regex over normalised text: its wildcards match anything short."""
    parts = WILD.split(_loose(quote) if loose else _norm(quote))
    return re.compile(r".{0,200}?".join(re.escape(p) for p in parts), re.S)


def _loose(text):
    """Without whitespace, quote marks and case: `"role":"admin"` matches `"role": "admin"`."""
    return re.sub(r"[\s\"']+", "", text).lower()


def _near(quote):
    """A paraphrase of the evidence still passes: the quote's words (3+ characters), in order, each within GAP
    characters of the last. A quote of one word (a hash, a token, a flag) must match exactly."""
    words = re.findall(r"[a-z0-9_]{3,}", _loose(WILD.sub(" ", quote)))
    if len(words) < 2:
        return None
    return re.compile(f".{{0,{GAP}}}?".join(re.escape(w) for w in words), re.S)


def found(quote, hay):
    """Is a quote in the evidence text? hay: (normalised, loose) from corpus()."""
    if _pattern(quote).search(hay[0]) or _pattern(quote, True).search(hay[1]):
        return True
    near = _near(quote)
    return bool(near and near.search(hay[1]))


def evidence_path(engagement, path):
    """A cited evidence path as a file in the engagement folder, or None."""
    p = str(path or "").strip()
    p = re.split(r"\s", p, maxsplit=1)[0].split(":")[0] if p else ""   # "<path> (what it shows)", "<path>:<line>"
    if not p:
        return None
    base = os.path.realpath(os.path.join(WORK, engagement))
    if p.startswith("/work/"):   # paths as the tools print them, wherever the engagements are mounted
        p = os.path.join(WORK, p[len("/work/"):])
    full = p if os.path.isabs(p) else os.path.join(base, p)
    full = os.path.realpath(full)
    return full if full.startswith(base + os.sep) and os.path.isfile(full) else None


def _read(path):
    with open(path, "rb") as f:
        return f.read(MAX_READ).decode("utf-8", "replace")


def src_problems(text):
    """/src/<repo>/<file>:<line> references that don't point at an existing line. Unchecked when /src isn't here."""
    if not os.path.isdir(SRC):
        return []
    out = []
    for path, a, b in SRC_REF.findall(text or ""):
        full = os.path.realpath(os.path.join(SRC, path[len("/src/"):]))
        if not full.startswith(os.path.realpath(SRC) + os.sep) or not os.path.isfile(full):
            out.append(f"{path}:{a} (no such file)")
            continue
        n = _read(full).count("\n") + 1
        if int(b or a) > n or int(a) < 1:
            out.append(f"{path}:{a}{'-' + b if b else ''} (the file has {n} lines)")
    return out


def corpus(engagement, evidence, text=""):
    """The text a finding's quotes may come from (its evidence files and the source files it cites), as
    (normalised, loose)."""
    parts = []
    for e in evidence or []:
        f = evidence_path(engagement, e)
        if f:
            parts.append(_read(f))
    if os.path.isdir(SRC):
        for path, _, _ in SRC_REF.findall(text or ""):
            full = os.path.realpath(os.path.join(SRC, path[len("/src/"):]))
            if full.startswith(os.path.realpath(SRC) + os.sep) and os.path.isfile(full):
                parts.append(_read(full))
        for e in evidence or []:   # evidence can cite a source line too
            m = SRC_REF.match(str(e))
            if m:
                full = os.path.realpath(os.path.join(SRC, m.group(1)[len("/src/"):]))
                if full.startswith(os.path.realpath(SRC) + os.sep) and os.path.isfile(full):
                    parts.append(_read(full))
    text = "\n".join(parts)
    try:   # requests are often logged URL-encoded: id=1%27%20UNION... is the same quote as id=1' UNION...
        text += "\n" + urllib.parse.unquote_plus(text)
    except Exception:  # noqa: BLE001
        pass
    norm = _norm(text)
    return norm, _loose(norm)


def _list(evidence):
    if isinstance(evidence, str):
        try:
            evidence = json.loads(evidence)
        except ValueError:
            evidence = [evidence]
    return evidence or []


def unverified(engagement, description, reproduction, evidence):
    """The quotes of a finding's text that are in none of its cited evidence or source files."""
    text = f"{description or ''}\n{reproduction or ''}"
    qs = quotes(text)
    if not qs:
        return []
    hay = corpus(engagement, _list(evidence), text)
    return [q for q in qs if not found(q, hay)]


def problems(engagement, description, reproduction, evidence):
    """Everything the check has to say about a finding, as readable strings: source references that don't exist
    (these refuse a confirmation) and quotes that aren't in its evidence (these are listed, not refused)."""
    return src_problems(f"{description or ''}\n{reproduction or ''}") + [
        f"`{q[:120]}` is not in the cited evidence" for q in unverified(engagement, description, reproduction, evidence)]


def refusal(engagement, description, reproduction, evidence=None):
    """The REFUSED message for a confirmation, or None. Only a source reference that doesn't exist refuses."""
    p = src_problems(f"{description or ''}\n{reproduction or ''}")
    if not p:
        return None
    return ("status=confirmed refused: the finding refers to source that isn't there. " + "; ".join(p[:8])
            + (f"; and {len(p) - 8} more" if len(p) > 8 else "") + ". Give the file and line as they are under /src.")


QUOTES_NOTE = ("These texts in backticks are not in the cited evidence. An example input, or a protection named as "
               "missing, needs nothing. If one is something the target returned or a line of its code, add the file "
               "that has it to evidence when you next update this finding. Go on with the plan.")


def flag(engagement, description, reproduction, evidence, limit=8):
    """What a confirmation returns about quotes that aren't in the evidence, or None when all are."""
    q = unverified(engagement, description, reproduction, evidence)
    if not q:
        return None
    return {"not_in_evidence": [x[:120] for x in q[:limit]], **({"more": len(q) - limit} if len(q) > limit else {}),
            "note": QUOTES_NOTE}


def replay(root):
    """Confirmed findings in every engagement under root that this check would refuse."""
    import sqlite3
    global WORK
    WORK = root
    out = []
    for eng in sorted(os.listdir(root)):
        for name in (os.path.join(root, eng, ".rv", "findings.db"), os.path.join(root, eng, "findings.db")):
            if os.path.isfile(name):
                break
        else:
            continue
        con = sqlite3.connect(f"file:{name}?mode=ro", uri=True)
        con.row_factory = sqlite3.Row
        try:
            rows = con.execute("SELECT id, title, description, reproduction, evidence FROM findings "
                               "WHERE status = 'confirmed'").fetchall()
        except sqlite3.Error:
            continue
        for r in rows:
            p = problems(eng, r["description"], r["reproduction"], r["evidence"])
            out.append({"engagement": eng, "finding": r["id"], "title": r["title"], "flagged": bool(p),
                        "refused": bool(refusal(eng, r["description"], r["reproduction"])), "problems": p})
    return out


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    rows = replay(os.path.expanduser(sys.argv[1]))
    if "--json" in sys.argv:
        print(json.dumps(rows, indent=1))
    else:
        for r in rows:
            if r["flagged"]:
                print(f"{r['engagement']} {r['finding']} {r['title'][:60]}: " + "; ".join(r["problems"][:3]))
        print(f"{sum(r['flagged'] for r in rows)} of {len(rows)} confirmed finding(s) have quotes or source references "
              f"that are not in their evidence; {sum(r['refused'] for r in rows)} would be refused (a source "
              "reference that doesn't exist)")
