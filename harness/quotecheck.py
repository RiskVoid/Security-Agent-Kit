"""What a confirmed finding quotes must be in its evidence (epic #52, issue #41).

The cheapest guard against a hallucinated finding: an agent that confirms a finding quoting a response, a header or
a line of code that isn't in the evidence it cites. When the planner confirms a finding, every quote in its
description and reproduction (inline code and code-block lines) must be found in the cited evidence files, and
every /src/<repo>/<file>:<line> must point at a line that exists. Otherwise the confirmation is refused and the
missing quotes are named.

Not quotes, so not checked: commands (a line or span that starts with a program or "$ "), spans shorter than
MIN_QUOTE characters, and spans with placeholders (<id>, {{cred:NAME}}, ...). Whitespace is normalised and HTML
entities are decoded on both sides; a redaction marker ([REDACTED ...]) and a credential reference ({{cred:NAME}})
in a quote match any text in the evidence.

Run as a script to replay past runs: python3 harness/quotecheck.py <engagements dir> [--json]
lists the confirmed findings it would have refused.
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


def problems(engagement, description, reproduction, evidence):
    """What a confirmed finding quotes that isn't in its evidence, as readable strings (empty: it may be confirmed)."""
    if isinstance(evidence, str):
        try:
            evidence = json.loads(evidence)
        except ValueError:
            evidence = [evidence]
    text = f"{description or ''}\n{reproduction or ''}"
    out = src_problems(text)
    qs = quotes(text)
    if not qs:
        return out
    hay = corpus(engagement, evidence, text)
    for q in qs:
        if not found(q, hay):
            out.append(f"`{q[:120]}` is not in the cited evidence")
    return out


def refusal(engagement, description, reproduction, evidence):
    """The REFUSED message for a confirmation, or None."""
    p = problems(engagement, description, reproduction, evidence)
    if not p:
        return None
    return ("status=confirmed refused: the finding quotes text its evidence doesn't contain. " + "; ".join(p[:8])
            + (f"; and {len(p) - 8} more" if len(p) > 8 else "") + ". Quote the evidence exactly (copy from the "
            "evidence file), cite the evidence file that has it, or mark the text as a description rather than a "
            "quote (no backticks).")


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
            out.append({"engagement": eng, "finding": r["id"], "title": r["title"], "refused": bool(p),
                        "problems": p})
    return out


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    rows = replay(os.path.expanduser(sys.argv[1]))
    if "--json" in sys.argv:
        print(json.dumps(rows, indent=1))
    else:
        for r in rows:
            if r["refused"]:
                print(f"{r['engagement']} {r['finding']} {r['title'][:60]}: " + "; ".join(r["problems"][:3]))
        print(f"{sum(r['refused'] for r in rows)} of {len(rows)} confirmed finding(s) would be refused")
