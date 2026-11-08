"""Loads kali-mcp/tiers.yaml (tool tiers, subcommand rules, rate flags, strict mode) and checks it.

PyYAML is used when it is installed. Otherwise a small parser reads the subset of YAML the file uses (block
mappings and lists, one-line {a: b} and [a, b], quoted and plain scalars, comments) and refuses anything else,
so a file that loads here means the same under any YAML parser.
"""
import json, re

TIERS = ("passive", "active", "intrusive")
KEYS = {"intrusive", "active", "subcommands", "rate_flags", "strict"}


class ConfigError(ValueError):
    pass


# ---------------------------------------------------------------- YAML subset
def _mask(s):
    """s with the inside of quoted strings blanked out (same length), so # [ ] { } in them are ignored."""
    out, i = list(s), 0
    while i < len(s):
        ch = s[i]
        if ch in "'\"" and (i == 0 or s[i - 1] in " \t[{,:-"):
            j = i + 1
            while j < len(s):
                if ch == "'" and s[j] == "'" and s[j + 1:j + 2] == "'":
                    j += 2
                    continue
                if ch == '"' and s[j] == "\\":
                    j += 2
                    continue
                if s[j] == ch:
                    break
                j += 1
            for k in range(i + 1, min(j, len(s))):
                out[k] = "x"
            i = j + 1
        else:
            i += 1
    return "".join(out)


def _strip_comment(line):
    m = re.search(r"(^|[ \t])#", _mask(line))
    return line[:m.start()] if m else line


def _flow(s, n):
    """Parse a one-line value: [list], {map}, quoted or plain scalar. Returns (value, rest)."""
    s = s.lstrip()
    if s.startswith(("[", "{")):
        close, out = ("]", []) if s[0] == "[" else ("}", {})
        s = s[1:].lstrip()
        while True:
            if s.startswith(close):
                return out, s[1:]
            if isinstance(out, dict):
                m = re.match(r"([A-Za-z0-9_.+-]+)\s*:\s", s)
                if not m:
                    raise ConfigError(f"line {n}: expected 'key: value' in {{...}}")
                key, (val, s) = m.group(1), _flow(s[m.end():], n)
                out[key] = val
            else:
                val, s = _flow(s, n)
                out.append(val)
            s = s.lstrip()
            if s.startswith(","):
                s = s[1:].lstrip()
            elif not s.startswith(close):
                raise ConfigError(f"line {n}: expected ',' or '{close}'")
    if s.startswith("'"):
        m = re.match(r"'((?:[^']|'')*)'", s)
        if not m:
            raise ConfigError(f"line {n}: unterminated quote")
        return m.group(1).replace("''", "'"), s[m.end():]
    if s.startswith('"'):
        m = re.match(r'"((?:[^"\\]|\\.)*)"', s)
        if not m:
            raise ConfigError(f"line {n}: unterminated quote")
        return json.loads(m.group(0)), s[m.end():]
    m = re.match(r"[^,\]}]*", s)
    word = m.group(0).strip()
    if re.search(r"[\[\]{}'\"&*!|>%@`]", word[:1]) or ": " in word:
        raise ConfigError(f"line {n}: unsupported YAML: {word!r} (quote it)")
    if word in ("null", "~", ""):
        val = None
    elif word in ("true", "false"):
        val = word == "true"
    elif re.fullmatch(r"-?\d+", word):
        val = int(word)
    else:
        val = word
    return val, s[m.end():]


def _scalar(s, n):
    val, rest = _flow(s, n)
    if rest.strip():
        raise ConfigError(f"line {n}: unexpected text after the value: {rest.strip()!r}")
    return val


def _depth(s):
    """Open [ and { minus closed ones, outside quotes."""
    m = _mask(s)
    return m.count("[") + m.count("{") - m.count("]") - m.count("}")


KEY = re.compile(r"([A-Za-z0-9_.+-]+):(?:\s+(.*))?$")


def parse_yaml(text):
    lines = []
    for n, raw in enumerate(text.splitlines(), 1):
        if "\t" in raw[:len(raw) - len(raw.lstrip())]:
            raise ConfigError(f"line {n}: indent with spaces, not tabs")
        s = _strip_comment(raw).rstrip()
        if s.strip():
            lines.append([len(s) - len(s.lstrip()), s.strip(), n])
    # a value that continues on the next lines (a [list] or {map} split over lines) is joined first
    joined = []
    for ln in lines:
        prev = joined[-1] if joined else None
        if prev and _depth(prev[1]) > 0:
            prev[1] += " " + ln[1]
        else:
            joined.append(ln)
    lines, pos = joined, 0

    def block(indent):
        nonlocal pos
        if lines[pos][1].startswith("- ") or lines[pos][1] == "-":
            out = []
            while pos < len(lines) and lines[pos][0] == indent and (lines[pos][1].startswith("- ") or lines[pos][1] == "-"):
                ind, s, n = lines[pos]
                rest = s[1:].lstrip()
                if not rest:
                    raise ConfigError(f"line {n}: put the item on the same line as '-'")
                if KEY.match(rest):  # "- key: value" starts a mapping indented to where the key is
                    lines[pos] = [ind + len(s) - len(rest), rest, n]
                    out.append(block(lines[pos][0]))
                else:
                    pos += 1
                    out.append(_scalar(rest, n))
            return out
        out = {}
        while pos < len(lines) and lines[pos][0] == indent:
            ind, s, n = lines[pos]
            m = KEY.match(s)
            if not m:
                raise ConfigError(f"line {n}: expected 'key: value'")
            key, val = m.group(1), m.group(2)
            if key in out:
                raise ConfigError(f"line {n}: '{key}' appears twice")
            pos += 1
            if val:
                out[key] = _scalar(val, n)
            elif pos < len(lines) and (lines[pos][0] > indent or
                                       (lines[pos][0] == indent and lines[pos][1].startswith("- "))):
                out[key] = block(lines[pos][0])
            else:
                out[key] = None
        return out

    if not lines:
        return None
    if lines[0][0] != 0:
        raise ConfigError(f"line {lines[0][2]}: the file must start at column 1")
    data = block(0)
    if pos < len(lines):
        raise ConfigError(f"line {lines[pos][2]}: unexpected indentation")
    return data


def load_yaml(text):
    try:
        import yaml
    except ImportError:
        return parse_yaml(text)
    return yaml.safe_load(text)


# ---------------------------------------------------------------- tiers
def _names(v, where):
    if not isinstance(v, list) or not all(isinstance(x, str) and re.fullmatch(r"[A-Za-z0-9_.+-]+", x) for x in v):
        raise ConfigError(f"{where}: expected a list of program names")
    return v


def _tier(v, where):
    if v not in TIERS:
        raise ConfigError(f"{where}: tier must be one of {', '.join(TIERS)}, not {v!r}")
    return v


def _rules(v, where):
    out = []
    for i, r in enumerate(v or []):
        w = f"{where}[{i + 1}]"
        if not isinstance(r, dict) or set(r) != {"program", "match", "tier"}:
            raise ConfigError(f"{w}: expected program, match and tier")
        try:
            rx = re.compile(str(r["match"]))
        except re.error as e:
            raise ConfigError(f"{w}: bad regular expression: {e}") from None
        out.append((_names([r["program"]], w)[0], rx, _tier(r["tier"], w)))
    return out


def build(data, source="tiers.yaml"):
    """The checked policy tables from parsed YAML."""
    if not isinstance(data, dict):
        raise ConfigError(f"{source}: expected a mapping at the top")
    extra = set(data) - KEYS
    if extra:
        raise ConfigError(f"{source}: unknown keys {sorted(extra)} (expected {sorted(KEYS)})")
    intrusive = set(_names(data.get("intrusive") or [], f"{source}: intrusive"))
    active = set(_names(data.get("active") or [], f"{source}: active"))
    both = intrusive & active
    if both:
        raise ConfigError(f"{source}: {sorted(both)} listed as both intrusive and active")
    rate = {}
    for prog, spec in (data.get("rate_flags") or {}).items():
        w = f"{source}: rate_flags.{prog}"
        if not isinstance(spec, dict) or not spec.get("flags") or set(spec) - {"flags", "format", "after"}:
            raise ConfigError(f"{w}: expected {{flags: [...]}} with optional format and after")
        flags = spec["flags"]
        if not isinstance(flags, list) or not all(isinstance(f, str) and f.startswith("-") for f in flags):
            raise ConfigError(f"{w}: flags must be a list of options starting with '-'")
        fmt = str(spec.get("format") or "{}")
        if fmt.count("{}") != 1:
            raise ConfigError(f"{w}: format must contain {{}} once")
        rate[prog] = {"flags": flags, "format": fmt, "after": spec.get("after")}
    strict = data.get("strict") or {}
    if set(strict) - {"interpreters", "interpreter_tier", "subcommands"}:
        raise ConfigError(f"{source}: strict: unknown keys {sorted(set(strict) - {'interpreters', 'interpreter_tier', 'subcommands'})}")
    return {
        "intrusive": intrusive, "active": active,
        "subcommands": _rules(data.get("subcommands"), f"{source}: subcommands"),
        "rate_flags": rate,
        "interpreters": set(_names(strict.get("interpreters") or [], f"{source}: strict.interpreters")),
        "interpreter_tier": _tier(strict.get("interpreter_tier", "intrusive"), f"{source}: strict.interpreter_tier"),
        "strict_subcommands": _rules(strict.get("subcommands"), f"{source}: strict.subcommands"),
    }


def load(path):
    with open(path) as f:
        return build(load_yaml(f.read()), path)
