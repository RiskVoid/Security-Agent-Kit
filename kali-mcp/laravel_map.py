"""Laravel application map (RW-012).

Reads a Laravel source tree without running any of it (no PHP, no Artisan, no Composer: nothing of the client's
code executes) and relates routes to their effective middleware, controllers, Form Requests, policies and gates,
Eloquent models with their mass-assignment settings and tenant scopes, views, jobs and I/O. Every item carries its
source location, and each derived relationship says how it was derived and how confident the map is.

  framework     Laravel and PHP versions from composer.json / composer.lock
  routes        method, URI, name, action, effective middleware (file group + groups + route), route-level `can`
  controllers   per method: bound models, Form Request, authorization calls, how request input is used, sinks
  models        table, $fillable / $guarded, columns (from migrations), global scopes (tenant isolation)
  policies      policy class, model, abilities; Form Requests with their authorize() and rules
  sinks         raw SQL with variables, unescaped Blade output, file downloads, outbound HTTP, mail, commands
  leads         candidate issues with the reasoning (to verify at runtime, never findings by themselves)
  controls      protections the map found (route `can`, authorize calls, tenant scopes, validated input): what
                must not be reported as a flaw without runtime evidence
  gaps          what a static map can't see (dynamic routes, packages, macros, service providers' logic)
  build         the source digest (rvkit source digest v1) and, when given, the deployed build to compare

A runtime route export (`php artisan route:list --json` from the client, or the PHP profile, RW-013) can be
compared with the static routes: routes only one side has are listed.
"""
import hashlib, json, os, re

VERSION = 1
SKIP_DIRS = {"vendor", "node_modules", ".git", "storage", "cache", ".idea", ".vscode"}
DIGEST_PARTS = ("app", "bootstrap/app.php", "bootstrap/providers.php", "config", "database", "resources", "routes",
                "composer.json", "composer.lock")
VERBS = ("get", "post", "put", "patch", "delete", "options", "any", "match")
SENSITIVE_COLUMNS = re.compile(r"^(role|roles|is_[a-z_]*admin|[a-z_]*_admin|admin|organization_id|tenant_id|team_id|"
                               r"account_id|company_id|owner_id|user_id|permissions?|api_token|password|"
                               r"email_verified_at|is_verified|verified|balance|credit[s]?|plan|status)$")
MAX_FILES = 20000


# ---------------------------------------------------------------- PHP text helpers
def strip_comments(src):
    """Blank out comments (keeping newlines, so offsets and line numbers stay right). Strings are kept."""
    out, i, n = [], 0, len(src)
    while i < n:
        c = src[i]
        if c in "'\"":
            j = i + 1
            while j < n and src[j] != c:
                j += 2 if src[j] == "\\" else 1
            out.append(src[i:j + 1]); i = j + 1
        elif src.startswith("//", i) or (c == "#" and not src.startswith("#[", i)):
            j = src.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i)); i = j
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append(re.sub(r"[^\n]", " ", src[i:j])); i = j
        else:
            out.append(c); i += 1
    return "".join(out)


def _match(src, i, open_ch="(", close_ch=")"):
    """Index of the bracket closing the one at src[i] (strings skipped), or len(src)."""
    depth, n = 0, len(src)
    while i < n:
        c = src[i]
        if c in "'\"":
            j = i + 1
            while j < n and src[j] != c:
                j += 2 if src[j] == "\\" else 1
            i = j + 1
            continue
        if c == open_ch:
            depth += 1
        elif c == close_ch:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return n


def line_of(src, idx):
    return src.count("\n", 0, idx) + 1


def strings(args):
    return [m.group(2) for m in re.finditer(r"(['\"])((?:\\.|(?!\1).)*)\1", args)]


def class_refs(args):
    return re.findall(r"([A-Za-z_\\][A-Za-z0-9_\\]*)::class", args)


def _short(name):
    return (name or "").rstrip("\\").split("\\")[-1]


def _read(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


# ---------------------------------------------------------------- build identity
def source_digest(root):
    """rvkit source digest v1: sha256 over `sha256sum`-style lines of the app's own files (sorted by path, bytes),
    the same as `find <parts> -type f ! -name .gitignore | LC_ALL=C sort | xargs sha256sum | sha256sum`."""
    files = []
    for part in DIGEST_PARTS:
        p = os.path.join(root, part)
        if os.path.isfile(p):
            files.append(part)
        elif os.path.isdir(p):
            for dp, dirs, fns in os.walk(p):
                dirs.sort()
                for fn in fns:
                    if fn != ".gitignore":
                        files.append(os.path.relpath(os.path.join(dp, fn), root))
    if not files:
        return None
    h = hashlib.sha256()
    for rel in sorted(files, key=lambda s: s.encode()):
        with open(os.path.join(root, rel), "rb") as f:
            h.update(f"{hashlib.sha256(f.read()).hexdigest()}  {rel}\n".encode())
    return h.hexdigest()


# ---------------------------------------------------------------- framework
def framework(root):
    out = {"laravel": None, "php": None, "lock": False, "packages": 0, "evidence": []}
    try:
        cj = json.loads(_read(os.path.join(root, "composer.json")) or "{}")
    except ValueError:
        cj = {}
    req = cj.get("require") or {}
    out["laravel_constraint"] = req.get("laravel/framework")
    out["php"] = req.get("php")
    if cj:
        out["evidence"].append("composer.json")
    try:
        lock = json.loads(_read(os.path.join(root, "composer.lock")) or "{}")
    except ValueError:
        lock = {}
    if lock:
        out["lock"] = True
        pk = lock.get("packages") or []
        out["packages"] = len(pk) + len(lock.get("packages-dev") or [])
        for p in pk:
            if p.get("name") == "laravel/framework":
                out["laravel"] = str(p.get("version", "")).lstrip("v")
        notable = ("laravel/sanctum", "laravel/passport", "laravel/fortify", "laravel/jetstream", "laravel/breeze",
                   "spatie/laravel-permission", "stancl/tenancy", "spatie/laravel-multitenancy", "livewire/livewire",
                   "inertiajs/inertia-laravel", "filament/filament", "laravel/horizon", "laravel/telescope")
        out["notable_packages"] = sorted(p["name"] + " " + str(p.get("version", "")).lstrip("v")
                                         for p in pk if p.get("name") in notable)
        out["evidence"].append("composer.lock")
    return out


# ---------------------------------------------------------------- classes
def index_classes(root):
    """{short name: [class info]} for PHP classes under app/ (and database/ for completeness)."""
    idx, n = {}, 0
    for base in ("app",):
        for dp, dirs, fns in os.walk(os.path.join(root, base)):
            dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
            for fn in sorted(fns):
                if not fn.endswith(".php"):
                    continue
                n += 1
                if n > MAX_FILES:
                    return idx
                path = os.path.join(dp, fn)
                src = strip_comments(_read(path))
                ns = re.search(r"^\s*namespace\s+([^;]+);", src, re.M)
                for m in re.finditer(r"^\s*(?:final\s+|abstract\s+|readonly\s+)*(class|trait|interface|enum)\s+"
                                     r"(\w+)(?:\s+extends\s+([\w\\]+))?(?:\s+implements\s+([\w\\,\s]+))?\s*\{",
                                     src, re.M):
                    start = src.find("{", m.end() - 1)
                    end = _match(src, start, "{", "}")
                    uses = {_short(u.split(" as ")[0]): u.split(" as ")[0].strip()
                            for u in re.findall(r"^\s*use\s+([^;{]+);", src[:m.start()], re.M)}
                    info = {"name": m.group(2), "kind": m.group(1), "fqcn": (ns.group(1).strip() + "\\" if ns else "")
                            + m.group(2), "extends": _short(m.group(3)), "file": os.path.relpath(path, root),
                            "line": line_of(src, m.start()), "src": src, "body": (start, end), "uses": uses}
                    info["traits"] = [_short(t.strip()) for line in re.findall(r"^\s*use\s+([\w\\, ]+);",
                                                                              src[start + 1:end], re.M)
                                      for t in line.split(",")]
                    idx.setdefault(m.group(2), []).append(info)
    return idx


def methods(info):
    src, (start, end) = info["src"], info["body"]
    out = {}
    for m in re.finditer(r"(?:public|protected|private|static|\s)*function\s+(\w+)\s*\(", src[start:end]):
        a = start + m.end() - 1
        b = _match(src, a)
        brace = src.find("{", b)
        semi = src.find(";", b)
        if brace < 0 or (0 <= semi < brace):
            continue  # abstract or interface method
        e = _match(src, brace, "{", "}")
        out[m.group(1)] = {"params": src[a + 1:b], "body": src[brace + 1:e], "line": line_of(src, start + m.start()),
                           "offset": brace + 1}
    return out


def _array_prop(src, name):
    m = re.search(r"(?:protected|public|private)\s+(?:array\s+)?\$" + name + r"\s*=\s*\[", src)
    if not m:
        return None
    a = m.end() - 1
    return strings(src[a:_match(src, a, "[", "]")])


# ---------------------------------------------------------------- migrations
def tables(root):
    """{table: {"columns": [...], "file", "line"}} from Schema::create / Schema::table in migrations."""
    out = {}
    mdir = os.path.join(root, "database", "migrations")
    for fn in sorted(os.listdir(mdir)) if os.path.isdir(mdir) else []:
        if not fn.endswith(".php"):
            continue
        src = strip_comments(_read(os.path.join(mdir, fn)))
        for m in re.finditer(r"Schema::(create|table)\(\s*['\"](\w+)['\"]\s*,", src):
            a = src.find("{", m.end())
            body = src[a:_match(src, a, "{", "}")]
            t = out.setdefault(m.group(2), {"columns": [], "file": f"database/migrations/{fn}",
                                            "line": line_of(src, m.start())})
            for c in re.finditer(r"\$table->(\w+)\(\s*(?:['\"](\w+)['\"])?", body):
                kind, col = c.group(1), c.group(2)
                if kind == "id":
                    col = col or "id"
                elif kind == "timestamps":
                    t["columns"] += ["created_at", "updated_at"]; continue
                elif kind == "rememberToken":
                    col = "remember_token"
                elif kind in ("foreignIdFor",):
                    continue
                if col and col not in t["columns"] and kind not in ("index", "unique", "primary", "foreign",
                                                                     "dropColumn", "renameColumn"):
                    t["columns"].append(col)
    return out


def _table_of(model_name, src):
    m = re.search(r"\$table\s*=\s*['\"](\w+)['\"]", src)
    if m:
        return m.group(1)
    snake = re.sub(r"(?<!^)(?=[A-Z])", "_", model_name).lower()
    if snake.endswith("y") and not snake.endswith(("ay", "ey", "oy", "uy")):
        return snake[:-1] + "ies"
    return snake + ("es" if snake.endswith(("s", "x", "ch", "sh")) else "s")


# ---------------------------------------------------------------- routes
def _route_files(root):
    """[(file, group middleware, prefix)] as the framework loads them (Laravel 11+ bootstrap/app.php, or the
    RouteServiceProvider of older versions, or the defaults)."""
    boot = strip_comments(_read(os.path.join(root, "bootstrap", "app.php")))
    files = []
    if "withRouting" in boot:
        a = boot.find("(", boot.find("withRouting"))
        args = boot[a:_match(boot, a)]
        prefix = (re.search(r"apiPrefix\s*:\s*['\"]([^'\"]*)['\"]", args) or [None, "api"])[1]
        for key, mw, pre in (("web", ["web"], ""), ("api", ["api"], prefix)):
            m = re.search(key + r"\s*:\s*__DIR__\s*\.\s*['\"]([^'\"]+)['\"]", args)
            if m:
                files.append((os.path.normpath("bootstrap/" + m.group(1).lstrip("/")), mw, pre))
        h = re.search(r"health\s*:\s*['\"]([^'\"]+)['\"]", args)
        if h:
            files.append(("@health", [], h.group(1)))
        return files, "bootstrap/app.php withRouting"
    rsp = strip_comments(_read(os.path.join(root, "app", "Providers", "RouteServiceProvider.php")))
    if rsp:
        for m in re.finditer(r"Route::((?:\w+\([^)]*\)->)*)group\(\s*base_path\(['\"]([^'\"]+)['\"]\)", rsp):
            chain = m.group(1)
            mw = strings(" ".join(re.findall(r"middleware\(([^)]*)\)", chain)))
            pre = (strings(" ".join(re.findall(r"prefix\(([^)]*)\)", chain))) or [""])[0]
            files.append((m.group(2), mw, pre))
        if files:
            return files, "app/Providers/RouteServiceProvider.php"
    for f, mw, pre in (("routes/web.php", ["web"], ""), ("routes/api.php", ["api"], "api")):
        if os.path.isfile(os.path.join(root, f)):
            files.append((f, mw, pre))
    return files, "default route files (no withRouting or RouteServiceProvider found)"


def _chain(src, i):
    """Parse Route::a(...)->b(...)->c(...) starting at src[i] == 'R'. Returns ([(name, args, args_offset)], end)."""
    calls, j = [], i + len("Route::")
    m = re.match(r"\s*(\w+)\s*\(", src[j:])
    if not m:
        return [], j
    while m:
        a = j + m.end() - 1
        b = _match(src, a)
        calls.append((m.group(1), src[a + 1:b], a + 1))
        j = b + 1
        m = re.match(r"\s*->\s*(\w+)\s*\(", src[j:])
    return calls, j


def _closure_body(args, offset, src):
    k = re.search(r"\bfunction\s*\([^)]*\)\s*(?:use\s*\([^)]*\)\s*)?(?::\s*\w+\s*)?\{", args)
    if not k:
        return None
    a = offset + k.end() - 1
    return a + 1, _match(src, a, "{", "}")


def _action(args, ctx, uses):
    rest = args.split(",", 1)[1] if "," in args else ""
    arr = re.search(r"\[\s*([\w\\]+)::class\s*,\s*['\"](\w+)['\"]\s*\]", rest)
    if arr:
        return _short(uses.get(_short(arr.group(1)), arr.group(1))), arr.group(2)
    inv = re.match(r"\s*([\w\\]+)::class\s*\)?\s*$", rest)
    if inv:
        return _short(inv.group(1)), "__invoke"
    at = re.match(r"\s*['\"]([\w\\]+)@(\w+)['\"]", rest)
    if at:
        return _short(at.group(1)), at.group(2)
    if ctx.get("controller"):
        s = strings(rest)
        if s:
            return ctx["controller"], s[0]
    if re.search(r"\bfunction\b|\bfn\b", rest):
        return None, "closure"
    return None, None


RESOURCE = [("GET", "", "index"), ("GET", "/create", "create"), ("POST", "", "store"), ("GET", "/{p}", "show"),
            ("GET", "/{p}/edit", "edit"), ("PUT|PATCH", "/{p}", "update"), ("DELETE", "/{p}", "destroy")]


def _join(*parts):
    p = "/".join(s.strip("/") for s in parts if s and s.strip("/"))
    return "/" + p if p else "/"


def parse_routes(root):
    files, how = _route_files(root)
    routes = []

    def walk(src, start, end, ctx, rel, uses):
        i = start
        while True:
            i = src.find("Route::", i, end)
            if i < 0:
                return
            calls, j = _chain(src, i)
            if not calls:
                i += 7; continue
            name0, args0, off0 = calls[0]
            mw, pre, names, can, ctrl, wo = [], "", "", [], ctx.get("controller"), []
            for name, args, _ in calls:
                if name == "middleware":
                    mw += strings(args)
                elif name == "withoutMiddleware":
                    wo += strings(args)
                elif name == "prefix":
                    pre = (strings(args) or [""])[0]
                elif name in ("name", "as"):
                    names = (strings(args) or [""])[0]
                elif name == "can":
                    s = strings(args)
                    can.append("can:" + ",".join(s))
                elif name == "controller":
                    ctrl = _short(uses.get(_short((class_refs(args) or [""])[0]), (class_refs(args) or [""])[0]))
            group = next((c for c in calls if c[0] == "group"), None)
            if group:
                gargs, goff = group[1], group[2]
                if name0 == "group":  # Route::group(['middleware' => ..., 'prefix' => ...], function () {...})
                    arr = re.search(r"'middleware'\s*=>\s*(\[[^\]]*\]|'[^']*')", gargs)
                    mw += strings(arr.group(1)) if arr else []
                    p = re.search(r"'prefix'\s*=>\s*'([^']*)'", gargs)
                    pre = p.group(1) if p else pre
                body = _closure_body(gargs, goff, src)
                if body:
                    sub = {"middleware": ctx["middleware"] + mw + can, "prefix": _join(ctx["prefix"], pre),
                           "name": ctx["name"] + names, "controller": ctrl, "without": ctx["without"] + wo}
                    walk(src, body[0], body[1], sub, rel, uses)
                i = j; continue
            effective = [m for m in ctx["middleware"] + mw + can if m not in ctx["without"] + wo]
            base = {"file": rel, "line": line_of(src, i), "middleware": effective,
                    "name": (ctx["name"] + names) if names else None}
            if name0 in VERBS or name0 in ("redirect", "permanentRedirect", "view"):
                s = strings(args0)
                if name0 == "match":
                    methods_ = [x.upper() for x in strings(args0.split("]", 1)[0])]
                    s = strings(args0.split("]", 1)[1]) if "]" in args0 else s
                else:
                    methods_ = {"any": ["ANY"], "redirect": ["ANY"], "permanentRedirect": ["ANY"],
                                "view": ["GET"]}.get(name0, [name0.upper()])
                if not s:
                    i = j; continue
                ctl, meth = _action(args0, {**ctx, "controller": ctrl}, uses) if name0 in VERBS else \
                    (None, name0)
                routes.append({**base, "methods": methods_, "uri": _join(ctx["prefix"], s[0]),
                               "controller": ctl, "action": meth})
            elif name0 in ("resource", "apiResource"):
                s = strings(args0)
                cls = class_refs(args0)
                if s and cls:
                    ctl = _short(uses.get(_short(cls[0]), cls[0]))
                    param = re.sub(r"s$", "", s[0].split(".")[-1].replace("-", "_"))
                    only = [c[1] for c in calls if c[0] == "only"]
                    keep = strings(" ".join(only)) if only else None
                    skip = strings(" ".join(c[1] for c in calls if c[0] == "except"))
                    for verb, suffix, meth in RESOURCE:
                        if name0 == "apiResource" and meth in ("create", "edit"):
                            continue
                        if (keep is not None and meth not in keep) or meth in skip:
                            continue
                        routes.append({**base, "methods": verb.split("|"),
                                       "uri": _join(ctx["prefix"], s[0], suffix.replace("{p}", "{" + param + "}")),
                                       "controller": ctl, "action": meth, "name": f"{s[0]}.{meth}"})
            i = j

    for rel, mw, pre in files:
        if rel == "@health":  # withRouting(health: '/up'): the framework's health check route
            routes.append({"file": "bootstrap/app.php", "line": line_of(_read(os.path.join(root, "bootstrap", "app.php")),
                                                                        _read(os.path.join(root, "bootstrap",
                                                                                           "app.php")).find("health")),
                           "middleware": [], "name": None, "methods": ["GET"], "uri": _join(pre),
                           "controller": None, "action": "health"})
            continue
        src = strip_comments(_read(os.path.join(root, rel)))
        if not src:
            continue
        uses = {_short(u.split(" as ")[-1]): u.split(" as ")[0].strip()
                for u in re.findall(r"^\s*use\s+([^;{]+);", src, re.M)}
        walk(src, 0, len(src), {"middleware": list(mw), "prefix": _join(pre), "name": "", "controller": None,
                                "without": []}, rel, uses)
    for r in routes:
        r["params"] = re.findall(r"\{(\w+)\??\}", r["uri"])
        r["authenticated"] = any(m == "auth" or m.startswith("auth:") or m in ("auth.basic", "verified")
                                 or m.startswith("auth.") for m in r["middleware"])
        r["route_can"] = [m for m in r["middleware"] if m.startswith("can:")]
    return routes, how


# ---------------------------------------------------------------- controllers, models, policies, requests
AUTHZ_CALL = re.compile(r"\$this->authorize(?:Resource)?\(\s*['\"]?(\w*)|Gate::(?:authorize|allows|denies|check|any|"
                        r"inspect)\(\s*['\"]?(\w*)|->can(?:not)?\(\s*['\"](\w+)|abort_(?:if|unless)\([^;]*(?:->can|"
                        r"->is\w*|->role|isAdmin|hasRole)|\$request->user\(\)->can|Policy::")
INPUT_ALL = re.compile(r"\$request->(?:all|input|post|json)\(\s*\)|request\(\)->all\(\)|Request::all\(\)|"
                       r"\$request->except\(")
MASS = re.compile(r"(?:->|::)(update|create|fill|forceFill|forceCreate|firstOrCreate|updateOrCreate)\(\s*"
                  r"(\$request->(?:all|input|post|json)\(\s*\)|request\(\)->all\(\)|\$request->except\([^)]*\)|"
                  r"\$data|\$input|\$attributes)")
SINKS = [
    ("raw-sql", re.compile(r"DB::(?:select|statement|insert|update|delete|unprepared|raw)\(\s*(\"[^\"]*\$[^\"]*\"|"
                           r"'[^']*'\s*\.\s*\$|\$\w+)"), "a query built from a variable or an interpolated string"),
    ("raw-sql", re.compile(r"->(?:whereRaw|orWhereRaw|selectRaw|orderByRaw|havingRaw|groupByRaw|fromRaw)\(\s*"
                           r"(\"[^\"]*\$[^\"]*\"|'[^']*'\s*\.\s*\$|\$\w+)"),
     "a raw query fragment built from a variable"),
    ("file-download", re.compile(r"(?:Storage::(?:disk\([^)]*\)->)?(?:download|get|readStream|response)|"
                                 r"response\(\)->(?:download|file))\(\s*\$"), "a file chosen by a variable"),
    ("file-read", re.compile(r"\b(?:file_get_contents|fopen|readfile|include|require)(?:_once)?\s*\(\s*\$"),
     "a local file path from a variable"),
    ("command", re.compile(r"\b(?:exec|shell_exec|system|passthru|proc_open|popen)\s*\(|Process::(?:run|start)\(|"
                           r"new\s+Process\("), "an operating-system command"),
    ("deserialize", re.compile(r"\bunserialize\s*\("), "PHP unserialize"),
    ("eval", re.compile(r"\beval\s*\("), "PHP eval"),
    ("outbound-http", re.compile(r"Http::(?:get|post|put|patch|delete|send|withToken|withHeaders|acceptJson|asForm|"
                                 r"timeout|retry|baseUrl)\(|new\s+(?:\\?GuzzleHttp\\)?Client\(|curl_exec\("),
     "an outbound HTTP request (an external effect; SSRF if the URL comes from input)"),
    ("mail", re.compile(r"Mail::(?:to|raw|send|queue)\(|->notify\(|Notification::send\("),
     "mail or a notification (an external effect)"),
    ("redirect", re.compile(r"(?:redirect\(\)->away|Redirect::away)\(\s*\$"), "a redirect to a variable URL"),
]


def _sinks_in(text, base_src, offset, rel):
    found = []
    for kind, rx, what in SINKS:
        for m in rx.finditer(text):
            line = line_of(base_src, offset + m.start())
            code = base_src.splitlines()[line - 1].strip()[:200] if base_src else m.group(0)
            found.append({"kind": kind, "what": what, "file": rel, "line": line, "code": code})
    return found


def analyze(root):
    """The map, as a dict (no network, no execution)."""
    root = os.path.normpath(root)
    idx = index_classes(root)
    fw = framework(root)
    tbl = tables(root)
    routes, routing = parse_routes(root)

    def cls(name, kinds=None):
        for c in idx.get(_short(name), []):
            if not kinds or c["kind"] in kinds:
                return c
        return None

    # models
    models = {}
    scope_traits = {}
    for name, infos in idx.items():
        for c in infos:
            if c["kind"] == "trait" and re.search(r"addGlobalScope\(", c["src"][c["body"][0]:c["body"][1]]):
                scope_traits[name] = c
    for name, infos in idx.items():
        for c in infos:
            if c["kind"] != "class" or c["extends"] not in ("Model", "Authenticatable", "Pivot", "User") and \
                    not c["file"].startswith("app/Models/"):
                continue
            body = c["src"][c["body"][0]:c["body"][1]]
            scopes = []
            for t in c["traits"]:
                if t in scope_traits:
                    sc = scope_traits[t]
                    scopes.append({"via": f"trait {t}", "file": sc["file"], "line": sc["line"],
                                   "scope": (class_refs(sc["src"]) or re.findall(r"new\s+(\w+)", sc["src"]) or [""])[0]})
            for m in re.finditer(r"addGlobalScope\(\s*(?:new\s+(\w+)|['\"](\w+)['\"])", body):
                scopes.append({"via": "booted()", "file": c["file"], "line": line_of(c["src"], c["body"][0] +
                                                                                       m.start()),
                               "scope": m.group(1) or m.group(2)})
            for m in re.finditer(r"#\[ScopedBy\(\[?([^\]\)]*)", c["src"]):
                scopes.append({"via": "#[ScopedBy]", "file": c["file"], "line": line_of(c["src"], m.start()),
                               "scope": ",".join(_short(x) for x in class_refs(m.group(1)))})
            table = _table_of(name, body)
            fillable, guarded = _array_prop(body, "fillable"), _array_prop(body, "guarded")
            cols = (tbl.get(table) or {}).get("columns", [])
            if fillable is not None:
                assignable = [x for x in fillable]
                how = "$fillable"
            elif guarded is not None:
                assignable = [x for x in cols if x not in guarded] if "*" not in guarded else []
                how = "$guarded " + json.dumps(guarded)
            else:
                assignable, how = [], "default ($guarded = ['*']: nothing mass assignable)"
            models[name] = {"file": c["file"], "line": c["line"], "table": table, "columns": cols,
                            "fillable": fillable, "guarded": guarded, "assignable": assignable, "assignment": how,
                            "sensitive_assignable": [x for x in assignable if SENSITIVE_COLUMNS.match(x)],
                            "global_scopes": scopes, "tenant_scoped": bool(scopes),
                            "hidden": _array_prop(body, "hidden")}

    # policies and gates
    policies = []
    for name, infos in idx.items():
        for c in infos:
            if c["kind"] == "class" and (name.endswith("Policy") or c["file"].startswith("app/Policies/")):
                policies.append({"policy": name, "model": name[:-6] if name.endswith("Policy") else None,
                                 "file": c["file"], "line": c["line"], "abilities": sorted(methods(c)),
                                 "registered": "auto-discovery (app/Policies/<Model>Policy)"})
    gates = []
    for name, infos in idx.items():
        for c in infos:
            for m in re.finditer(r"Gate::(define|policy)\(\s*([^,]+),", c["src"]):
                gates.append({"kind": m.group(1), "subject": m.group(2).strip(), "file": c["file"],
                              "line": line_of(c["src"], m.start())})
                if m.group(1) == "policy":
                    model = _short((class_refs(m.group(2)) or [""])[0])
                    for p in policies:
                        if p["model"] == model or p["policy"] in m.group(0):
                            p["registered"] = f"Gate::policy in {c['file']}"

    # form requests
    requests_ = {}
    for name, infos in idx.items():
        for c in infos:
            if c["kind"] == "class" and c["extends"] == "FormRequest":
                ms = methods(c)
                auth = ms.get("authorize", {}).get("body", "")
                rules = ms.get("rules", {}).get("body", "")
                requests_[name] = {"file": c["file"], "line": c["line"],
                                   "authorize": "always true" if re.fullmatch(r"\s*return\s+true\s*;\s*", auth) else
                                   ("checks: " + re.sub(r"\s+", " ", auth.strip())[:160] if auth else "not defined"),
                                   "fields": re.findall(r"['\"]([\w.*]+)['\"]\s*=>", rules)}

    # controllers
    controllers, sinks = {}, []
    for name, infos in idx.items():
        for c in infos:
            if c["kind"] != "class" or not (name.endswith("Controller") or "/Controllers/" in c["file"]):
                continue
            for mname, m in methods(c).items():
                params = m["params"]
                bound = [{"model": t, "param": p} for t, p in re.findall(r"([A-Z]\w*)\s+\$(\w+)", params)
                         if t in models]
                freq = [t for t in re.findall(r"([A-Z]\w*)\s+\$\w+", params) if t in requests_]
                authz = []
                for a in AUTHZ_CALL.finditer(m["body"]):
                    close = m["body"].find(")", a.end())
                    call = m["body"][a.start():close + 1] if 0 <= close - a.end() < 120 else a.group(0)
                    authz.append({"call": re.sub(r"\s+", " ", call)[:100],
                                  "line": line_of(c["src"], m["offset"] + a.start())})
                inputs = []
                if INPUT_ALL.search(m["body"]):
                    inputs.append("all request input")
                if re.search(r"->validated\(|->safe\(", m["body"]):
                    inputs.append("validated input")
                if re.search(r"\$request->validate\(|Validator::make\(|\$this->validate\(", m["body"]):
                    inputs.append("validated inline")
                mass = [{"call": x.group(1), "with": x.group(2), "line": line_of(c["src"], m["offset"] + x.start()),
                         "code": c["src"].splitlines()[line_of(c["src"], m["offset"] + x.start()) - 1].strip()[:200]}
                        for x in MASS.finditer(m["body"])]
                s = _sinks_in(m["body"], c["src"], m["offset"], c["file"])
                for x in s:
                    x["in"] = f"{name}@{mname}"
                sinks += s
                controllers[f"{name}@{mname}"] = {
                    "file": c["file"], "line": m["line"], "bound_models": bound, "form_requests": freq,
                    "authorization": authz, "input": inputs, "mass_assignment": mass,
                    "sinks": [x["kind"] for x in s]}
            if name.endswith("Controller") and re.search(r"authorizeResource\(", c["src"]):
                for k, v in controllers.items():
                    if k.startswith(name + "@"):
                        v["authorization"].append({"call": "authorizeResource (constructor)", "line": c["line"]})

    # sinks outside controllers (models, jobs, listeners, services) and views
    seen = {(x["file"], x["line"], x["kind"]) for x in sinks}
    for name, infos in idx.items():
        for c in infos:
            if "/Controllers/" in c["file"]:
                continue
            for x in _sinks_in(c["src"][c["body"][0]:c["body"][1]], c["src"], c["body"][0], c["file"]):
                if (x["file"], x["line"], x["kind"]) not in seen:
                    x["in"] = name
                    sinks.append(x); seen.add((x["file"], x["line"], x["kind"]))
    views = []
    vdir = os.path.join(root, "resources", "views")
    for dp, dirs, fns in os.walk(vdir):
        dirs.sort()
        for fn in sorted(fns):
            if not fn.endswith(".blade.php"):
                continue
            path = os.path.join(dp, fn)
            rel = os.path.relpath(path, root)
            src = _read(path)
            unescaped = []
            for m in re.finditer(r"\{!!\s*(.+?)\s*!!\}", src, re.S):
                expr = m.group(1).strip()
                harmless = re.fullmatch(r"(csrf_field|method_field)\(.*\)|\$\w+->links\(\)|__\(.+\)|"
                                        r"json_encode\(.+\)|e\(.+\)|nl2br\(e\(.+\)\)", expr)
                item = {"file": rel, "line": line_of(src, m.start()), "expr": expr[:120]}
                unescaped.append(item)
                if not harmless:
                    sinks.append({"kind": "unescaped-output", "what": "Blade {!! !!} output without escaping",
                                  "file": rel, "line": item["line"], "code": "{!! " + expr[:120] + " !!}",
                                  "in": rel})
            forms = len(re.findall(r"<form[^>]+method=[\"']?post", src, re.I))
            csrf = len(re.findall(r"@csrf|csrf_field\(\)|_token", src))
            views.append({"file": rel, "unescaped": unescaped, "post_forms": forms, "csrf_tokens": csrf,
                          "name": os.path.relpath(path, vdir)[:-10].replace(os.sep, ".")})

    jobs = sorted({name for name, infos in idx.items() for c in infos if c["file"].startswith(("app/Jobs/",
                                                                                               "app/Listeners/"))})
    config = _deployment_config(root)
    m = {"version": VERSION, "framework": fw, "routing": routing, "routes": routes, "controllers": controllers,
         "models": models, "policies": policies, "gates": gates, "form_requests": requests_, "views": views,
         "jobs": jobs, "sinks": sinks, "config": config,
         "build": {"source_digest": source_digest(root), "algorithm": "rvkit source digest v1 (sha256 over "
                   "sha256sum lines of " + ", ".join(DIGEST_PARTS) + ")"}}
    m["leads"], m["controls"] = leads(m)
    m["gaps"] = gaps(root, m)
    return m


def _deployment_config(root):
    out = []
    for f in (".env", ".env.example", ".env.production"):
        src = _read(os.path.join(root, f))
        for k in ("APP_DEBUG", "APP_ENV", "SESSION_SECURE_COOKIE", "MAIL_MAILER", "QUEUE_CONNECTION"):
            mm = re.search(r"^" + k + r"=(.*)$", src, re.M)
            if mm:
                out.append({"file": f, "key": k, "value": mm.group(1).strip() if k != "APP_KEY" else "[set]",
                            "line": line_of(src, mm.start())})
    app = strip_comments(_read(os.path.join(root, "config", "app.php")))
    mm = re.search(r"['\"]debug['\"]\s*=>\s*\(bool\)\s*env\(\s*['\"]APP_DEBUG['\"]\s*,\s*(\w+)", app)
    if mm:
        out.append({"file": "config/app.php", "key": "debug default", "value": mm.group(1),
                    "line": line_of(app, mm.start())})
    return out


def leads(m):
    """Candidate issues and found controls, each with the reasoning and the locations it rests on."""
    out, controls = [], []
    for r in m["routes"]:
        key = f"{r['controller']}@{r['action']}" if r["controller"] else None
        c = m["controllers"].get(key) if key else None
        where = f"{'|'.join(r['methods'])} {r['uri']}"
        if r["route_can"]:
            controls.append({"kind": "route-authorization", "route": where, "detail": ", ".join(r["route_can"]),
                             "file": r["file"], "line": r["line"]})
        if not c:
            continue
        bound = c["bound_models"]
        freq_auth = [m["form_requests"][f]["authorize"] for f in c["form_requests"]]
        authorized = bool(c["authorization"] or r["route_can"] or any(a.startswith("checks") for a in freq_auth))
        if c["authorization"]:
            controls.append({"kind": "authorization-call", "route": where, "detail": "; ".join(
                a["call"] for a in c["authorization"]), "file": c["file"], "line": c["authorization"][0]["line"]})
        for b in bound:
            model = m["models"].get(b["model"], {})
            if model.get("tenant_scoped"):
                controls.append({"kind": "tenant-scope", "route": where, "detail": f"{b['model']} has the global "
                                 f"scope {model['global_scopes'][0]['scope']} ({model['global_scopes'][0]['via']}): "
                                 "route binding finds only the user's tenant's records",
                                 "file": model["global_scopes"][0]["file"], "line": model["global_scopes"][0]["line"]})
            elif not authorized:
                out.append({
                    "kind": "object-authorization", "severity_hint": "high" if r["authenticated"] else "medium",
                    "confidence": "medium", "route": where, "controller": key,
                    "title": f"{where} may return any {b['model']} (no ownership or tenant check found)",
                    "why": f"{key} takes {b['model']} ${b['param']} by route binding; the method has no authorize/"
                           f"Gate/can call, the route has no can middleware, and {b['model']} has no global "
                           "(tenant) scope.",
                    "verify": f"request {where} for another tenant's {b['model']} as a valid identity and look for "
                              "that record's fixture marker (authorization matrix or replay_request)",
                    "locations": [{"file": r["file"], "line": r["line"]}, {"file": c["file"], "line": c["line"]},
                                  {"file": model.get("file"), "line": model.get("line")}]})
        if not r["authenticated"] and (bound or set(r["methods"]) - {"GET", "HEAD"}) and \
                not any(x == "guest" for x in r["middleware"]):
            out.append({"kind": "unauthenticated-route", "severity_hint": "medium", "confidence": "low",
                        "route": where, "controller": key,
                        "title": f"{where} has no authentication middleware",
                        "why": f"effective middleware: {', '.join(r['middleware']) or 'none'}",
                        "verify": "request it without an identity",
                        "locations": [{"file": r["file"], "line": r["line"]}]})
        for ma in c["mass_assignment"]:
            target = "User" if "user()" in ma["code"] else next((b["model"] for b in bound if f"${b['param']}"
                                                                 in ma["code"]), None)
            model = m["models"].get(target or "", {})
            sens = model.get("sensitive_assignable", [])
            if "validated" in ma["with"]:
                continue
            out.append({"kind": "mass-assignment", "severity_hint": "high" if sens else "medium",
                        "confidence": "high" if sens else "medium", "route": where, "controller": key,
                        "title": f"{where} assigns all request input to {target or 'a model'}"
                                 + (f" ({', '.join(sens)} assignable)" if sens else ""),
                        "why": f"{ma['code']} with {model.get('assignment', 'unknown model settings')}",
                        "verify": f"send an extra field ({(sens or ['role'])[0]}) as a write-capable identity and "
                                  "read it back; restore the account afterwards",
                        "locations": [{"file": c["file"], "line": ma["line"]},
                                      {"file": model.get("file"), "line": model.get("line")}]})
        if "validated input" in c["input"] and not c["mass_assignment"]:
            controls.append({"kind": "validated-input", "route": where, "detail": "uses validated() input",
                             "file": c["file"], "line": c["line"]})
    for f in m["form_requests"].values():
        if f["authorize"] == "always true":
            out.append({"kind": "form-request-authorize", "severity_hint": "info", "confidence": "low",
                        "title": f"{f['file']}: authorize() returns true", "why": "authorization must happen "
                        "elsewhere (route can, controller or policy)", "verify": "check the routes using it",
                        "locations": [{"file": f["file"], "line": f["line"]}]})
    for s in m["sinks"]:
        if s["kind"] in ("raw-sql", "unescaped-output", "file-read", "command", "deserialize", "eval", "redirect"):
            out.append({"kind": s["kind"], "severity_hint": {"raw-sql": "high", "command": "high", "eval": "high",
                                                             "deserialize": "high"}.get(s["kind"], "medium"),
                        "confidence": "medium", "title": f"{s['what']} in {s['in']}", "why": s["code"],
                        "verify": "trace the variable to request input (Semgrep laravel rules, then a request)",
                        "locations": [{"file": s["file"], "line": s["line"]}]})
    for c in m["config"]:
        if c["key"] == "APP_DEBUG" and c["value"].lower() == "true" and c["file"] != ".env.example":
            out.append({"kind": "debug-mode", "severity_hint": "medium", "confidence": "medium",
                        "title": f"APP_DEBUG=true in {c['file']}", "why": "debug pages expose stack traces, "
                        "configuration and environment values", "verify": "trigger an error on the deployment "
                        "(a 404 or a malformed request) and look for the debug page",
                        "locations": [{"file": c["file"], "line": c["line"]}]})
    return out, controls


def gaps(root, m):
    g = ["Static map: routes registered by packages, macros, the framework itself (storage/{path} when the local "
         "disk is served) or service providers' own code, and middleware "
         "applied in controllers' constructors or by route attributes, are not seen. Compare with a runtime route "
         "export (php artisan route:list --json) when possible.",
         "Joern's PHP frontend (php2cpg) needs a PHP binary, which the Kali image doesn't have: no Joern data-flow "
         "for PHP. Semgrep's php and laravel rules (offline) are the pattern analysis; the PHP profile (RW-013) "
         "can parse-check the code."]
    if not m["framework"]["lock"]:
        g.append("No composer.lock: package versions are unknown (dependency checks need it).")
    if os.path.isdir(os.path.join(root, "app", "Livewire")) or any("livewire" in p for p in
                                                                    m["framework"].get("notable_packages", [])):
        g.append("Livewire components are actions reachable over /livewire/update: they are not mapped as routes.")
    if any(r["controller"] and f"{r['controller']}@{r['action']}" not in m["controllers"] for r in m["routes"]):
        missing = sorted({f"{r['controller']}@{r['action']}" for r in m["routes"] if r["controller"] and
                          f"{r['controller']}@{r['action']}" not in m["controllers"]})
        g.append("Route actions without a controller method in app/ (package or dynamic): " + ", ".join(missing[:10]))
    return g


def compare_routes(static_routes, export):
    """Compare the static routes with a runtime export (route:list --json): routes only one side has."""
    def norm(uri):
        return "/" + re.sub(r"\{(\w+)\?\}", r"{\1}", uri.strip("/"))
    run = set()
    for r in export:
        for meth in str(r.get("method", "")).split("|"):
            if meth and meth != "HEAD":
                run.add((meth, norm(r.get("uri", ""))))
    anym = ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
    stat = {(x, norm(r["uri"])) for r in static_routes for meth in r["methods"]
            for x in (anym if meth == "ANY" else (meth,))}
    return {"runtime_only": sorted(f"{a} {b}" for a, b in run - stat),
            "static_only": sorted(f"{a} {b}" for a, b in stat - run), "matched": len(run & stat)}


def summary(m):
    fw = m["framework"]
    lines = [f"Laravel {fw['laravel'] or fw.get('laravel_constraint') or '?'} (PHP {fw['php'] or '?'}), "
             f"{fw['packages']} packages{'' if fw['lock'] else ', no composer.lock'}; routes from {m['routing']}",
             f"{len(m['routes'])} routes ({sum(1 for r in m['routes'] if r['authenticated'])} authenticated), "
             f"{len(m['controllers'])} controller methods, {len(m['models'])} models "
             f"({sum(1 for x in m['models'].values() if x['tenant_scoped'])} with a global scope), "
             f"{len(m['policies'])} policies, {len(m['form_requests'])} form requests, {len(m['sinks'])} sinks",
             f"source digest {m['build']['source_digest']}"]
    b = m["build"]
    if b.get("deployed"):
        lines.append(f"deployed build {b['deployed']} ({b.get('deployed_from')}): "
                     + ("MATCHES the source" if b["match"] else "DOES NOT MATCH the source: runtime results may "
                        "not apply to this code"))
    elif b.get("deployed_error"):
        lines.append(f"deployed build: unknown ({b['deployed_error']})")
    if m.get("route_comparison"):
        rc = m["route_comparison"]
        lines.append(f"runtime routes: {rc['matched']} matched, {len(rc['runtime_only'])} only at runtime, "
                     f"{len(rc['static_only'])} only in the static map")
    lines.append("")
    lines.append(f"Leads ({len(m['leads'])}), to verify at runtime; none is a finding yet:")
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    for x in sorted(m["leads"], key=lambda x: order.get(x["severity_hint"], 9)):
        loc = ", ".join(f"{l['file']}:{l['line']}" for l in x["locations"] if l.get("file"))
        lines.append(f"  [{x['severity_hint']}/{x['confidence']}] {x['title']}\n      why: {x['why']}\n"
                     f"      verify: {x['verify']}\n      at: {loc}")
    lines.append("")
    lines.append(f"Controls found ({len(m['controls'])}); don't report these as flaws without runtime evidence:")
    for x in m["controls"][:40]:
        lines.append(f"  {x['kind']}: {x['route']}: {x['detail']} ({x['file']}:{x['line']})")
    lines.append("")
    lines.append("Gaps:")
    lines += [f"  - {g}" for g in m["gaps"]]
    return "\n".join(lines)
