"""The assessment report as one self-contained HTML page, in the RiskVoid report design (riskvoid.io design system,
"Report master": paper surface, ink neutrals, one signal blue, severity colours by meaning, Space Grotesk / Inter /
JetBrains Mono). Fonts and logo are embedded, nothing is fetched: the file can be emailed, archived or opened
offline, and prints to PDF page by page (cover, then sections).

report.py builds the content once and calls write(); this module only renders. Every value from the engagement
(findings, notes, commands, paths) is escaped: the markdown subset below produces tags only from its own syntax.
Custom and plain brands (branding.py) swap the name, logo, the primary and accent colours and the fonts.
"""
import base64, html, re
from pathlib import Path

ASSETS = Path(__file__).resolve().parent / "assets"
SEVS = ("critical", "high", "medium", "low", "info")
GRADE = {"critical": ("F", "Critical exposure", "critical"), "high": ("D", "Needs attention", "high"),
         "medium": ("C", "Moderate exposure", "medium"), "low": ("B", "Minor issues only", "low"),
         "info": ("A", "No exploitable issues", "ok"), None: ("A", "No confirmed vulnerabilities", "ok")}
STATUS_COLOR = {"Open": "critical", "Resolved": "ok", "Accepted risk": "medium"}


def e(v):
    return html.escape("" if v is None else str(v), quote=True)


def _data_uri(path, mime):
    try:
        return f"data:{mime};base64," + base64.b64encode(Path(path).read_bytes()).decode()
    except OSError:
        return ""


# ---------------------------------------------------------------- markdown subset (same as the Word report)
INLINE = re.compile(r"(\*\*[^*]+\*\*|`[^`]+`)")


def _inline(text):
    out = []
    for part in INLINE.split(text):
        if part.startswith("**") and part.endswith("**") and len(part) > 4:
            out.append(f"<strong>{e(part[2:-2])}</strong>")
        elif part.startswith("`") and part.endswith("`") and len(part) > 2:
            out.append(f"<code>{e(part[1:-1])}</code>")
        else:
            out.append(e(part))
    return "".join(out)


def md(text):
    lines, i, out, para, items = (text or "").split("\n"), 0, [], [], []

    def flush():
        if para:
            out.append(f"<p>{_inline(' '.join(para))}</p>")
            para.clear()
        if items:
            out.append("<ul>" + "".join(f"<li>{_inline(x)}</li>" for x in items) + "</ul>")
            items.clear()
    while i < len(lines):
        ln = lines[i]
        if ln.strip().startswith("```"):
            flush()
            j = i + 1
            while j < len(lines) and not lines[j].strip().startswith("```"):
                j += 1
            out.append(code(lines[i + 1:j]))
            i = j + 1
            continue
        m = re.match(r"\s*(?:[-*]|\d+[.)])\s+(.*)", ln)
        if m:
            if para:
                out.append(f"<p>{_inline(' '.join(para))}</p>")
                para.clear()
            items.append(m.group(1))
        elif ln.startswith("#"):
            flush()
            tag = "h4" if ln.startswith("###") else "h3"
            out.append(f"<{tag}>{_inline(ln.lstrip('#').strip())}</{tag}>")
        elif not ln.strip():
            flush()
        else:
            if items:
                flush()
            para.append(ln.strip())
        i += 1
    flush()
    return "\n".join(out)


def code(lines):
    if isinstance(lines, str):
        lines = lines.rstrip("\n").split("\n")
    rows = "".join(f'<span class="ln">{n}</span>{e(t) or " "}\n' for n, t in enumerate(lines, 1))
    return f'<pre class="code">{rows}</pre>'


# ---------------------------------------------------------------- pieces
def sev_tag(sev, label=None):
    s = sev if sev in SEVS else "info"
    return f'<span class="tag sev-{s}">{e(label or sev)}</span>'


def label(text):
    return f'<div class="label">{e(text)}</div>'


def section(num, eyebrow, title, body, cls=""):
    return (f'<section class="sec {cls}"><div class="eyebrow">{e(num)} · {e(eyebrow)}</div>'
            f'<h2>{e(title)}</h2>{body}</section>')


def table(head, rows, cls=""):
    th = "".join(f"<th>{e(h)}</th>" for h in head)
    tr = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows)
    return f'<div class="tbl {cls}"><table><thead><tr>{th}</tr></thead><tbody>{tr}</tbody></table></div>'


def integrity(status):
    if status == "verified":
        return '<span class="tag sev-ok">Pass</span>'
    if status == "code reference":
        return '<span class="tag sev-low">Code ref</span>'
    if (status or "").startswith("not produced"):
        return '<span class="tag sev-medium">Not audited</span>'
    return f'<span class="tag sev-critical" title="{e(status)}">Fail</span>'


# ---------------------------------------------------------------- styles
CSS = """
:root{
  --paper:#ffffff;--paper-1:#f7f7f8;--paper-2:#eeeef0;--paper-inset:#f2f2f4;
  --ink-0:oklch(22% 0.012 264);--ink-1:oklch(38% 0.010 264);--ink-2:oklch(52% 0.010 264);--ink-3:oklch(64% 0.008 264);
  --rule:oklch(90% 0.004 264);--rule-strong:oklch(83% 0.006 264);
  --signal:oklch(55% 0.17 250);--ink-void:oklch(15% 0.008 264);--cover-text:oklch(70% 0.01 264);
  --sev-critical:oklch(54% 0.20 25);--sev-high:oklch(64% 0.16 55);--sev-medium:oklch(70% 0.14 80);--sev-low:oklch(58% 0.13 235);
  --sev-info:oklch(55% 0.03 264);--sev-ok:oklch(56% 0.14 155);
  --sev-critical-bg:oklch(54% 0.20 25 / 0.10);--sev-high-bg:oklch(64% 0.16 55 / 0.12);--sev-medium-bg:oklch(70% 0.14 80 / 0.14);
  --sev-low-bg:oklch(58% 0.13 235 / 0.10);--sev-info-bg:oklch(55% 0.03 264 / 0.10);--sev-ok-bg:oklch(56% 0.14 155 / 0.10);
  --font-display:'Space Grotesk',system-ui,sans-serif;--font-sans:'Inter','Inter Tight',system-ui,sans-serif;
  --font-mono:'JetBrains Mono',ui-monospace,monospace;
}
*,*::before,*::after{box-sizing:border-box}
html,body{margin:0;padding:0;background:var(--paper-2);color:var(--ink-0);font-family:var(--font-sans);
  -webkit-font-smoothing:antialiased;font-size:15px;line-height:1.6}
.doc{display:flex;flex-direction:column;align-items:center;gap:28px;padding:40px 16px 80px}
.toolbar{width:min(816px,100%);display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;
  font-family:var(--font-mono);font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--ink-3)}
.page{width:min(816px,100%);background:var(--paper);box-shadow:0 8px 40px rgba(0,0,0,.18);display:flex;flex-direction:column}
.cover{min-height:1056px;position:relative;overflow:hidden}
.band{background:var(--ink-void);padding:56px 64px;color:#fff;position:relative;overflow:hidden}
.band::before{content:"";position:absolute;inset:0;pointer-events:none;
  background:radial-gradient(ellipse 50% 120% at 90% 0%,oklch(72% 0.155 238 / .18),transparent 60%)}
.band .row{position:relative;display:flex;align-items:center;gap:13px}
.band img{width:32px;height:32px;object-fit:contain;display:block}
.band .name{font-family:var(--font-display);font-weight:600;font-size:22px;letter-spacing:-.02em}
.band .cls{margin-left:auto;font-family:var(--font-mono);font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:var(--cover-text)}
.cover-body{padding:72px 64px 0;flex:1;display:flex;flex-direction:column}
.eyebrow{font-family:var(--font-mono);font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:var(--signal);margin-bottom:14px}
.cover-body .eyebrow{font-size:12px;letter-spacing:.16em;margin-bottom:28px}
h1{font-family:var(--font-display);font-weight:600;font-size:58px;line-height:1.02;letter-spacing:-.03em;margin:0 0 24px;overflow-wrap:anywhere}
.lede{font-size:19px;color:var(--ink-2);line-height:1.5;margin:0;max-width:46ch}
.cover-meta{margin-top:auto;display:grid;grid-template-columns:1fr 1fr;border-top:1px solid var(--rule)}
.cover-meta .kv{padding:24px 32px 24px 0;border-right:1px solid var(--rule);display:grid;grid-template-columns:1fr 1fr;gap:20px}
.label{font-family:var(--font-mono);font-size:10px;letter-spacing:.1em;text-transform:uppercase;color:var(--ink-3);margin-bottom:6px}
.val{font-family:var(--font-mono);font-size:13px;color:var(--ink-1);overflow-wrap:anywhere}
.posture{padding:24px 0 24px 32px;display:flex;align-items:center;gap:24px}
.grade{width:88px;height:88px;border-radius:14px;border:2px solid currentColor;display:grid;place-items:center;
  font-family:var(--font-display);font-weight:600;font-size:44px;flex-shrink:0}
.foot,.head{padding:20px 64px;display:flex;justify-content:space-between;gap:12px;font-family:var(--font-mono);font-size:11px;color:var(--ink-3)}
.foot{border-top:1px solid var(--rule)}
.head{border-bottom:1px solid var(--rule);align-items:center;padding:24px 64px}
.head img{width:22px;height:22px;object-fit:contain}
.head .name{font-family:var(--font-display);font-weight:600;font-size:15px;letter-spacing:-.02em;color:var(--ink-0);margin-right:auto;margin-left:11px}
.body{padding:48px 64px;flex:1;display:grid;gap:56px}
.sec h2{font-family:var(--font-display);font-weight:600;font-size:32px;letter-spacing:-.02em;margin:0 0 24px;line-height:1.15}
.sec h3{font-family:var(--font-display);font-weight:600;font-size:20px;letter-spacing:-.01em;margin:28px 0 10px}
.sec h4{font-size:15px;font-weight:600;margin:20px 0 8px}
.sec p,.sec li{color:var(--ink-1);max-width:68ch}
.sec p{margin:0 0 14px}
.sec ul{margin:0 0 14px;padding-left:20px}
.sec strong{color:var(--ink-0);font-weight:600}
code{font-family:var(--font-mono);font-size:.86em;background:var(--paper-inset);padding:1px 6px;border-radius:3px;color:var(--ink-0);overflow-wrap:anywhere}
pre.code{background:var(--ink-void);border-radius:8px;padding:18px 20px;margin:0 0 20px;font-family:var(--font-mono);font-size:12.5px;
  line-height:1.7;color:oklch(82% 0.006 264);white-space:pre-wrap;word-break:break-word;overflow-x:auto}
pre.code .ln{color:oklch(50% 0.01 264);display:inline-block;width:26px;text-align:right;padding-right:14px;user-select:none}
.draft{border:1px solid var(--sev-medium);border-left:4px solid var(--sev-medium);background:var(--sev-medium-bg);
  border-radius:0 8px 8px 0;padding:16px 20px}
.draft b{font-family:var(--font-mono);font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:oklch(45% 0.12 80)}
.draft ul{margin:8px 0 0;padding-left:18px;color:var(--ink-1);font-size:14px}
.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:var(--rule);border:1px solid var(--rule);border-radius:10px;overflow:hidden;margin-top:32px}
.kpi{background:var(--paper);padding:22px 24px}
.kpi .n{font-family:var(--font-display);font-size:38px;font-weight:600;letter-spacing:-.02em;line-height:1;margin-top:10px;font-feature-settings:'tnum'}
.kpi .d{font-family:var(--font-mono);font-size:11px;color:var(--ink-2);margin-top:8px}
.bar{display:flex;height:12px;border-radius:4px;overflow:hidden;background:var(--paper-inset)}
.legend{display:flex;gap:24px;margin-top:14px;flex-wrap:wrap}
.legend span{display:inline-flex;align-items:center;gap:8px;font-family:var(--font-mono);font-size:13px;color:var(--ink-1)}
.legend i{width:9px;height:9px;border-radius:2px;display:inline-block}
.tag{display:inline-flex;align-items:center;width:max-content;padding:2px 8px;border-radius:4px;font-family:var(--font-mono);
  font-size:10px;font-weight:500;text-transform:uppercase;letter-spacing:.06em;white-space:nowrap;border:1px solid transparent}
.sev-critical{color:var(--sev-critical);background:var(--sev-critical-bg);border-color:oklch(54% 0.20 25 / .3)}
.sev-high{color:var(--sev-high);background:var(--sev-high-bg);border-color:oklch(64% 0.16 55 / .3)}
.sev-medium{color:oklch(55% 0.13 80);background:var(--sev-medium-bg);border-color:oklch(70% 0.14 80 / .35)}
.sev-low{color:var(--sev-low);background:var(--sev-low-bg);border-color:oklch(58% 0.13 235 / .3)}
.sev-info{color:var(--sev-info);background:var(--sev-info-bg);border-color:oklch(55% 0.03 264 / .3)}
.sev-ok{color:var(--sev-ok);background:var(--sev-ok-bg);border-color:oklch(56% 0.14 155 / .3)}
.c-critical{color:var(--sev-critical)}.c-high{color:var(--sev-high)}.c-medium{color:var(--sev-medium)}.c-low{color:var(--sev-low)}
.c-info{color:var(--sev-info)}.c-ok{color:var(--sev-ok)}
.tbl{border:1px solid var(--rule);border-radius:10px;overflow:hidden;overflow-x:auto;margin:0 0 20px}
.tbl table{border-collapse:collapse;width:100%;font-size:13.5px}
.tbl th{text-align:left;padding:12px 16px;background:var(--paper-1);border-bottom:1px solid var(--rule);font-family:var(--font-mono);
  font-size:10px;font-weight:500;letter-spacing:.1em;text-transform:uppercase;color:var(--ink-3);white-space:nowrap}
.tbl td{padding:12px 16px;border-bottom:1px solid var(--rule);vertical-align:top;color:var(--ink-1)}
.tbl tr:last-child td{border-bottom:0}
.tbl .t{font-weight:500;color:var(--ink-0)}
.tbl .m{font-family:var(--font-mono);font-size:11.5px;color:var(--ink-3)}
.tbl .nw{white-space:nowrap}
.tbl.mono td{font-family:var(--font-mono);font-size:11.5px;overflow-wrap:anywhere}
.finding{padding-top:8px;border-top:1px solid var(--rule)}
.finding:first-of-type{border-top:0;padding-top:0}
.finding .top{display:flex;align-items:center;gap:12px;margin-bottom:14px;flex-wrap:wrap}
.finding h3{font-family:var(--font-display);font-weight:600;font-size:26px;letter-spacing:-.02em;line-height:1.2;margin:0 0 8px}
.finding .loc{font-family:var(--font-mono);font-size:12px;color:var(--ink-3);margin-bottom:24px;overflow-wrap:anywhere}
.impact{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:28px}
.impact>div{background:var(--paper-inset);border:1px solid var(--rule);border-radius:8px;padding:14px 16px;min-width:0}
.impact .v{font-size:14px;font-weight:500;color:var(--ink-0);margin-top:4px;overflow-wrap:anywhere}
.sub{font-family:var(--font-mono);font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--ink-3);margin:24px 0 10px}
.findings-list{display:grid;gap:56px}
@media (max-width:720px){
  .band,.cover-body,.body,.head,.foot{padding-left:24px;padding-right:24px}
  h1{font-size:40px}.cover{min-height:0}.cover-body{padding-top:40px}
  .cover-meta{grid-template-columns:1fr}.cover-meta .kv{border-right:0;padding-right:0}.posture{padding-left:0}
  .kpis,.impact{grid-template-columns:1fr 1fr}
}
@page{size:letter;margin:0}
@media print{
  html,body{background:#fff}.doc{padding:0;gap:0}.toolbar{display:none}
  .page{box-shadow:none;width:100%;break-after:page}.page:last-child{break-after:auto}
  .cover{height:100vh;min-height:0}
  .finding,.tbl tr,.kpis,.impact{break-inside:avoid}
  .sec h2,.sec h3,.sub{break-after:avoid}
}
"""


def _fonts_css(brand):
    if not brand.vendor:   # custom/plain: the brand's font families, installed or not on the reader's machine
        d, s, m = (f"'{x}'" for x in brand.fonts)
        return (f":root{{--font-display:{d},system-ui,sans-serif;--font-sans:{s},system-ui,sans-serif;"
                f"--font-mono:{m},ui-monospace,monospace}}")
    out = []
    for fam, f, w in (("Space Grotesk", "space-grotesk-latin.woff2", "300 700"), ("Inter", "inter-latin.woff2", "100 900"),
                      ("JetBrains Mono", "jetbrains-mono-latin.woff2", "100 800")):
        uri = _data_uri(ASSETS / "fonts" / f, "font/woff2")
        if uri:
            out.append(f"@font-face{{font-family:'{fam}';font-weight:{w};font-style:normal;src:url({uri}) format('woff2')}}")
    return "\n".join(out)


def _brand_css(brand):
    p = brand.palette or {}
    css = []
    if p.get("INK_VOID"):
        css.append(f"--ink-void:#{p['INK_VOID']}")
    if p.get("SIGNAL"):
        css.append(f"--signal:#{p['SIGNAL']}")
    if p.get("COVER_TEXT"):
        css.append(f"--cover-text:#{p['COVER_TEXT']}")
    return (":root{" + ";".join(css) + "}") if css else ""


# ---------------------------------------------------------------- page
def render(c):
    """c: the dict report.py assembles (see build()). Returns the HTML document."""
    brand, findings, ev, act, info = c["brand"], c["findings"], c["evidence"], c["activity"], c["info"]
    logo_light = _data_uri(brand.logo or (ASSETS / "riskvoid-logo.png" if brand.vendor else ""), "image/png") \
        if (brand.logo or brand.vendor) else ""
    logo_dark = _data_uri(brand.logo_dark or (ASSETS / "riskvoid-logo.png" if brand.vendor else ""), "image/png") \
        if (brand.logo_dark or brand.vendor) else ""
    cls = c["classification"]
    open_ = [f for f in findings if f["status"] == "confirmed"]
    top = next((s for s in SEVS if any(f["severity"] == s for f in open_)), None)
    letter, verdict, gcolor = GRADE[top]
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVS}
    title = c["client"] or c["engagement"]

    def head():
        img = f'<img src="{logo_light}" alt="">' if logo_light else ""
        nm = f'<span class="name">{e(brand.name)}</span>' if brand.name else '<span class="name"></span>'
        return f'<div class="head">{img}{nm}<span>{e(c["engagement"])} · {e(c["date"])}</span></div>'

    def foot(label_):
        return (f'<div class="foot"><span>{e(cls.upper())}{(" · " + e(brand.footer)) if brand.footer else ""}</span>'
                f'<span>{e(label_)}</span></div>')

    # cover
    meta_cells = "".join(f'<div>{label(k)}<div class="val">{e(v or "—")}</div></div>' for k, v in c["cover"])
    cover = f"""
<div class="page cover">
  <div class="band"><div class="row">{f'<img src="{logo_dark}" alt="">' if logo_dark else ""}
    {f'<span class="name">{e(brand.name)}</span>' if brand.name else ""}<span class="cls">{e(cls)}</span></div></div>
  <div class="cover-body">
    <div class="eyebrow">Security assessment report{" · draft" if c["draft"] else ""}</div>
    <h1>{e(title)}</h1>
    <p class="lede">{e(c["description"])}</p>
    <div class="cover-meta">
      <div class="kv">{meta_cells}</div>
      <div class="posture"><div class="grade c-{gcolor}">{letter}</div>
        <div>{label("Security posture")}<div style="font-size:15px;color:var(--ink-1);line-height:1.4">{e(verdict)}:
          {len(open_)} open finding{"s" if len(open_) != 1 else ""}{f", highest {top}" if top else ""}.</div></div></div>
    </div>
  </div>
  {foot("Cover")}
</div>"""

    # 01 executive summary
    total = len(findings) or 1
    bar = "".join(f'<span style="width:{100 * counts[s] / total:.1f}%;background:var(--sev-{s})"></span>'
                  for s in SEVS if counts[s])
    legend = "".join(f'<span><i style="background:var(--sev-{s})"></i>{counts[s]} {s}</span>' for s in SEVS if counts[s])
    kpis = [("Critical", counts["critical"], "var(--sev-critical)", "confirmed"),
            ("High", counts["high"], "var(--sev-high)", "confirmed"),
            ("Total findings", len(findings), "var(--ink-0)", f'{sum(1 for f in findings if f["status"] == "fixed")} resolved'),
            ("Posture", letter, f"var(--sev-{gcolor})", verdict.lower())]
    exec_body = (md(c["exec_md"]) if c["exec_md"] else
                 '<p><em>Executive summary not written yet (report/executive-summary.md).</em></p>')
    exec_body += '<div class="kpis">' + "".join(
        f'<div class="kpi">{label(k)}<div class="n" style="color:{col}">{e(v)}</div><div class="d">{e(dl)}</div></div>'
        for k, v, col, dl in kpis) + "</div>"
    if findings:
        exec_body += (f'<div style="margin-top:36px"><div style="display:flex;justify-content:space-between">'
                      f'{label("Findings by severity")}{label(f"{len(findings)} total")}</div>'
                      f'<div class="bar">{bar}</div><div class="legend">{legend}</div></div>')
    draft = ""
    if c["draft"]:
        draft = ('<div class="draft"><b>Draft, not for client delivery</b><ul>' +
                 "".join(f"<li>{e(x)}</li>" for x in c["issues"]) + "</ul></div>")

    # 02 register
    reg = table(["ID", "Severity", "Finding", "CWE", "Status"], [
        [f'<span class="m nw">{e(f["id"])}</span>', sev_tag(f["severity"]),
         f'<div class="t">{e(f["title"])}</div><div class="m">{e(f.get("asset") or "")}</div>',
         f'<span class="m nw">{e(f.get("cwe") or "—")}</span>',
         f'<span class="tag sev-{STATUS_COLOR.get(c["status_label"][f["status"]], "info")}">{e(c["status_label"][f["status"]])}</span>']
        for f in findings]) if findings else "<p>No vulnerabilities were confirmed within the assessed scope.</p>"

    # 03 scope and rules
    sc, r = info["scope"], info["rules"]
    targets = [["Network", f"<code>{e(n)}</code>"] for n in sc["nets"]] + \
              [["Domain (incl. subdomains)", f"<code>{e(x)}</code>"] for x in sc["domains"]] + \
              [["Source code", f"<code>{e(p)}</code>"] for p in sc["paths"]]
    scope_body = ("<p>Testing was limited to the targets below. The limits were enforced technically: every command ran "
                  "in a per-engagement sandbox whose network access was restricted to these targets, at or below the "
                  "agreed intensity, and every command was recorded in an audit log.</p>" +
                  table(["Type", "Target"], targets or [["—", "no targets"]]) +
                  table(["Rule", "Value"], [
                      ["Allowed testing tiers", " ".join(sev_tag({"passive": "low", "active": "high",
                                                                   "intrusive": "critical"}.get(t, "info"), t)
                                                         for t in r["tiers"])],
                      ["Maximum request rate", f"{e(r['max_rate'])} per second"],
                      ["Network access", e(r["network"])],
                      ["Testing window (UTC)", e(":".join(map(str, r["window"])) if r["window"] else "unrestricted")],
                      ["Testing period", e(c["period"])]]))

    # 04 methodology
    by_tier = ", ".join(f"{v} {k}" for k, v in act["by_tier"].items() if v) or "none"
    meth = (md(c["meth_md"]) if c["meth_md"] else "") + (
        "<p>Each activity is classified by tier: <strong>passive</strong> (code and configuration analysis, research), "
        "<strong>active</strong> (scanning, crawling, fingerprinting) and <strong>intrusive</strong> (exploitation, "
        "brute force). Intrusive commands require explicit, single-use approval. Automated tool output was triaged by "
        "a consultant: only findings confirmed against the evidence are reported.</p>"
        f"<p>{e(act['commands_run'])} commands were run ({e(by_tier)}); {e(act['commands_refused'])} were refused by "
        f"the policy engine; {e(act['approvals']['approved'])} intrusive actions were approved and "
        f"{e(act['approvals']['denied'])} denied.</p>")
    if act["tools"]:
        meth += table(["Tool", "Runs"], [[f"<code>{e(k)}</code>", e(v)] for k, v in list(act["tools"].items())[:15]])
    meth += ("<h3>Severity rating</h3><p>Severity reflects the impact and likelihood of exploitation in this "
             "environment. For known vulnerabilities in third-party components, the CVSS base score is adjusted using "
             "CISA's Known Exploited Vulnerabilities catalogue and the FIRST EPSS probability of exploitation.</p>")

    # 05 findings
    cards = []
    for f in findings:
        st = c["status_label"][f["status"]]
        cvss = f"{f['cvss_score']:.1f}" if f.get("cvss_score") is not None else "n/a"
        parts = [f'<article class="finding" id="{e(f["id"])}"><div class="top"><span class="eyebrow" style="margin:0">'
                 f'{e(f["id"])}</span>{sev_tag(f["severity"], f["severity"] + (" · " + f["cwe"] if f.get("cwe") else ""))}'
                 f'<span class="tag sev-{STATUS_COLOR.get(st, "info")}">{e(st)}</span></div>',
                 f'<h3>{e(f["title"])}</h3><div class="loc">{e(f.get("asset") or "")}</div>',
                 '<div class="impact">' + "".join(
                     f'<div>{label(k)}<div class="v {cl}">{e(v)}</div></div>' for k, v, cl in (
                         ("Severity", f["severity"].capitalize(), "c-" + f["severity"]), ("CVSS", cvss, ""),
                         ("CWE", f.get("cwe") or "n/a", ""), ("Status", st, "c-" + STATUS_COLOR.get(st, "info")))) +
                 "</div>"]
        if f.get("cvss_vector"):
            parts.append(f'<div class="sub">CVSS vector</div><p><code>{e(f["cvss_vector"])}</code></p>')
        for lab, key in (("Description", "description"), ("Impact", "impact")):
            if f.get(key):
                parts.append(f'<div class="sub">{lab}</div>{md(f[key])}')
        if f.get("reproduction"):
            rep = f["reproduction"]
            parts.append('<div class="sub">Steps to reproduce</div>' +
                         (md(rep) if "```" in rep or re.search(r"^\s*(?:[-*]|\d+[.)])\s", rep, re.M) else code(rep)))
        if f.get("remediation"):
            parts.append(f'<div class="sub">Remediation</div>{md(f["remediation"])}')
        lst = ev.get(f["id"], [])
        parts.append('<div class="sub">Evidence</div>' + (table(["File", "SHA-256", "Integrity"], [
            [f'<code>{e(i["path"])}</code>' + (f' <span class="m">{e(i["note"])}</span>' if i.get("note") else ""),
             f'<span class="m">{e((i.get("sha256") or "")[:16])}{"…" if i.get("sha256") else "n/a"}</span>',
             integrity(i.get("status"))] for i in lst]) if lst else "<p>No evidence recorded.</p>"))
        cards.append("".join(parts) + "</article>")

    secs = [section("01", "Executive summary", "What we found", exec_body),
            section("02", "Findings register", "All findings", reg),
            section("03", "Scope", "Scope and rules of engagement", scope_body),
            section("04", "Methodology", "How we tested", meth),
            section("05", "Finding detail", "Findings", '<div class="findings-list">' + "".join(cards) + "</div>"
                    if cards else "<p>No findings.</p>")]
    n = 6
    if c["concl_md"]:
        secs.append(section("06", "Conclusion", "Conclusion", md(c["concl_md"])))
        n = 7
    appx = []
    for f in findings:
        for i in ev.get(f["id"], []):
            pb = i.get("produced_by") or ""
            appx.append([e(f["id"]), e(i["path"]), e(i.get("sha256") or "n/a"),
                         e(pb if len(pb) <= 90 else pb[:89] + "…") + (f'<br><span class="m">{e(c["fmt_ts"](i["at"]))}</span>'
                                                                       if i.get("at") else ""),
                         integrity(i.get("status"))])
    secs.append(section(f"{n:02d}", "Appendix A", "Evidence integrity",
                        "<p>SHA-256 of each evidence file at report time, and the audited command that produced exactly "
                        "that content. <strong>Pass</strong>: unchanged since the sandbox produced it. <strong>Not "
                        "audited</strong>: hashed, but written outside the audited sandbox. <strong>Code ref</strong>: a "
                        "location in the client's source code.</p>" +
                        table(["Finding", "File", "SHA-256", "Produced by", "Integrity"], appx or [["", "none", "", "", ""]],
                              "mono")))
    ap = act["approvals"]
    secs.append(section(f"{n + 1:02d}", "Appendix B", "Activity summary", table(["Measure", "Value"], [
        ["First / last activity", e(f"{c['fmt_ts'](act['first'])} / {c['fmt_ts'](act['last'])}")],
        ["Commands run", e(act["commands_run"])], ["Commands refused by policy", e(act["commands_refused"])],
        ["Evidence files recorded", e(act["evidence_files"])],
        ["Approvals requested / approved / denied", e(f"{ap['requested']} / {ap['approved']} / {ap['denied']}")],
        ["Emergency halts", e(act["halts"])], ["Scope changes", e(act["scope_changes"])],
        ["Results triaged as false positives", e(c["n_fp"])], ["Results merged as duplicates", e(c["n_dup"])]])))

    body = f'<div class="page">{head()}<div class="body">{draft}{"".join(secs)}</div>{foot("Security assessment report")}</div>'
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="RiskVoid agent kit">
<title>{e(title)} · Security assessment report{" (DRAFT)" if c["draft"] else ""}</title>
<style>{_fonts_css(brand)}
{CSS}
{_brand_css(brand)}</style></head>
<body><div class="doc">
<div class="toolbar"><span>{e(brand.name or "Security")} · Security assessment report · {e(c["date"])}</span>
<span>{e(cls)} · v{e(c["version"])}{" · DRAFT" if c["draft"] else ""}</span></div>
{cover}
{body}
</div></body></html>
"""


def write(path, context):
    Path(path).write_text(render(context), encoding="utf-8")
    return str(path)
