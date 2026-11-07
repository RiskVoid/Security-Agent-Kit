"""Branded assessment report from an engagement's findings database (RiskVoid design by default).

  python3 report.py <engagement>      (on the host: ./rvkit report <engagement>)

Writes /work/<eng>/report/<eng>-report-<date>.docx, a PDF copy and a findings register (.xlsx).
Inputs, all optional, written by the planner or the consultant:
  /work/<eng>/report/meta.txt               "Client: ...", "Prepared by: ...", "Version: ..." (template created on
                                            the first run)
  /work/<eng>/report/executive-summary.md   executive summary (required for a final report)
  /work/<eng>/report/methodology.md         extra methodology text (the tool/tier summary is automatic)
  /work/<eng>/report/conclusion.md          closing remarks
Branding (name, logo, colours, fonts) comes from REPORT_BRAND / ORG_NAME / REPORT_BRAND_DIR: see branding.py.
Only confirmed, fixed and accepted-risk findings are reported. Evidence is checked against the kali audit log
(evidence_provenance): every file gets its SHA-256 and the command that produced it. The report is marked DRAFT
while anything blocks delivery (missing summary, open candidates, missing/modified evidence).
"""
import asyncio, datetime, json, os, re, subprocess, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "brand"))
import rv_brand as rvb  # noqa: E402
from rv_brand import run_props, el, P  # noqa: E402
import branding  # noqa: E402
from docx.shared import Pt, Twips  # noqa: E402
from docx.oxml.ns import qn  # noqa: E402
from mcp import ClientSession  # noqa: E402
from mcp.client.streamable_http import streamablehttp_client  # noqa: E402
import findings_db as db  # noqa: E402
from redact import redact  # noqa: E402

KALI_MCP = os.environ.get("KALI_MCP_URL", "http://kali-mcp:8090/mcp")
SEV_ORDER = {s: i for i, s in enumerate(db.SEVERITIES)}
REPORTED = ("confirmed", "fixed", "accepted-risk")
STATUS_LABEL = {"confirmed": "Open", "fixed": "Resolved", "accepted-risk": "Accepted risk"}
META_TEMPLATE = """Client:
Prepared by: {prepared_by}
Version: 1.0
Classification: Confidential
"""


# ---------------------------------------------------------------- inputs
def kali(tool, args):
    async def go():
        async with streamablehttp_client(KALI_MCP, timeout=30, sse_read_timeout=600) as (r, w, _):
            async with ClientSession(r, w) as s:
                await s.initialize()
                res = await s.call_tool(tool, args)
                return "\n".join(c.text for c in res.content if getattr(c, "text", None))
    out = asyncio.run(go())
    try:
        return json.loads(out)
    except ValueError:
        raise ValueError(f"kali-mcp {tool}: {out[:300]}") from None


def read_opt(path):
    try:
        return Path(path).read_text().strip()
    except OSError:
        return ""


def meta(eng, prepared_by):
    p = Path(db.WORK, eng, "report", "meta.txt")
    if not p.exists():
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(META_TEMPLATE.format(prepared_by=prepared_by))
    out = {}
    for line in p.read_text().splitlines():
        if ":" in line and not line.lstrip().startswith("#"):
            k, v = line.split(":", 1)
            out[k.strip().lower()] = v.strip()
    return out


def norm_path(eng, item):
    """Evidence item -> (path, note). Workspace paths (/projects/engagements/<eng>/...) map to /work/<eng>/..."""
    s = str(item).strip()
    path, _, note = s.partition(" ")
    path = re.sub(r"^/projects/engagements/", "/work/", path)
    return path, note.strip().strip("()")


def evidence_index(eng, findings):
    """Per finding: [{path, note, sha256, status, produced_by, at}], plus readiness issues."""
    items, files = {}, []
    for f in findings:
        items[f["id"]] = [dict(zip(("path", "note"), norm_path(eng, e))) for e in (f.get("evidence") or [])]
        files += [i["path"] for i in items[f["id"]] if not i["path"].startswith("/src/")]
    prov = {p["given"]: p for p in kali("evidence_provenance", {"engagement": eng, "paths": sorted(set(files))})} \
        if files else {}
    issues = []
    for fid, lst in items.items():
        if not lst:
            issues.append(f"{fid} has no evidence")
        for i in lst:
            if i["path"].startswith("/src/"):
                i["status"] = "code reference"
                continue
            p = prov.get(i["path"], {})
            i.update(sha256=p.get("sha256"), status=p.get("status", "missing"), produced_by=p.get("produced_by"),
                     at=p.get("at"))
            if i["status"] == "missing" or i["status"].startswith("MODIFIED") or i["status"].startswith("not an"):
                issues.append(f"{fid}: evidence {i['path']} is {i['status']}")
    return items, issues


# ---------------------------------------------------------------- docx helpers
def integrity_label(status):
    if status == "verified":
        return "Pass"
    if status == "code reference":
        return "Code ref"
    if status.startswith("not produced"):
        return "Not audited"
    return "Fail"


def code_block(d, text):
    for line in text.rstrip("\n").split("\n"):
        p = d._p()
        r = p.add_run(line or " ")
        run_props(r, rvb.FONT_M, 8, P["INK0"])
        pf = p.paragraph_format
        pf.space_after = Pt(0)
        pf.space_before = Pt(0)
        p._p.get_or_add_pPr().append(el("w:shd", val="clear", color="auto", fill=P["PAPER1"]))


INLINE = re.compile(r"(\*\*[^*]+\*\*|`[^`]+`)")


def rich(p, text):
    for part in INLINE.split(text):
        if not part:
            continue
        if part.startswith("**") and part.endswith("**"):
            p.add_run(part[2:-2]).bold = True
        elif part.startswith("`") and part.endswith("`"):
            run_props(p.add_run(part[1:-1]), rvb.FONT_M, 9, P["INK0"])
        else:
            p.add_run(part)


def md(d, text):
    """Small markdown subset: paragraphs, - / * / 1. lists, ``` code, ## / ### headings, **bold**, `code`."""
    text = redact(text or "")
    lines, i, para = text.split("\n"), 0, []

    def flush():
        if para:
            rich(d._p(), " ".join(para))
            para.clear()
    while i < len(lines):
        ln = lines[i]
        if ln.strip().startswith("```"):
            flush()
            j = i + 1
            while j < len(lines) and not lines[j].strip().startswith("```"):
                j += 1
            code_block(d, "\n".join(lines[i + 1:j]))
            d._p().paragraph_format.space_after = Pt(2)
            i = j + 1
            continue
        m = re.match(r"\s*(?:[-*]|\d+[.)])\s+(.*)", ln)
        if m:
            flush()
            p = d.doc.add_paragraph(style="List Bullet")
            p.paragraph_format.left_indent = Twips(960 + 720)
            p.paragraph_format.right_indent = Twips(960)
            rich(p, m.group(1))
        elif ln.startswith("#"):
            flush()
            (d.h3 if ln.startswith("###") else d.h2)(ln.lstrip("#").strip())
        elif not ln.strip():
            flush()
        else:
            para.append(ln.strip())
        i += 1
    flush()


def cover(d, title, description, pairs):
    d.cover(title, description=description, meta=[k for k, _ in pairs])
    t = d.doc.tables[-1]
    for n, (_, v) in enumerate(pairs):
        cell = t.rows[n // 2].cells[n % 2]
        cell.paragraphs[1].runs[0].text = v or " "


def fmt_ts(ts):
    return (ts or "")[:16].replace("T", " ") + (" UTC" if ts else "")


# ---------------------------------------------------------------- build
def build(eng):
    brand = branding.load()  # fails before anything is written if the brand is misconfigured
    db.engagement_dir(eng)
    info = kali("engagement_info", {"engagement": eng})
    act = kali("engagement_activity", {"engagement": eng})
    m = meta(eng, brand.prepared_by)
    rdir = Path(db.WORK, eng, "report")
    exec_md, meth_md, concl_md = (read_opt(rdir / n) for n in ("executive-summary.md", "methodology.md",
                                                                "conclusion.md"))
    allf = db.list_(eng)
    findings = sorted([f for f in allf if f["status"] in REPORTED],
                      key=lambda f: (SEV_ORDER.get(f["severity"], 9), f["id"]))
    findings = [redact(f) for f in findings]
    ev, issues = evidence_index(eng, findings)
    cands = [f for f in allf if f["status"] == "candidate"]
    fps = [f for f in allf if f["status"] == "false-positive"]
    dups = [f for f in allf if f["status"] == "duplicate"]
    if not exec_md:
        issues.insert(0, "no executive summary (report/executive-summary.md)")
    if cands:
        issues.append(f"{len(cands)} candidate finding(s) not yet triaged: " + ", ".join(f["id"] for f in cands))
    if not m.get("client"):
        issues.append("client name not set (report/meta.txt)")
    draft = bool(issues)
    today = datetime.date.today().isoformat()
    period = f"{fmt_ts(act['first'])[:10]} to {fmt_ts(act['last'])[:10]}" if act["first"] else "n/a"
    sc = info["scope"]
    scope_short = ", ".join(sc["domains"] + sc["nets"] + [os.path.basename(p) for p in sc["paths"]])[:120]

    d = brand.doc(header_tag="SECURITY ASSESSMENT")
    # rv_brand bug workaround: the default template's theme-font attributes (asciiTheme etc.) override the named
    # brand fonts in Word and LibreOffice, so headings render in the theme font. Strip them from every style.
    for rf in d.doc.styles.element.iter(qn("w:rFonts")):
        for att in ("w:asciiTheme", "w:hAnsiTheme", "w:eastAsiaTheme", "w:cstheme"):
            rf.attrib.pop(qn(att), None)
    cover(d, "Security Assessment Report",
          f"Results of the security assessment of {scope_short or 'the agreed scope'}: findings ranked by "
          "severity, with evidence and remediation guidance.",
          [("Client", m.get("client")), ("Engagement", eng), ("Testing period", period),
           ("Report date", today), ("Prepared by", m.get("prepared by", brand.prepared_by)),
           ("Version / status", f"{m.get('version', '1.0')} · {'DRAFT' if draft else 'Final'}"),
           ("Classification", m.get("classification") or "Confidential")])

    if draft:
        d.guidance("DRAFT, not for client delivery. Resolve before sending: " + "; ".join(issues) + ".")

    # 1. executive summary
    d.h1("Executive summary")
    if exec_md:
        md(d, exec_md)
    else:
        d.guidance("Write 3–5 paragraphs in report/executive-summary.md: what was assessed and why, overall risk "
                   "posture, the most important findings in business terms, and the top remediation priorities.")
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in db.SEVERITIES}
    d.h2("Findings at a glance")
    d.table(["Severity", "Findings", "Open"], rows=[[s.capitalize(), str(counts[s]),
                                                     str(sum(1 for f in findings if f["severity"] == s
                                                             and f["status"] == "confirmed"))]
                                                    for s in db.SEVERITIES], col_weights=[1.4, 1, 1])
    if findings:
        d.body("")
        d.table(["ID", "Severity", "Finding", "Asset", "Status"],
                rows=[[f["id"], f["severity"].capitalize(), f["title"], f.get("asset") or "",
                       STATUS_LABEL[f["status"]]] for f in findings], col_weights=[0.9, 1.1, 4, 2, 1.2])
    else:
        d.body("No vulnerabilities were confirmed within the assessed scope.")

    # 2. scope and rules
    d.h1("Scope and rules of engagement")
    d.body("Testing was limited to the targets below. The limits were enforced technically: every command ran in "
           "a per-engagement sandbox whose network access was restricted to these targets, at or below the agreed "
           "intensity, and every command was recorded in an audit log.")
    rows = [["Network", n] for n in sc["nets"]] + [["Domain (incl. subdomains)", x] for x in sc["domains"]] + \
           [["Source code", p] for p in sc["paths"]]
    d.table(["Type", "Target"], rows=rows or [["n/a", "no targets"]], col_weights=[1.4, 4])
    r = info["rules"]
    d.body("")
    d.table(["Rule", "Value"], rows=[
        ["Allowed testing tiers", ", ".join(r["tiers"])],
        ["Maximum request rate", f"{r['max_rate']} per second"],
        ["Network access", r["network"]],
        ["Testing window (UTC)", r["window"] or "unrestricted"],
        ["Testing period", period]], col_weights=[1.4, 4])

    # 3. methodology
    d.h1("Methodology")
    if meth_md:
        md(d, meth_md)
    d.body("Each activity is classified by tier: passive (code and configuration analysis, research), active "
           "(scanning, crawling, fingerprinting) and intrusive (exploitation, brute force). Intrusive commands "
           "require explicit, single-use approval. Automated tool output was triaged by a consultant: only "
           "findings confirmed against the evidence are reported.")
    d.body(f"{act['commands_run']} commands were run "
           f"({', '.join(f'{v} {k}' for k, v in act['by_tier'].items() if v) or 'none'}); "
           f"{act['commands_refused']} were refused by the policy engine; "
           f"{act['approvals']['approved']} intrusive actions were approved and {act['approvals']['denied']} denied.")
    if act["tools"]:
        d.table(["Tool", "Runs"], rows=[[k, str(v)] for k, v in list(act["tools"].items())[:15]],
                col_weights=[3, 1])
    d.h2("Severity rating")
    d.body("Severity reflects the impact and likelihood of exploitation in this environment. For known "
           "vulnerabilities in third-party components, the CVSS base score is adjusted using CISA's Known "
           "Exploited Vulnerabilities catalogue (exploitation observed in the wild) and the FIRST EPSS "
           "probability of exploitation.")

    # 4. findings
    d.h1("Findings")
    if not findings:
        d.body("No findings.")
    for f in findings:
        d.h2(f"{f['id']}  {f['title']}")
        cvss = f"{f['cvss_score']:.1f}" if f.get("cvss_score") is not None else "n/a"
        d.table(["Severity", "CVSS", "CWE", "Status"],
                rows=[[f["severity"].capitalize(), cvss, f.get("cwe") or "n/a", STATUS_LABEL[f["status"]]]],
                col_weights=[1.2, 0.8, 1.6, 1.2])
        if f.get("asset"):
            d.body("")
            p = d._p()
            p.add_run("Affected asset: ").bold = True
            p.add_run(f["asset"])
        if f.get("cvss_vector"):
            p = d._p()
            p.add_run("CVSS vector: ").bold = True
            run_props(p.add_run(f["cvss_vector"]), rvb.FONT_M, 8.5, P["INK1"])
        for label, key in (("Description", "description"), ("Impact", "impact"),
                           ("Steps to reproduce", "reproduction"), ("Remediation", "remediation")):
            if f.get(key):
                d.h3(label)
                md(d, f[key])
        d.h3("Evidence")
        lst = ev.get(f["id"], [])
        if lst:
            d.table(["Evidence", "SHA-256", "Integrity"],
                    rows=[[i["path"] + (f"  ({i['note']})" if i["note"] else ""),
                           (i.get("sha256") or "")[:16] + ("…" if i.get("sha256") else "n/a"),
                           integrity_label(i["status"])] for i in lst], col_weights=[4, 1.6, 1])
        else:
            d.body("No evidence recorded.")

    if concl_md:
        d.h1("Conclusion")
        md(d, concl_md)

    # appendices
    d.h1("Appendix A: Evidence integrity")
    d.body("SHA-256 of each evidence file at report time, and the audited command that produced exactly that "
           "content. Pass: the file is unchanged since the sandbox produced it. Not audited: the file exists and "
           "is hashed, but was written outside the audited sandbox (for example a worker transcript). Code ref: a "
           "location in the client's source code.")
    rows = []
    for f in findings:
        for i in ev.get(f["id"], []):
            rows.append([f["id"], i["path"], i.get("sha256") or "n/a",
                         ((lambda c: c if len(c) <= 90 else c[:89] + "…")(i.get("produced_by") or ""))
                         + (f"  [{fmt_ts(i['at'])}]" if i.get("at") else ""),
                         integrity_label(i["status"])])
    d.table(["Finding", "File", "SHA-256", "Produced by", "Integrity"], rows=rows or [["", "none", "", "", ""]],
            col_weights=[0.8, 2, 2.5, 2.5, 1.2])

    d.h1("Appendix B: Activity summary")
    d.table(["Measure", "Value"], rows=[
        ["First / last activity", f"{fmt_ts(act['first'])} / {fmt_ts(act['last'])}"],
        ["Commands run", str(act["commands_run"])],
        ["Commands refused by policy", str(act["commands_refused"])],
        ["Evidence files recorded", str(act["evidence_files"])],
        ["Approvals requested / approved / denied",
         f"{act['approvals']['requested']} / {act['approvals']['approved']} / {act['approvals']['denied']}"],
        ["Emergency halts", str(act["halts"])],
        ["Scope changes", str(act["scope_changes"])],
        ["Results triaged as false positives", str(len(fps))],
        ["Results merged as duplicates", str(len(dups))]], col_weights=[2.5, 3])

    # output
    rdir.mkdir(parents=True, exist_ok=True)
    stem = f"{eng}-report-{today}" + ("-DRAFT" if draft else "")
    for old in rdir.glob(f"{eng}-report-{today}*"):
        old.unlink()
    docx = rdir / f"{stem}.docx"
    d.save(str(docx))

    cols = [("ID", 9), ("Severity", 12), ("Finding", 46), ("Asset", 28), ("CWE", 14), ("CVSS", 8),
            ("Status", 14), ("Remediation", 60)]
    wb = brand.workbook("Findings Register", meta=["Client", "Engagement", "Report date"], columns=cols,
                     n_rows=max(len(findings), 1))
    ws = wb.active
    hdr = next(r for r in range(1, 30) if ws.cell(row=r, column=1).value == "ID")
    for n, v in enumerate((m.get("client") or "", eng, today)):
        ws.cell(row=3 + n, column=2).value = v
    for k, f in enumerate(findings):
        vals = [f["id"], f["severity"].capitalize(), f["title"], f.get("asset") or "", f.get("cwe") or "",
                f.get("cvss_score"), STATUS_LABEL[f["status"]], (f.get("remediation") or "")[:1000]]
        for j, v in enumerate(vals, start=1):
            ws.cell(row=hdr + 1 + k, column=j).value = v
    xlsx = rdir / f"{eng}-findings-{today}.xlsx"
    wb.save(str(xlsx))

    pdf = rdir / f"{stem}.pdf"
    r = subprocess.run(["soffice", "--headless", "--convert-to", "pdf", "--outdir", str(rdir), str(docx)],
                       capture_output=True, text=True, timeout=300,
                       env={**os.environ, "HOME": "/tmp"})
    return {"docx": str(docx), "pdf": str(pdf) if pdf.exists() else f"PDF conversion failed: {r.stderr[-300:]}",
            "xlsx": str(xlsx), "status": "DRAFT" if draft else "final", "issues": issues,
            "findings": len(findings), "excluded": {"candidate": len(cands), "false-positive": len(fps), "duplicate": len(dups)}}


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    try:
        r = build(sys.argv[1])
    except ValueError as e:
        print("error:", e, file=sys.stderr)
        sys.exit(1)
    print(json.dumps(r, indent=1))
