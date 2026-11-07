"""Report branding: which name, logo, colours and fonts the client report uses.

Configured through the environment of the findings-mcp container:
  REPORT_BRAND      riskvoid (default) | plain | custom
  ORG_NAME          the organisation preparing the report: default for "Prepared by" (meta.txt still overrides it
                    per engagement) and, for plain/custom, the name in the report header. Default: RiskVoid for the
                    riskvoid brand, empty for plain, brand.json "org_name" for custom.
  REPORT_BRAND_DIR  folder of the custom brand (default /brand-custom): brand.json, optional logo.png,
                    logo-white.png and fonts/. See brands/example/README.md for the contract.

riskvoid is the vendored RiskVoid design (brand/rv_brand.py) untouched. plain and custom reuse its layout and only
swap the brand-specific parts: the logo, the name in the header bars, the footer text, the palette and the fonts.
rv_brand.py is not edited (it is a vendored copy): its module globals (P, FONT_*, LOGO) are set here, and BrandDoc
overrides the two methods that hardcode the RiskVoid name and the square logo.
"""
import json, os, re, shutil, subprocess
from dataclasses import dataclass, field
from pathlib import Path

import rv_brand as rvb
from docx.shared import Pt, Inches, Emu
from docx.enum.text import WD_TAB_ALIGNMENT

_P0 = dict(rvb.P)
_FONTS0 = (rvb.FONT_D, rvb.FONT_S, rvb.FONT_M)
_LOGO0 = rvb.LOGO
CUSTOM_DIR = "/brand-custom"
FONT_HOME = "/tmp"   # report.py runs LibreOffice with HOME=/tmp, so fonts in /tmp/.fonts are found by the PDF export
HEX = re.compile(r"#?([0-9A-Fa-f]{6})")
MAX_ASPECT = 4.0     # wider logos are scaled down to fit the logo slot

# neutral look: no logo, slate band, fonts every Word install has (rendered with the metric-compatible Liberation
# fonts in the container)
PLAIN_FONTS = ("Arial", "Arial", "Courier New")
PLAIN_PALETTE = {"INK_VOID": "1F2937", "SIGNAL": "4B5563", "COVER_TEXT": "9CA3AF"}
METRIC_ALIASES = {"arial": "Liberation Sans", "helvetica": "Liberation Sans", "courier new": "Liberation Mono",
                  "courier": "Liberation Mono", "times new roman": "Liberation Serif", "times": "Liberation Serif"}
JSON_KEYS = {"org_name", "footer", "show_name", "colors", "fonts", "palette"}


class BrandError(ValueError):
    pass


@dataclass
class Brand:
    key: str
    name: str                  # name in the header bars ("" = none)
    prepared_by: str           # default for "Prepared by"
    footer: str                # footer text after "CONFIDENTIAL · " ("" = none)
    logo: str | None = None    # on light backgrounds (running header)
    logo_dark: str | None = None   # on the dark cover band and the workbook band
    fonts: tuple = _FONTS0     # display, body, mono
    palette: dict = field(default_factory=dict)
    vendor: bool = False       # True: the untouched RiskVoid design

    def apply(self):
        """Point the rv_brand module globals at this brand (reset first, so it is idempotent)."""
        rvb.P.clear()
        rvb.P.update(_P0, **self.palette)
        rvb.FONT_D, rvb.FONT_S, rvb.FONT_M = self.fonts
        rvb.LOGO = _LOGO0

    def doc(self, **kw):
        return RVDoc(**kw) if self.vendor else BrandDoc(self, **kw)

    def workbook(self, title, **kw):
        if self.vendor:
            return rvb.rv_workbook(title, **kw)
        wb = rvb.rv_workbook(title, **kw)    # anchors the stock logo; swapped or removed below
        ws = wb.active
        logo = self.logo_dark or self.logo
        ws._images = []
        a1 = ws.cell(row=1, column=1)
        if logo:   # same placement as rv_workbook: 22 px high, 8 px from the left, 9 px from the top
            from openpyxl.drawing.image import Image as XLImage
            from openpyxl.drawing.spreadsheet_drawing import OneCellAnchor, AnchorMarker
            from openpyxl.drawing.xdr import XDRPositiveSize2D
            from openpyxl.utils.units import pixels_to_EMU as px
            w, h = _logo_size(logo, 22)
            img = XLImage(logo)
            img.anchor = OneCellAnchor(_from=AnchorMarker(col=0, colOff=px(8), row=0, rowOff=px(9 + (22 - h) / 2)),
                                       ext=XDRPositiveSize2D(cx=px(w), cy=px(h)))
            ws.add_image(img)
            a1.value = " " * max(8, round((w + 8) / 3.75)) + self.name if self.name else None  # spaces clear the logo
        else:
            a1.value = self.name
        return wb


RVDoc = rvb.RVDoc


def _logo_size(path, height):
    """(width, height) for a logo at the given height, keeping its aspect ratio (capped at MAX_ASPECT)."""
    from PIL import Image
    with Image.open(path) as im:
        aspect = im.width / im.height
    if aspect > MAX_ASPECT:
        return height * MAX_ASPECT, height * MAX_ASPECT / aspect
    return height * aspect, height


class BrandDoc(rvb.RVDoc):
    """RVDoc with the brand's logo (any aspect ratio, or none) and name in the header bars and footers."""

    def __init__(self, brand, **kw):
        self.brand = brand
        super().__init__(**kw)

    def _bar(self, container, dark, logo_in, logo_col, height=None, border=None):
        # same structure as RVDoc._bar; the logo column keeps the stock gap after the logo, or is dropped
        for t in list(container.tables):
            t._tbl.getparent().remove(t._tbl)
        logo = self.brand.logo_dark if dark else self.brand.logo
        if logo:
            w_in, h_in = _logo_size(logo, logo_in)
            lcol = logo_col + round((w_in - logo_in) * 1440)
            cols = [rvb.IND, lcol, rvb.PAGE_W - 2 * rvb.IND - lcol, rvb.IND]
        else:
            cols = [rvb.IND, rvb.CONTENT, rvb.IND]
        t = container.add_table(1, len(cols), Emu(rvb.PAGE_W * 635))
        rvb.table_setup(t, rvb.PAGE_W, cols, borders=border)
        cells = t.rows[0].cells
        if height:
            t.rows[0]._tr.get_or_add_trPr().append(rvb.el("w:trHeight", val=str(height), hRule="exact"))
        pad = 0 if height else 140
        for c in cells:
            rvb.valign(c)
            if dark:
                rvb.shade(c, rvb.P["INK_VOID"])
            rvb.tc_mar(c, left=0, right=0, top=pad, bottom=pad)
            c.paragraphs[0].paragraph_format.space_after = Pt(0)
        if logo:
            cells[1].paragraphs[0].add_run().add_picture(logo, width=Inches(w_in), height=Inches(h_in))
        p1 = cells[-2].paragraphs[0]
        p1.paragraph_format.tab_stops.clear_all()
        p1.paragraph_format.tab_stops.add_tab_stop(Emu((cols[-2] - 20) * 635), WD_TAB_ALIGNMENT.RIGHT)
        container._element.insert(0, t._tbl)
        return p1

    def _chrome(self):
        super()._chrome()
        b = self.brand
        sub = {"RiskVoid": b.name, "RISKVOID.COM": b.footer,
               "CONFIDENTIAL · RISKVOID.COM": "CONFIDENTIAL" + (f" · {b.footer}" if b.footer else "")}
        s = self.doc.sections[0]
        for part in (s.first_page_header, s.header, s.footer, s.first_page_footer):
            for t in part.tables:
                for c in t.rows[0].cells:
                    for p in c.paragraphs:
                        for r in p.runs:
                            if r.text in sub:
                                r.text = sub[r.text]


# ---------------------------------------------------------------- loading
def _installed_families():
    out = subprocess.run(["fc-list", ":", "family"], capture_output=True, text=True,
                         env={**os.environ, "HOME": FONT_HOME}).stdout
    fams = {f.strip().lower(): f.strip() for line in out.splitlines() for f in line.split(",") if f.strip()}
    return fams, {a for a, real in METRIC_ALIASES.items() if real.lower() in fams}


def _check_fonts(fonts, where):
    fams, aliases = _installed_families()
    missing = [f for f in sorted(fonts) if f.lower() not in fams and f.lower() not in aliases]
    if missing:
        raise BrandError(f"{where}: font(s) not installed in the report container: {', '.join(missing)}. Put the "
                         ".ttf/.otf files in the brand folder's fonts/ subfolder, or use an installed family: "
                         + ", ".join(sorted(fams.values())) + " (and Arial, Helvetica, Courier New, Times New Roman "
                         "via Liberation)")


def _png(path, label):
    from PIL import Image
    try:
        with Image.open(path) as im:
            im.verify()
            if im.format != "PNG":
                raise BrandError(f"{label} is {im.format}, not PNG")
    except BrandError:
        raise
    except Exception as e:
        raise BrandError(f"{label} is not a readable PNG: {e}") from None
    return str(path)


def _custom(org_env):
    d = Path(os.environ.get("REPORT_BRAND_DIR") or CUSTOM_DIR)
    where = f"REPORT_BRAND=custom ({d}/brand.json)"
    if not d.is_dir():
        raise BrandError(f"REPORT_BRAND=custom but the brand folder {d} does not exist: mount your brand folder "
                         f"there (contract: harness/brands/example/README.md)")
    try:
        cfg = json.loads((d / "brand.json").read_text())
    except FileNotFoundError:
        raise BrandError(f"{where}: brand.json is missing") from None
    except (OSError, ValueError) as e:
        raise BrandError(f"{where}: cannot read brand.json: {e}") from None
    if not isinstance(cfg, dict):
        raise BrandError(f"{where}: brand.json must be a JSON object")
    unknown = sorted(set(cfg) - JSON_KEYS - {k for k in cfg if k.startswith("_")})
    if unknown:
        raise BrandError(f"{where}: unknown field(s) {', '.join(unknown)}; allowed: {', '.join(sorted(JSON_KEYS))}")

    def text(key, default):
        v = cfg.get(key, default)
        if not isinstance(v, str):
            raise BrandError(f"{where}: {key} must be a string")
        return v.strip()
    name = org_env or text("org_name", "")
    if not name:
        raise BrandError(f"{where}: org_name is required (or set ORG_NAME)")
    show = cfg.get("show_name", True)
    if not isinstance(show, bool):
        raise BrandError(f"{where}: show_name must be true or false")

    def hexes(key, mapping):
        v = cfg.get(key, {})
        if not isinstance(v, dict):
            raise BrandError(f"{where}: {key} must be an object")
        out = {}
        for k, c in v.items():
            if k not in mapping:
                raise BrandError(f"{where}: unknown {key} entry {k!r}; allowed: {', '.join(sorted(mapping))}")
            m = HEX.fullmatch(c) if isinstance(c, str) else None
            if not m:
                raise BrandError(f"{where}: {key}.{k} must be a 6-digit hex colour like \"#1E3A5F\", got {c!r}")
            out[mapping[k]] = m.group(1).upper()
        return out
    palette = {**PLAIN_PALETTE,
               **hexes("colors", {"primary": "INK_VOID", "accent": "SIGNAL", "cover_text": "COVER_TEXT"}),
               **hexes("palette", {k: k for k in _P0})}

    fv = cfg.get("fonts", {})
    if not isinstance(fv, dict) or set(fv) - {"display", "body", "mono"} or \
            not all(isinstance(x, str) and x.strip() for x in fv.values()):
        raise BrandError(f"{where}: fonts must be an object with optional string fields display, body, mono")
    fonts = (fv.get("display", PLAIN_FONTS[0]).strip(), fv.get("body", PLAIN_FONTS[1]).strip(),
             fv.get("mono", PLAIN_FONTS[2]).strip())
    dst = Path(FONT_HOME, ".fonts", "rvkit-brand")   # brand fonts: installed per user for fontconfig / LibreOffice
    shutil.rmtree(dst, ignore_errors=True)
    if (d / "fonts").is_dir():
        dst.mkdir(parents=True)
        for f in (d / "fonts").iterdir():
            if f.suffix.lower() in (".ttf", ".otf", ".ttc"):
                shutil.copy(f, dst)
        subprocess.run(["fc-cache", "-f", str(dst)], capture_output=True, env={**os.environ, "HOME": FONT_HOME})
    _check_fonts(set(fonts), where)

    logo = _png(d / "logo.png", f"{d}/logo.png") if (d / "logo.png").exists() else None
    logo_dark = _png(d / "logo-white.png", f"{d}/logo-white.png") if (d / "logo-white.png").exists() else logo
    return Brand("custom", name=name if show else "", prepared_by=name,
                 footer=text("footer", name.upper()), logo=logo, logo_dark=logo_dark, fonts=fonts, palette=palette)


def load():
    """The configured brand, applied to rv_brand. Raises BrandError (a ValueError) when misconfigured."""
    key = (os.environ.get("REPORT_BRAND") or "riskvoid").strip().lower()
    org = (os.environ.get("ORG_NAME") or "").strip()
    if key == "riskvoid":
        b = Brand("riskvoid", name="RiskVoid", prepared_by=org or "RiskVoid", footer="RISKVOID.COM", vendor=True)
    elif key == "plain":
        b = Brand("plain", name=org, prepared_by=org, footer=org.upper(), fonts=PLAIN_FONTS,
                  palette=dict(PLAIN_PALETTE))
        _check_fonts(set(PLAIN_FONTS), "REPORT_BRAND=plain")
    elif key == "custom":
        b = _custom(org)
    else:
        raise BrandError(f"REPORT_BRAND={key!r} is not one of riskvoid, plain, custom")
    b.apply()
    return b
