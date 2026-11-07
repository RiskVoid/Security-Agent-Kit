"""RiskVoid brand toolkit for python-docx / openpyxl.

Produces documents that match the RiskVoid Design System's paper (report) theme:
full-bleed ink-void cover band, full-width running header/footer bars,
Space Grotesk / Inter Tight / JetBrains Mono, signal blue, 5-step severity scale.

The layout uses ZERO page margins with content inset via indents (0.67" = the
master's 64px column). This is deliberate: it is the only way to get a
true edge-to-edge band that survives Google Docs import (GDocs clamps tables
to page margins, ignores negative table indents, and ignores w:position on
inline images). See references/gdocs-notes.md for the full list of pitfalls.

Typical docx use:
    from rv_brand import RVDoc
    d = RVDoc(header_tag='AI AGENT SECURITY')
    d.cover('Technical Spot Check Report',
            description='One-paragraph purpose of the document.',
            meta=['Client', 'Engagement', 'Dates', 'RiskVoid.com owner'])
    d.h1('Executive summary')
    d.body('...')
    d.table(['ID', 'Severity', 'Finding'], rows=[['F-001', 'Critical', '...']])
    d.field('Client sponsor')
    d.save('report.docx')

Typical xlsx use:
    from rv_brand import rv_workbook
    wb = rv_workbook('Risk Register', meta=['Client', 'Engagement dates'],
                     columns=[('ID', 10), ('Risk', 40), ('Severity', 14)],
                     n_rows=25)
    wb.save('register.xlsx')
"""
import math
from pathlib import Path

from docx import Document
from docx.shared import Pt, Inches, Emu, Twips, RGBColor
from docx.enum.text import WD_TAB_ALIGNMENT, WD_BREAK
from docx.enum.style import WD_STYLE_TYPE
from docx.oxml.ns import qn
from docx.oxml import OxmlElement

ASSETS = Path(__file__).resolve().parent.parent / 'assets'
LOGO = str(ASSETS / 'riskvoid-logo.png')

P = {
 'INK0': '181B20', 'INK1': '404248', 'INK2': '66696F', 'INK3': '8A8C91',
 'RULE': 'DDDEE1', 'RULE_STRONG': 'C5C7CB', 'SIGNAL': '0073CF', 'INK_VOID': '090B0F',
 'SEV_CRIT': 'C9222B', 'SEV_HIGH': 'D36C00', 'SEV_MED': 'CB9317',
 'SEV_LOW': '0085BC', 'SEV_OK': '008B4E',
 'SEV_CRIT_BG': 'FAE9EA', 'SEV_HIGH_BG': 'FAEDE0', 'SEV_MED_BG': 'F8F0DF',
 'SEV_LOW_BG': 'E6F3F8', 'SEV_OK_BG': 'E6F3ED',
 'PAPER': 'FFFFFF', 'PAPER1': 'F7F7F8', 'COVER_TEXT': '9B9EA5',
}
FONT_D, FONT_S, FONT_M = 'Space Grotesk', 'Inter Tight', 'JetBrains Mono'

SEV_MAP = {
 'critical': ('SEV_CRIT', 'SEV_CRIT_BG'), 'high': ('SEV_HIGH', 'SEV_HIGH_BG'),
 'medium': ('SEV_MED', 'SEV_MED_BG'), 'low': ('SEV_LOW', 'SEV_LOW_BG'),
 'resolved': ('SEV_OK', 'SEV_OK_BG'), 'ok': ('SEV_OK', 'SEV_OK_BG'),
 'pass': ('SEV_OK', 'SEV_OK_BG'), 'fail': ('SEV_CRIT', 'SEV_CRIT_BG'),
}

PAGE_W = 12240          # US Letter, dxa
IND = 960               # 0.67" content inset (the master's 64px)
CONTENT = PAGE_W - 2 * IND

# ---------------------------------------------------------------- low level
def el(tag, **attrs):
    e = OxmlElement(tag)
    for k, v in attrs.items():
        e.set(qn('w:' + k), str(v))
    return e

def ins(parent, child, successors):
    for tag in successors:
        s = parent.find(qn('w:' + tag))
        if s is not None:
            s.addprevious(child)
            return child
    parent.append(child)
    return child

SUCC_TBLW = ('jc','tblCellSpacing','tblInd','tblBorders','shd','tblLayout','tblCellMar','tblLook')
SUCC_TBLIND = ('tblBorders','shd','tblLayout','tblCellMar','tblLook')
SUCC_TBLBORDERS = ('shd','tblLayout','tblCellMar','tblLook')
SUCC_TBLCELLMAR = ('tblLook',)
SUCC_TCSHD = ('noWrap','tcMar','textDirection','tcFitText','vAlign','hideMark')
SUCC_PBDR = ('shd','tabs','suppressAutoHyphens','spacing','ind','jc','rPr','sectPr')
SUCC_CAPS = ('smallCaps','strike','color','spacing','w','kern','position','sz','szCs','u','lang')
SUCC_RSPACING = ('w','kern','position','sz','szCs','u','lang')

def run_props(run, font=None, size=None, color=None, bold=None, italic=None,
              caps=False, spacing=None):
    if font:
        run.font.name = font
        run._element.rPr.rFonts.set(qn('w:cs'), font)
    if size: run.font.size = Pt(size)
    if color: run.font.color.rgb = RGBColor.from_string(color)
    if bold is not None: run.font.bold = bold
    if italic is not None: run.font.italic = italic
    rPr = run._element.get_or_add_rPr()
    if caps: ins(rPr, el('w:caps', val='1'), SUCC_CAPS)
    if spacing: ins(rPr, el('w:spacing', val=str(spacing)), SUCC_RSPACING)

def p_border(par, edge, color, sz=6, space=6):
    pPr = par._p.get_or_add_pPr()
    pBdr = pPr.find(qn('w:pBdr'))
    if pBdr is None:
        pBdr = ins(pPr, el('w:pBdr'), SUCC_PBDR)
    old = pBdr.find(qn('w:' + edge))
    if old is not None: pBdr.remove(old)
    pBdr.append(el('w:' + edge, val='single', sz=str(sz), space=str(space), color=color))

def shade(cell, color):
    tcPr = cell._tc.get_or_add_tcPr()
    old = tcPr.find(qn('w:shd'))
    if old is not None: tcPr.remove(old)
    ins(tcPr, el('w:shd', val='clear', color='auto', fill=color), SUCC_TCSHD)

def valign(cell):
    tcPr = cell._tc.get_or_add_tcPr()
    if tcPr.find(qn('w:vAlign')) is None:
        tcPr.append(el('w:vAlign', val='center'))

def tc_mar(cell, left, right, top=0, bottom=0):
    tcPr = cell._tc.get_or_add_tcPr()
    old = tcPr.find(qn('w:tcMar'))
    if old is not None: tcPr.remove(old)
    m = el('w:tcMar')
    for k, v in (('top', top), ('left', left), ('bottom', bottom), ('right', right)):
        m.append(el('w:' + k, w=str(v), type='dxa'))
    ins(tcPr, m, ('textDirection','tcFitText','vAlign','hideMark'))

def table_setup(t, total_w, col_widths, borders=None, ind=None):
    """borders: dict edge->(color, sz); edges absent render as none."""
    tp = t._tbl.tblPr
    old = tp.find(qn('w:tblW'))
    if old is not None: tp.remove(old)
    ins(tp, el('w:tblW', w=str(total_w), type='dxa'), SUCC_TBLW)
    if ind:
        ins(tp, el('w:tblInd', w=str(ind), type='dxa'), SUCC_TBLIND)
    if tp.find(qn('w:tblLayout')) is None:
        ins(tp, el('w:tblLayout', type='fixed'), ('tblCellMar','tblLook'))
    tb = el('w:tblBorders')
    for edge in ('top','left','bottom','right','insideH','insideV'):
        spec = (borders or {}).get(edge)
        if spec:
            tb.append(el('w:' + edge, val='single', sz=str(spec[1]), space='0', color=spec[0]))
        else:
            tb.append(el('w:' + edge, val='none', sz='0', space='0'))
    old = tp.find(qn('w:tblBorders'))
    if old is not None: tp.remove(old)
    ins(tp, tb, SUCC_TBLBORDERS)
    grid = t._tbl.find(qn('w:tblGrid'))
    for gc, w in zip(grid.findall(qn('w:gridCol')), col_widths):
        gc.set(qn('w:w'), str(w))
    for row in t.rows:
        for c, w in zip(row.cells, col_widths):
            c.width = Emu(w * 635)

def crush(p, dark=False):
    """1pt exact line; optional ink-void shading (leading header line — GDocs
    inserts a line above a table that starts a header; shaded dark it merges
    into the band instead of showing white)."""
    for r in list(p.runs): r._element.getparent().remove(r._element)
    run = p.add_run(' '); run.font.size = Pt(1)
    pPr = p._p.get_or_add_pPr()
    for tag in ('w:spacing', 'w:shd'):
        e = pPr.find(qn(tag))
        if e is not None: pPr.remove(e)
    if dark:
        sh = el('w:shd', val='clear', color='auto', fill=P['INK_VOID'])
        ins(pPr, sh, ('tabs','spacing','ind','jc','rPr'))
    sp = OxmlElement('w:spacing')
    sp.set(qn('w:before'), '0'); sp.set(qn('w:after'), '0')
    sp.set(qn('w:line'), '20'); sp.set(qn('w:lineRule'), 'exact')
    ins(pPr, sp, ('ind','jc','rPr'))
    rPr = pPr.find(qn('w:rPr'))
    if rPr is None:
        rPr = OxmlElement('w:rPr'); pPr.append(rPr)
    sz = OxmlElement('w:sz'); sz.set(qn('w:val'), '2'); rPr.append(sz)


# ---------------------------------------------------------------- documents
class RVDoc:
    def __init__(self, header_tag='AI AGENT SECURITY', confidential=True):
        self.doc = Document()
        self.header_tag = header_tag
        self.confidential = confidential
        self._styles()
        self._page_setup()
        self._chrome()

    # -- setup
    def _styles(self):
        S = self.doc.styles
        def get(name):
            try: return S[name]
            except KeyError:
                st = S.add_style(name, WD_STYLE_TYPE.PARAGRAPH)
                st.base_style = None
                return st
        def font(st, f, size, color, bold=False, italic=False):
            st.font.name = f; st.font.size = Pt(size)
            st.font.color.rgb = RGBColor.from_string(color)
            st.font.bold = bold; st.font.italic = italic
            rPr = st.element.get_or_add_rPr()
            rf = rPr.find(qn('w:rFonts'))
            if rf is None:
                rf = el('w:rFonts'); rPr.insert(0, rf)
            for a in ('w:ascii','w:hAnsi','w:cs'):
                rf.set(qn(a), f)
        n = get('Normal'); font(n, FONT_S, 10.5, P['INK1'])
        n.paragraph_format.space_after = Pt(6); n.paragraph_format.line_spacing = 1.35
        t = get('Title'); font(t, FONT_D, 40, P['INK0'], bold=True)
        t.paragraph_format.space_before = Pt(10); t.paragraph_format.space_after = Pt(10)
        pPr = t.element.get_or_add_pPr()
        b = pPr.find(qn('w:pBdr'))
        if b is not None: pPr.remove(b)
        h1 = get('Heading 1'); font(h1, FONT_D, 16, P['INK0'], bold=True)
        h1.paragraph_format.space_before = Pt(22); h1.paragraph_format.space_after = Pt(8)
        h2 = get('Heading 2'); font(h2, FONT_D, 12.5, P['INK0'], bold=True)
        h2.paragraph_format.space_before = Pt(14); h2.paragraph_format.space_after = Pt(6)
        h3 = get('Heading 3'); font(h3, FONT_S, 11, P['INK0'], bold=True)
        fl = get('FieldLabel'); font(fl, FONT_M, 8, P['INK3'])
        rPr = fl.element.get_or_add_rPr()
        ins(rPr, el('w:caps', val='1'), SUCC_CAPS)
        ins(rPr, el('w:spacing', val='20'), SUCC_RSPACING)
        fl.paragraph_format.space_before = Pt(8); fl.paragraph_format.space_after = Pt(2)

    def _page_setup(self):
        # python-docx's default template ships a w:zoom without the required
        # percent attribute, which fails strict OOXML validation — fix it.
        z = self.doc.settings.element.find(qn('w:zoom'))
        if z is not None and z.get(qn('w:percent')) is None:
            z.set(qn('w:percent'), '100')
        s = self.doc.sections[0]
        s.page_width = Twips(12240); s.page_height = Twips(15840)
        s.left_margin = 0; s.right_margin = 0
        s.top_margin = 0; s.bottom_margin = Inches(0.55)
        s.header_distance = 0; s.footer_distance = Inches(0.15)
        s.different_first_page_header_footer = True

    def _bar(self, container, dark, logo_in, logo_col, height=None, border=None):
        """4 columns: [spacer IND][logo][text][spacer IND], all zero cell
        margins. Google Docs drops tcMar on import, so the inset must be real
        columns — never cell margins."""
        for t in list(container.tables):
            t._tbl.getparent().remove(t._tbl)
        cols = [IND, logo_col, PAGE_W - 2 * IND - logo_col, IND]
        t = container.add_table(1, 4, Emu(PAGE_W * 635))
        table_setup(t, PAGE_W, cols, borders=border)
        cells = t.rows[0].cells
        if height:
            trPr = t.rows[0]._tr.get_or_add_trPr()
            trPr.append(el('w:trHeight', val=str(height), hRule='exact'))
        pad = 0 if height else 140
        for c in cells:
            valign(c)
            if dark: shade(c, P['INK_VOID'])
            tc_mar(c, left=0, right=0, top=pad, bottom=pad)
            c.paragraphs[0].paragraph_format.space_after = Pt(0)
        p0 = cells[1].paragraphs[0]
        p0.add_run().add_picture(LOGO, width=Inches(logo_in), height=Inches(logo_in))
        p1 = cells[2].paragraphs[0]
        p1.paragraph_format.tab_stops.clear_all()
        p1.paragraph_format.tab_stops.add_tab_stop(
            Emu((cols[2] - 20) * 635), WD_TAB_ALIGNMENT.RIGHT)
        container._element.insert(0, t._tbl)
        return p1

    def _chrome(self):
        s = self.doc.sections[0]
        # cover band (first-page header) with dark leading crush line
        fh = s.first_page_header
        # logo cell needs slack beyond the image width (0.32" = 461 twips) or
        # renderers clip the right edge of the mark
        p1 = self._bar(fh, dark=True, logo_in=0.32, logo_col=IND + 700,
                       height=2000, border={'top': (P['INK_VOID'], 24)})
        r = p1.add_run('RiskVoid'); run_props(r, FONT_D, 16.5, 'FFFFFF', bold=True)
        if self.confidential:
            r2 = p1.add_run('\tCONFIDENTIAL')
            run_props(r2, FONT_M, 8.5, P['COVER_TEXT'], spacing=30)
        lead = OxmlElement('w:p')
        fh._element.insert(0, lead)
        from docx.text.paragraph import Paragraph
        crush(Paragraph(fh._element[0], fh), dark=True)
        for p in fh.paragraphs[1:]:
            if not p._p.getparent().tag == qn('w:tc'):
                pass
        # trailing header paragraph -> collapse
        crush(fh.paragraphs[-1])
        # running header
        h = s.header
        p1 = self._bar(h, dark=False, logo_in=0.17, logo_col=IND + 430,
                       border={'bottom': (P['RULE'], 4)})
        r1 = p1.add_run('RiskVoid'); run_props(r1, FONT_D, 10, P['INK0'], bold=True)
        r2 = p1.add_run('\t' + self.header_tag)
        run_props(r2, FONT_M, 7.5, P['INK3'], spacing=20)
        crush(h.paragraphs[-1])
        # running footer with page fields
        f = s.footer
        fp = self._footer_bar(f)
        fl = fp.add_run(('CONFIDENTIAL · ' if self.confidential else '') + 'RISKVOID.COM')
        run_props(fl, FONT_M, 7.5, P['INK3'], spacing=20)
        fr = fp.add_run('\tPAGE '); run_props(fr, FONT_M, 7.5, P['INK3'], spacing=20)
        for instr in ('PAGE', 'NUMPAGES'):
            b = fp.add_run(); b._element.append(el('w:fldChar', fldCharType='begin'))
            i = fp.add_run()
            it = OxmlElement('w:instrText'); it.set(qn('xml:space'), 'preserve')
            it.text = f' {instr} '; i._element.append(it)
            run_props(i, FONT_M, 7.5, P['INK3'])
            e = fp.add_run(); e._element.append(el('w:fldChar', fldCharType='end'))
            if instr == 'PAGE':
                sep = fp.add_run(' OF '); run_props(sep, FONT_M, 7.5, P['INK3'], spacing=20)
        crush(f.paragraphs[-1])
        # first-page footer
        ff = s.first_page_footer
        fp = self._footer_bar(ff)
        a = fp.add_run('RISKVOID.COM'); run_props(a, FONT_M, 7.5, P['INK3'], spacing=20)
        b = fp.add_run('\tPAGE 1 — COVER'); run_props(b, FONT_M, 7.5, P['INK3'], spacing=20)
        crush(ff.paragraphs[-1])

    def _footer_bar(self, container):
        """3 columns: [spacer IND][text][spacer IND] — see _bar for why."""
        for t in list(container.tables):
            t._tbl.getparent().remove(t._tbl)
        t = container.add_table(1, 3, Emu(PAGE_W * 635))
        table_setup(t, PAGE_W, [IND, CONTENT, IND], borders={'top': (P['RULE'], 4)})
        for c in t.rows[0].cells:
            tc_mar(c, left=0, right=0, top=140, bottom=140)
            c.paragraphs[0].paragraph_format.space_after = Pt(0)
        p = t.rows[0].cells[1].paragraphs[0]
        p.paragraph_format.tab_stops.clear_all()
        p.paragraph_format.tab_stops.add_tab_stop(Emu((CONTENT - 20) * 635), WD_TAB_ALIGNMENT.RIGHT)
        container._element.insert(0, t._tbl)
        return p

    # -- content helpers (all body content is inset by IND)
    def _p(self, style=None):
        p = self.doc.add_paragraph(style=style)
        p.paragraph_format.left_indent = Twips(IND)
        p.paragraph_format.right_indent = Twips(IND)
        return p

    def cover(self, title, description=None, meta=None):
        """Cover page: air, display title, description, bottom metadata grid, page break."""
        gap = self._p(); gap.paragraph_format.space_after = Pt(46)
        tp = self._p('Title'); tp.add_run(title)
        if description:
            dp = self._p()
            r = dp.add_run(description)
            run_props(r, FONT_S, 12, P['INK2'])
            dp.paragraph_format.space_after = Pt(24)
        if meta:
            gap = self._p(); gap.paragraph_format.space_before = Pt(36)
            rows = math.ceil(len(meta) / 2)
            t = self.doc.add_table(rows=rows, cols=2)
            half = CONTENT // 2
            table_setup(t, CONTENT, [half, half], ind=IND,
                        borders={'top': (P['RULE_STRONG'], 6), 'insideV': (P['RULE'], 4)})
            tp_ = t._tbl.tblPr
            m = el('w:tblCellMar')
            for k, v in (('top', 100), ('left', 0), ('bottom', 60), ('right', 300)):
                m.append(el('w:' + k, w=str(v), type='dxa'))
            ins(tp_, m, SUCC_TBLCELLMAR)
            for n, label in enumerate(meta):
                cell = t.rows[n // 2].cells[n % 2]
                lp = cell.paragraphs[0]
                lr = lp.add_run(label)
                run_props(lr, FONT_M, 8, P['INK3'], caps=True, spacing=20)
                lp.paragraph_format.space_before = Pt(4)
                lp.paragraph_format.space_after = Pt(2)
                vp = cell.add_paragraph()
                vr = vp.add_run(' '); run_props(vr, FONT_M, 10, P['INK0'])
                p_border(vp, 'bottom', P['RULE_STRONG'], sz=4, space=2)
                vp.paragraph_format.space_after = Pt(0)
        pb = self._p()
        pb.add_run().add_break(WD_BREAK.PAGE)
        pb.paragraph_format.space_after = Pt(0)

    def h1(self, text):
        p = self._p('Heading 1'); p.add_run(text)
        p_border(p, 'bottom', P['RULE'], sz=6, space=4)
        return p

    def h2(self, text):
        p = self._p('Heading 2'); p.add_run(text); return p

    def h3(self, text):
        p = self._p('Heading 3'); p.add_run(text); return p

    def body(self, text):
        p = self._p(); p.add_run(text); return p

    def guidance(self, text):
        """Grey italic instruction text meant to be replaced before sending."""
        p = self._p()
        r = p.add_run(text); run_props(r, FONT_S, 9.5, P['INK3'], italic=True)
        return p

    def field(self, label):
        """Mono uppercase label + write-on line."""
        lp = self._p('FieldLabel'); lp.add_run(label)
        vp = self._p()
        r = vp.add_run(' '); run_props(r, FONT_M, 10, P['INK0'])
        p_border(vp, 'bottom', P['RULE_STRONG'], sz=4, space=2)
        vp.paragraph_format.space_after = Pt(10)

    def bullets(self, items):
        for it in items:
            p = self.doc.add_paragraph(it, style='List Bullet')
            p.paragraph_format.left_indent = Twips(IND + 720)
            p.paragraph_format.right_indent = Twips(IND)

    def table(self, headers, rows=None, n_blank_rows=0, col_weights=None):
        """Brand table: ink-void mono header row, zebra body, severity auto-tint."""
        data = list(rows or [])
        data += [[''] * len(headers)] * n_blank_rows
        t = self.doc.add_table(rows=1 + len(data), cols=len(headers))
        w = col_weights or [1] * len(headers)
        tot = sum(w)
        widths = [round(CONTENT * x / tot) for x in w]
        widths[-1] = CONTENT - sum(widths[:-1])
        table_setup(t, CONTENT, widths, ind=IND, borders={
            'top': (P['RULE'], 4), 'left': (P['RULE'], 4), 'bottom': (P['RULE'], 4),
            'right': (P['RULE'], 4), 'insideH': (P['RULE'], 4), 'insideV': (P['RULE'], 4)})
        tp_ = t._tbl.tblPr
        m = el('w:tblCellMar')
        for k, v in (('top', 110), ('left', 140), ('bottom', 110), ('right', 140)):
            m.append(el('w:' + k, w=str(v), type='dxa'))
        ins(tp_, m, SUCC_TBLCELLMAR)
        for j, htext in enumerate(headers):
            c = t.rows[0].cells[j]
            shade(c, P['INK_VOID'])
            r = c.paragraphs[0].add_run(str(htext))
            run_props(r, FONT_M, 7, 'FFFFFF', caps=True, spacing=6)
        trPr = t.rows[0]._tr.get_or_add_trPr()
        trPr.append(el('w:trHeight', val='420', hRule='atLeast'))
        for i, row in enumerate(data, start=1):
            for j, val in enumerate(row):
                c = t.rows[i].cells[j]
                txt = str(val)
                sev = SEV_MAP.get(txt.strip().lower())
                if sev:
                    fg, bg = sev
                    shade(c, P[bg])
                    r = c.paragraphs[0].add_run(txt)
                    run_props(r, FONT_M, 8.5, P[fg], bold=True, caps=True, spacing=10)
                else:
                    if i % 2 == 0: shade(c, P['PAPER1'])
                    r = c.paragraphs[0].add_run(txt)
                    run_props(r, FONT_S, 9.5, P['INK1'])
        return t

    def save(self, path):
        self.doc.save(path)
        return path


# ---------------------------------------------------------------- workbooks
def rv_workbook(title, meta=None, columns=None, n_rows=25, sheet_name=None,
                confidential=True, severity_headers=('severity','impact','likelihood',
                'priority','status','result','risk')):
    """Branded openpyxl workbook: dark band w/ centered logo, title, meta rows,
    ink-void header row, zebra body, severity conditional formatting."""
    import openpyxl
    from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
    from openpyxl.formatting.rule import Rule
    from openpyxl.styles.differential import DifferentialStyle
    from openpyxl.utils import get_column_letter
    from openpyxl.drawing.image import Image as XLImage
    from openpyxl.drawing.spreadsheet_drawing import OneCellAnchor, AnchorMarker
    from openpyxl.drawing.xdr import XDRPositiveSize2D
    from openpyxl.utils.units import pixels_to_EMU

    def fill(h): return PatternFill('solid', start_color='FF'+h, end_color='FF'+h)
    def side(h, st='thin'): return Side(style=st, color='FF'+h)

    columns = columns or [('Column A', 20)]
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = sheet_name or title[:31]
    ws.sheet_view.showGridLines = False
    ws.sheet_properties.tabColor = 'FF' + P['SIGNAL']
    maxc = len(columns)

    # band
    ws.row_dimensions[1].height = 30
    for cn in range(1, maxc + 1):
        c = ws.cell(row=1, column=cn)
        c.fill = fill(P['INK_VOID'])
        c.border = Border(bottom=side(P['SIGNAL'], 'medium'))
    a1 = ws.cell(row=1, column=1)
    a1.value = '        RiskVoid'   # leading spaces clear the anchored logo
    a1.font = Font(name=FONT_D, size=13, bold=True, color='FFFFFFFF')
    a1.alignment = Alignment(horizontal='left', vertical='center')
    if confidential and maxc > 2:
        last = ws.cell(row=1, column=maxc)
        last.value = 'CONFIDENTIAL'
        last.font = Font(name=FONT_M, size=8, color='FF' + P['COVER_TEXT'])
        last.alignment = Alignment(horizontal='right', vertical='center')
    img = XLImage(LOGO)
    marker = AnchorMarker(col=0, colOff=pixels_to_EMU(8), row=0, rowOff=pixels_to_EMU(9))
    img.anchor = OneCellAnchor(_from=marker,
                               ext=XDRPositiveSize2D(cx=pixels_to_EMU(22), cy=pixels_to_EMU(22)))
    ws.add_image(img)

    # title + meta
    ws.row_dimensions[2].height = 30
    t = ws.cell(row=2, column=1)
    t.value = title
    t.font = Font(name=FONT_D, size=20, bold=True, color='FF' + P['INK0'])
    rn = 4
    for label in (meta or []):
        lc = ws.cell(row=rn, column=1)
        lc.value = label.upper()
        lc.font = Font(name=FONT_M, size=8, color='FF' + P['INK3'])
        vc = ws.cell(row=rn, column=2)
        vc.font = Font(name=FONT_M, size=10, color='FF' + P['INK0'])
        vc.border = Border(bottom=side(P['RULE_STRONG']))
        rn += 1
    hdr = rn + 1

    # header row
    ws.row_dimensions[hdr].height = 26
    for j, (name, width) in enumerate(columns, start=1):
        ws.column_dimensions[get_column_letter(j)].width = width
        c = ws.cell(row=hdr, column=j)
        c.value = str(name).upper()
        c.fill = fill(P['INK_VOID'])
        c.font = Font(name=FONT_M, size=8, color='FFFFFFFF')
        c.alignment = Alignment(horizontal='left', vertical='center', wrap_text=True)
        c.border = Border(bottom=side(P['SIGNAL'], 'medium'))

    # body
    thin = Border(left=side(P['RULE']), right=side(P['RULE']),
                  top=side(P['RULE']), bottom=side(P['RULE']))
    for i in range(hdr + 1, hdr + 1 + n_rows):
        zebra = (i - hdr) % 2 == 0
        for j in range(1, maxc + 1):
            c = ws.cell(row=i, column=j)
            c.font = Font(name=FONT_S, size=10, color='FF' + P['INK1'])
            c.alignment = Alignment(vertical='top', wrap_text=True)
            c.border = thin
            c.fill = fill(P['PAPER1'] if zebra else P['PAPER'])
    ws.freeze_panes = ws.cell(row=hdr + 1, column=1)

    # severity conditional formatting
    rules = [('Critical','SEV_CRIT','SEV_CRIT_BG'), ('High','SEV_HIGH','SEV_HIGH_BG'),
             ('Medium','SEV_MED','SEV_MED_BG'), ('Low','SEV_LOW','SEV_LOW_BG'),
             ('Resolved','SEV_OK','SEV_OK_BG'), ('Pass','SEV_OK','SEV_OK_BG'),
             ('Fail','SEV_CRIT','SEV_CRIT_BG')]
    for j, (name, _) in enumerate(columns, start=1):
        if not any(k in str(name).lower() for k in severity_headers):
            continue
        col = get_column_letter(j)
        rng = f'{col}{hdr+1}:{col}{hdr+n_rows}'
        anchor = f'{col}{hdr+1}'
        for text, fg, bg in rules:
            dxf = DifferentialStyle(font=Font(name=FONT_M, size=9, bold=True, color='FF'+P[fg]),
                                    fill=fill(P[bg]))
            rule = Rule(type='containsText', operator='containsText', text=text, dxf=dxf)
            rule.formula = [f'NOT(ISERROR(SEARCH("{text}",{anchor})))']
            ws.conditional_formatting.add(rng, rule)
    return wb
