# Google Docs / Sheets import pitfalls (and how rv_brand.py works around them)

These were discovered the hard way while iterating on the RiskVoid templates.
Every rule below exists because breaking it produced a visibly broken document
after Drive import. If you change the chrome layout, re-test in Google Docs.

## Word → Google Docs

1. **Tables are clamped to page margins.** Negative `tblInd` (the classic Word
   full-bleed trick) is ignored — the table snaps back inside the margins.
   → The only reliable full-bleed: page margins = 0 and inset the body content
   with paragraph indents (960 twips) instead.

2. **Table cell margins (`tcMar`/`tblCellMar`) are dropped on import.** A bar
   that insets its text with a 960-twip left cell margin renders with the text
   jammed against the page edge in GDocs, and wide margins can distort the
   table's width. → All insets inside chrome bars must be real spacer COLUMNS
   (gridCol widths are honored); keep cell margins at/near zero. This is why
   `_bar()` is [spacer][logo][text][spacer] and `_footer_bar()` is
   [spacer][text][spacer].

3. **Give logo cells slack.** An image as wide as its cell's text area gets
   its right edge clipped. Logo columns are image width + ~240 twips.

4. **`w:position` on runs is ignored for inline images.** Baseline-shifting a
   logo to optically center it does nothing after import.
   → Put the logo in its own table cell with `vAlign=center`, text in a second
   centered cell. Cell vertical alignment survives everywhere.

5. **A table that starts a header gets an empty line inserted above it** on
   import, which renders as a white strip above the cover band.
   → Keep a controlled 1pt leading paragraph before the band table and shade
   it INK_VOID so whatever height GDocs gives it, it renders dark and merges
   with the band.

6. **Empty header/footer paragraphs render at a full line height** even with a
   1pt run, because line height derives from the paragraph mark.
   → "Crush" placeholder paragraphs: 1pt run + exact 20-twip line spacing +
   paragraph-mark size 2 half-points (see `crush()` in rv_brand.py).

7. **`WidthType.PERCENTAGE` tables break.** Always DXA widths, and table width
   must equal the sum of gridCol widths; set widths on cells too.

8. **Metadata grids: avoid `insideH` borders** when cells contain their own
   bottom-border fill lines — the borders stack into a laddered mess. Use only
   a top rule + `insideV` divider.

## Excel → Google Sheets

1. **Cell indent is dropped on import** — text indented to clear an anchored
   logo snaps back and overlaps it. → Use leading spaces in the cell value.

2. **Image anchors keep their EMU offsets.** Vertically center the band logo
   with a `OneCellAnchor` rowOff computed from the row height, not by eye.

3. Merged cells in the band row make fills silently not apply to non-anchor
   cells — unmerge row 1 before styling it.

## Both

- Fonts are NOT embedded. If the machine/Google account lacks Space Grotesk /
  Inter Tight / JetBrains Mono, rendering falls back (Word: Times-like serif).
  This is an installation issue — never "fix" it by changing the brand fonts.
- Verify renders with LibreOffice → PDF → PNG before delivering; it catches
  most geometry issues (though not the GDocs-specific ones above).
