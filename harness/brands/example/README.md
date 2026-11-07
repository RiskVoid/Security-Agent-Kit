# Custom report brand (example)

The client report (`./rvkit report <engagement>`, or the agent's `generate_report` tool) uses the RiskVoid design
by default. To put your own name, logo, colours and fonts on it, copy this folder somewhere outside the kit, edit
it, and set in the kit's `.env`:

```
REPORT_BRAND=custom                       # riskvoid (default) | plain | custom
REPORT_BRAND_FOLDER=/path/to/your/brand   # this folder, copied and edited
ORG_NAME=                                 # optional: overrides org_name below
```

then run `./rvkit up`. The folder is mounted read-only at `/brand-custom` in the findings-mcp container. The layout, sections, evidence tables and severity colours are the same for every brand.

`REPORT_BRAND=plain` needs no folder: no logo, neutral slate colours, Arial / Courier New, and `ORG_NAME` (if set)
as the name.

## Folder contents

| File | Required | Used for |
|---|---|---|
| `brand.json` | yes | name, footer, colours, fonts (below) |
| `logo.png` | no | logo in the running header of every page (white background). Any aspect ratio up to 4:1; transparent background recommended. Without it the header shows the name only. |
| `logo-white.png` | no | logo on the dark cover band and the spreadsheet band. Defaults to `logo.png`. |
| `fonts/` | no | `.ttf` / `.otf` files for fonts that are not installed in the container. |

The logos in this example are placeholders: replace them.

## brand.json

| Field | Required | Default | Meaning |
|---|---|---|---|
| `org_name` | yes, unless `ORG_NAME` is set | | Your organisation. Shown next to the logo in the header bars and used as the default "Prepared by" on the cover. `ORG_NAME` overrides it. |
| `footer` | no | `org_name` in capitals | Footer text after "CONFIDENTIAL ·", usually your web address. `""` for none. |
| `show_name` | no | `true` | `false` hides the name in the header bars (when the logo already contains it). |
| `colors.primary` | no | `#1F2937` | Cover band, table header rows, spreadsheet header. |
| `colors.accent` | no | `#4B5563` | Spreadsheet tab colour and header rule. |
| `colors.cover_text` | no | `#9CA3AF` | "CONFIDENTIAL" on the cover band. |
| `fonts.display` | no | `Arial` | Title and headings. |
| `fonts.body` | no | `Arial` | Body text and tables. |
| `fonts.mono` | no | `Courier New` | Labels, code, hashes, footers. |
| `palette` | no | | Advanced: override any colour of the base design by its key (`INK0`-`INK3` text greys, `RULE`, `RULE_STRONG`, `PAPER1`, `SEV_*` severity colours, ...; see `harness/brand/rv_brand.py`). |

Colours are 6-digit hex, with or without `#`. Fields starting with `_` are ignored (use them for comments); any
other unknown field is an error.

Fonts must exist in the report container, otherwise the report fails with the list of installed families. Installed:
Space Grotesk, Inter Tight, JetBrains Mono, DejaVu Sans / Serif / Sans Mono, and Arial, Helvetica, Courier New and
Times New Roman (rendered with the metric-compatible Liberation fonts). For anything else, put the font files in
`fonts/`. The PDF embeds the fonts; the .docx only names them, so the reader's Word needs them installed too (or
substitutes its own).

Per engagement, `report/meta.txt` still overrides "Prepared by". Note that meta.txt is created on the first report
run with the brand's name filled in, so an engagement first reported under another brand keeps that name until you
edit it.

If the brand folder or brand.json is missing or invalid, report generation stops with an error that says what to fix;
nothing is written.
