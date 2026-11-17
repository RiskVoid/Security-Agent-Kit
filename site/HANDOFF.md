# Security Agent Kit page: implementation handoff

This folder is a finished, approved mockup of the Security Agent Kit page. Implement it in the
`riskvoid.io` repository (the Next.js app that serves riskvoid.com) at the route **`/security-agent-kit`**.

| File | What it is |
|---|---|
| `security-agent-kit.html` | The mockup. One self-contained file: markup, CSS and two small scripts. **It is the source of truth for layout and copy.** Open it in a browser first. |
| `assets/console-overview.png`, `assets/console-findings.png` | Real console screenshots, 2880 px wide (2x). |
| `assets/full-run.gif` | Recording of a full run, 960x600, 3.3 MB. |
| `assets/samples/*.pdf` | Two sample reports linked from the page. |
| `HANDOFF.md` | This brief. |

## Paste this into Claude Code in the riskvoid.io repo

> Implement the Security Agent Kit page at `/security-agent-kit`. The approved mockup and brief are in
> `/Users/ruslansazonov/development/riskvoid-agent-kit/site/`. Read `HANDOFF.md` there first, then
> `security-agent-kit.html`. Match the mockup's layout and use its copy word for word. Follow this repo's
> CLAUDE.md, reuse the landing-v2 components and `mk-*` styles where they fit, and run `npm run check:copy`,
> `npm run lint` and `npm run build` before you finish.

## Ground rules

1. **Copy is final.** Use the text in the mockup word for word. Do not rewrite, lengthen or add marketing
   lines. Every section title was shortened on purpose so it fits on one line on desktop. Keep that.
2. **No arrows and no em dashes** in any user-facing text (the repo's hard rule). The mockup already
   complies. Diagram connectors are plain CSS lines, not arrow glyphs. `npm run check:copy` must pass.
3. **Do not invent UI.** The page shows the product only through the real screenshots and the recording in
   `assets/`. Do not build mock console panels, fake terminals with window chrome, or sample approval cards.
4. **Do not invent numbers.** No star counts, user counts or logos of customers. The benchmark and comparison
   tables are dated facts from the kit's docs. Keep the dates shown next to them.
5. **Server-render the content.** Only the three interactive pieces below are client components.
6. Do not use the words "autonomous", "replaces pentesters" or "uncensored" anywhere.

## Where it goes in riskvoid.io

- Route: `src/app/security-agent-kit/page.tsx`, composed like `src/app/page.tsx` (a `<main className="rv-landing">`
  with one component per section).
- Components: a new folder `src/components/security-agent-kit/`, one file per section, same style as
  `src/components/landing-v2/`.
- Styles: the mockup uses the same design tokens as `src/styles/landing/tokens.css` (`--bg-0`, `--text-1`,
  `--accent`, `--sev-*`, radii, fonts). Use the existing tokens and `mk-*` classes (`mk-section`,
  `mk-container`, `mk-eyebrow`, `mk-h2`, `mk-grid-3`, `mk-faq`, and so on) wherever they already give the
  same result. Add page-specific rules to a new stylesheet next to `landing.css` only for what is missing.
  Do not copy the mockup's `:root` block; it duplicates the tokens.
- Footer: reuse `MarketingFooter`. Add the kit's own links (Documentation, Security policy, Licence,
  Third-party notices, Changelog, GitHub) as shown in the mockup's footer, either as a prop or as a small
  band above it.
- Header: the mockup has page-specific links (What it does, Controls, Harness, Your data, Benchmarks,
  Compare, FAQ), a GitHub button and a "Quick start" button in place of Sign in / Request access.
  `MarketingNav` has a fixed `LINKS` list today. Give it optional `links` and right-side action props, or
  make a thin `KitNav` that shares its markup and mobile drawer. Keep the brand lockup linking to `/`.
  The links must be centred on the page (the mockup uses a three-column grid: `1fr auto 1fr`).

## Sections, top to bottom

Anchor ids are the ones the header links to. Keep them.

| # | id | Mockup block | Notes |
|---|---|---|---|
| 1 | | Hero | Centred. Eyebrow, H1 with "a client" in the accent highlight (same device as the red "before" on the home page, but accent blue), one-sentence lede, four fact chips, three buttons, copyable install command, the "authorised work only" line, then the run recording in a bordered frame with a one-line caption. |
| 2 | | Proof strip | Two centred rows: "Built on" logos and "Methods". Label above each row. |
| 3 | `why` | Three claim cards | Numbered 01 to 03. Title, one sentence, three bullets. |
| 4 | `who` | Three audience cards | Chip, title, one sentence, link at the bottom. |
| 5 | `work` | Work table | Nine rows: icon, work, method, example tools. Three small cards under it and a one-line "not covered yet" note. On mobile each row stacks. |
| 6 | `controls` | Screenshot plus eight controls | `console-overview.png` full width with caption, then the eight controls in a four-column grid. |
| 7 | `data` | Worker selector | Interactive. See below. |
| 8 | `how` | Architecture diagram | One row of five boxes with the dashed "Scope firewall" between sandbox and target, and a second row of four dashed boxes. Pure HTML and CSS. |
| 9 | `harness` | Nine harness cards | Three by three. Mono label, short title, one line. |
| 10 | `see` | Screenshot plus deliverable | `console-findings.png` full width with caption, then a band: text and format chips on the left, two sample report links on the right. |
| 11 | `benchmarks` | Results table | Nine rows with small bars. Dated note under it, three takeaway cards, link to full results. |
| 12 | `compare` | Comparison table | Our column is tinted. Dated note under it. |
| 13 | `agents` | Coding agent | Two columns: text, agent logos, three example asks on the left; a plain code block on the right. |
| 14 | `quickstart` | Quick start | Two columns: text, six logos, three requirement rows on the left; code block and two buttons on the right. |
| 15 | `faq` | FAQ | Nine questions. First one open. |
| 16 | | Closing CTA | Centred title, one line, three buttons. |
| 17 | | Bridge band | One quiet line pointing to the main product at `/`. Keep it to one line. |

## Layout details that were asked for explicitly

These came out of review. Please keep them.

- **Card content lines up across a row.** In the claim cards, audience cards and the three data lanes, the
  title, text and list (or link, or "Runs on" box) sit on shared rows, whatever the text length. The mockup
  does this with CSS subgrid (`grid-template-rows: subgrid; grid-row: span 4`). Audience-card links align to
  the bottom.
- **The proof strip is centred**, label above logos, both rows.
- **The header links are centred on the page**, not in the leftover space between logo and buttons.
- **Quick-start logos**: two rows of three, each logo centred in its third of the column.
- **Screenshots keep their aspect ratio** (`height: auto`). Use `next/image` with the real dimensions:
  overview 2880x1760, findings 2880x1400. Both are shown full width of the container.
- **No heading wraps on desktop.** If a title wraps at 1200 px, the layout is wrong, not the title.
- Mobile (below 960 px): every grid becomes one column, header links collapse into the existing mobile
  drawer, nothing scrolls sideways. Wide tables scroll inside their card.

## Interactive pieces (client components)

1. **Copy button** on the hero install command. Copies the command, shows "Copied" for 1.5 s.
2. **Worker selector** (`data`). Five tabs. Selecting one updates the worker destination, the planner
   destination, the "You need" line and the command. The full data is the `W` object at the bottom of the
   mockup. A destination that is "Your machine" (and the planner box in the offline option) gets the green
   style. Use `role="tablist"` / `role="tab"` / `aria-selected`, and arrow-key navigation between tabs.
3. **FAQ accordion.** Reuse the landing `FAQ` component with a data file like `faq-data.ts`.

## Assets

Copy into `public/assets/security-agent-kit/`:

- `console-overview.png`, `console-findings.png`: use as they are. Write real alt text (the mockup has it).
- `full-run.gif`: 3.3 MB. Prefer converting it to a muted, looping, inline `<video>` (MP4 plus WebM) with the
  first frame as poster, and `prefers-reduced-motion` showing the poster only. Keep the GIF as fallback only
  if video is a problem.
- `samples/ledgerly-report-riskvoid.pdf`, `samples/ledgerly-report-plain.pdf`: link targets for the two
  sample report rows. Open in a new tab.

**Logos.** The mockup hot-links logos so it could be reviewed. Do not ship hot-links. Self-host them as SVG
under `public/assets/logos/`, in the neutral grey `#c8ccd4`, about 20 px:

| Where | Logos | Simple Icons slug |
|---|---|---|
| Built on | Kali Linux, Model Context Protocol, SearXNG, Docker | `kalilinux`, `modelcontextprotocol`, `searxng`, `docker` |
| Built on | OpenHands, LiteLLM | not in Simple Icons. The mockup uses their GitHub org avatars. Get the official marks from each project, or show the name without a logo. |
| Methods | OWASP | `owasp` (PTES, MITRE ATLAS and SLSA / OpenSSF are text only) |
| Coding agents | Claude Code, Cursor, GitHub Copilot, Gemini CLI | `claude`, `cursor`, `githubcopilot`, `googlegemini` (Codex is text only) |
| Quick start | macOS, Linux, Docker, OpenRouter, Colab, Ollama | `apple`, `linux`, `docker`, `openrouter`, `googlecolab`, `ollama` |

Check each project's logo-use terms before launch. The inline icons in the work table and controls list
are simple stroke icons defined as `<symbol>`s at the top of the mockup; use the repo's icon set
(`landing-v2/icons.tsx` or lucide) for the same shapes.

## Data to keep as typed arrays

Put these in a data file in the component folder so they are easy to update, with the date beside them:

- Work table rows (9).
- Benchmark rows (9), measured 2026-11-10.
- Comparison matrix (7 rows, 5 projects), checked 2026-11-08.
- Worker options (5).
- FAQ items (9).

## SEO

- `metadata.title`: `Security Agent Kit: self-hosted AI pentesting with guardrails`
- `metadata.description`: the `<meta name="description">` text in the mockup.
- `alternates.canonical`: `/security-agent-kit`. Open Graph and Twitter card to match.
- JSON-LD: `SoftwareApplication` (name RiskVoid Security Agent Kit, applicationCategory SecurityApplication,
  operatingSystem macOS and Linux, license Apache-2.0, codeRepository, softwareVersion 0.1.0, offers price 0),
  `FAQPage` generated from the FAQ data, and `BreadcrumbList`.
- Add the route to `src/app/sitemap.ts`.
- The kit's `llms.txt` and README already point to `https://riskvoid.com/security-agent-kit`.

## Links

- Repository: `https://github.com/RiskVoid/Security-Agent-Kit`. All "docs" links in the mockup go to files
  in that repository. Confirm the repository is public before the page goes live.
- External links open in a new tab with `rel="noopener"`.

## Open points to raise with Ruslan, not to decide alone

1. Whether the home page nav and footer should link to this page.
2. The run recording shows the older console layout in a few frames, and an unrelated conversation title in
   the agent UI sidebar. It should be re-recorded before launch; ship with the current one only if he says so.
3. There is no real screenshot of a pending approval yet. If one is supplied, it belongs in `controls`.
4. Analytics: if the site tracks events, the useful ones here are the GitHub click, the copy of the install
   command and the sample report downloads.

## Done means

- `/security-agent-kit` matches the mockup at 1440, 1200 and 375 px wide.
- Copy is identical to the mockup.
- `npm run check:copy`, `npm run lint` and `npm run build` pass.
- No request leaves the site for logos, fonts or images that the rest of riskvoid.com does not already make.
- Lighthouse performance and accessibility are in line with the home page.
