# Sample reports

Real output of the kit, from the release acceptance run on the Ledgerly lab on 2026-11-10. Ledgerly is the
seeded Laravel 12 application in [`evals/targets/rv-laravel-lab`](../../evals/targets/rv-laravel-lab). Everything
here is lab data: the accounts and tokens are the lab's own fixtures.

| Brand | Files | Revision |
|---|---|---|
| RiskVoid (default) | [PDF](riskvoid/ledgerly-report.pdf), [HTML](riskvoid/ledgerly-report.html) | R-003, approved for delivery |
| Plain (`REPORT_BRAND=plain`, `ORG_NAME=Example Security Ltd`) | [PDF](plain/ledgerly-report.pdf), [HTML](plain/ledgerly-report.html) | R-004, the same findings regenerated |

The run confirmed three findings with evidence: mass assignment to admin (high), cross-tenant invoice and document
reads (medium), and SQL injection in search (medium). Each was retested against the fixed build. The run also had
real gaps: cross-tenant documents were grouped into the invoice finding, and stored XSS and debug mode weren't
reported. [Capability baselines](../capability-baselines.md) has the score.

Each generation also writes a Word document and an Excel findings register; they're left out here to keep the
repository small. Download the HTML file to view it: GitHub shows its source, not the page.
