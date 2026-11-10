# Sample reports

Real output of the kit, from the release acceptance run on the Ledgerly lab on 2026-11-10. Ledgerly is the
seeded Laravel 12 application in [`evals/targets/rv-laravel-lab`](../../evals/targets/rv-laravel-lab). Everything
here is lab data: the accounts and tokens are the lab's own fixtures.

| Brand | File | Built from |
|---|---|---|
| RiskVoid (default) | [PDF](riskvoid/ledgerly-report.pdf) | The run's findings, evidence and test plan, as approved in R-003 |
| Plain (`REPORT_BRAND=plain`, `ORG_NAME=Example Security Ltd`) | [PDF](plain/ledgerly-report.pdf) | The same data, in the plain brand |

Both files were printed again on 2026-11-10 with the current report generator, outside the numbered revisions, so
they show today's layout: the PDF is the HTML report printed page by page, with the tools used and what they were
used for, and a section on coverage and limitations.

The run confirmed three findings with evidence: mass assignment to admin (high), cross-tenant invoice and document
reads (medium), and SQL injection in search (medium). Each was retested against the fixed build. The run also had
real gaps: cross-tenant documents were grouped into the invoice finding, and stored XSS and debug mode weren't
reported. [Capability baselines](../capability-baselines.md) has the score.

Each generation also writes an HTML page, a Word document and an Excel findings register; they're left out here
to keep the repository small.
