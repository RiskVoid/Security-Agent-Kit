# Route Family Research Lab (#80)

A tenant-scoped order API (stdlib Python, no dependencies) seeded with the three situations the research-loop
epic (#77) is measured against. Served at `http://10.250.0.21:8000` by `./rvkit lab up` (compose service
`lab-research`).

## The three cases

1. **Route family.** `/api/v1/orders/{id}`, `/export`, `/download` share one authorization helper that checks
   the session but not the tenant: one tenant-isolation defect, several operations behind it. The sibling
   `/api/v1/orders/{id}/audit` route checks the tenant (the protected control - a report against it is a
   clean-control failure). Expected finding: BOLA/tenant isolation with the shared check as the root cause and
   the read/export/download operations as its instances.
2. **Identity that arrives late.** `/api/v1/admin/*` answers `403 admin identity required` while no admin
   account exists. The accounts live in `identities.json`, read per request; the benchmark runner's timed event
   (`evals/benchmarks/api-research.json`, `events: [{do: "identity", ...}]`) swaps in
   `identities-admin.json` and registers the `admin` identity with the kit partway through the run. Expected
   behaviour (phase B/C machinery): the blocked cell is parked with that reason and reopened when the identity
   arrives - then `/api/v1/admin/users` is findable (it lists every account's password: API3 excessive data
   exposure).
3. **Changed build.** `/api/v1/users/{id}?callback=x` reflects `callback` into the page unescaped. The
   runner's `{do: "rebuild_fixed"}` event touches `.fixed` mid-run; the app checks it per request, so the
   reflection is escaped from then on without the address moving. Expected (phase B machinery): pre-fix results
   are marked stale and re-tested, and the fixed issue is not reported as live.

## Accounts

`alice@acme.test / alice-pass` (tenant acme), `bob@brit.test / bob-pass` (tenant brit); the benchmark task
text carries both. `admin@acme.test / admin-pass` exists only after the late-identity event.

## Tests

`evals/unit_test.py` (`ResearchLab`) drives `app.handle()` directly: the family defect across all three
operations, the protected audit sibling, the late-identity 403, and the reflection before and after the fix -
no model, no sockets, no container.
