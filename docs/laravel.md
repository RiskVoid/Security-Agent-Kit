# Laravel engagements

The kit's reference engagement is a Laravel application tested with its source and a staging deployment. This
page covers what the kit adds for Laravel: the application map, build identity, the optional PHP profile, what
the pattern tools can and can't see, and the methodology. Practise on the Ledgerly lab
([lab-and-benchmarks.md](lab-and-benchmarks.md#ledgerly-laravel-lab)).

---

## Application map

```sh
./rvkit appmap acme /src/acme-app --build-url https://staging.acme.test/version
```

The agent calls the same thing as the kali tool `laravel_map`. It reads the source and **runs none of it** (no
PHP, Artisan or Composer), then relates:

| Part | From |
|---|---|
| Framework and PHP versions, notable packages | `composer.json`, `composer.lock` |
| Routes with their effective middleware | `bootstrap/app.php` `withRouting` (or the `RouteServiceProvider`), route files, groups, `prefix`, `name`, `middleware`, `withoutMiddleware`, `can`, `controller`, `resource` / `apiResource` |
| Controller methods | route-bound models, Form Requests, `authorize` / `Gate` / `can` calls, how input is used (`$request->all()`, `validated()`) |
| Models | `$fillable` / `$guarded` against the columns in the migrations (which sensitive columns are mass assignable), global scopes (tenant isolation by trait, `booted()` or `#[ScopedBy]`) |
| Policies, gates, Form Requests | `app/Policies`, `Gate::define` / `Gate::policy`, `authorize()` and `rules()` |
| Views and sinks | unescaped Blade output (`{!! !!}`), raw SQL built from variables, file downloads, commands, `unserialize`, outbound HTTP, mail |

The result has three lists, each item with its source locations:

- **Leads**: candidate issues with the reasoning and how to verify them, for example "GET /api/invoices/{invoice}
  may return any Invoice: the method has no authorize call, the route no `can` middleware, and Invoice no
  tenant scope". A lead is not a finding: it is confirmed or refuted at runtime.
- **Controls**: protections found (route `can`, `authorize` calls, tenant scopes, validated input). Don't report
  these as weaknesses without runtime evidence; test them as the protected cases.
- **Gaps**: what a static map can't see (routes registered by packages, macros or the framework, middleware set
  in constructors, Livewire actions, no Joern data flow for PHP).

The map is saved as audited evidence in `evidence/appmap/laravel-<time>.json`.

### Build identity

The map computes the **source digest** (rvkit source digest v1: SHA-256 over `sha256sum` lines of `app`,
`bootstrap/app.php`, `bootstrap/providers.php`, `config`, `database`, `resources`, `routes`, `composer.json` and
`composer.lock`, sorted by path). With `--build-url` (the tool's `build_url`) it asks the deployment for its build:
the `X-Build-Id` header or a JSON `build` field. It then reports **MATCHES** or **DOES NOT MATCH**: runtime results
from a deployment built from other code don't prove anything about the source you were given. To compute the
same digest in the client's build:

```sh
find app bootstrap/app.php bootstrap/providers.php config database resources routes composer.json composer.lock \
  -type f ! -name .gitignore | LC_ALL=C sort | xargs sha256sum | sha256sum | cut -c1-64
```

### Runtime routes

`--routes <file>` (the tool's `routes_file`) compares the static routes with a runtime export
(`php artisan route:list --json`) in the engagement folder and lists routes only one side has. Get the export
from the client, or from the PHP profile.

---

## PHP profile (optional)

The Kali toolbox has no PHP. The PHP profile is a separate container (PHP 8.4.27 and Composer 2.8, pinned), built
on first use and started only by `./rvkit php`:

```sh
./rvkit php acme lint /src/acme-app      # parse every PHP file with PHP's parser; nothing runs
./rvkit php acme routes /src/acme-app    # boot the app on a copy and export its routes (asks first)
```

- It runs with **no network**, a read-only root, no capabilities and as the engagement's user. The source is
  mounted read-only; `routes` works on a throwaway copy in memory.
- `routes` boots the client's code (service providers, configuration), so it asks before running. It writes a
  generated `.env` (in-memory SQLite, array cache, session and mail, sync queue; no client secrets) over any
  `.env` from the source, and removes cached configuration. It needs `vendor/` in the source: with no network it
  can't install packages.
- Outputs go to `evidence/php/` and are recorded in the audit log (with who approved the boot), so
  `evidence_provenance` verifies them.

---

## Pattern and data-flow tools on PHP

| Tool | On PHP | Measured on Ledgerly |
|---|---|---|
| Semgrep (`analyze_source`, rulesets `php`, includes the laravel rules), offline | parses PHP; doesn't analyse Blade templates | parses all 51 files with no errors; finds 2 session-cookie settings; **misses** the raw SQL, the unescaped Blade output, the mass assignment and the cross-tenant reads |
| Joern | the PHP frontend (`php2cpg`) needs a PHP binary, which the Kali image doesn't have | not available: no data-flow claims for PHP |
| Application map | the framework-level relationships above | flags every seeded flaw as a lead, no leads on the fixed build |

So for Laravel, Semgrep finding nothing is not a clean result: the map's leads and runtime tests carry the
authorization and assignment checks.

---

## Methodology

The `laravel` playbook (`get_playbook laravel`) runs the engagement: map and build identity, pattern analysis,
identities and fixtures, an authorization matrix over every route with a bound model (controls included as the
protected cases), mass assignment with cleanup, raw SQL and Blade output, configuration (debug mode, cookies,
exposed tooling) and external effects. See [authenticated-testing.md](authenticated-testing.md) for identities and
matrices.
