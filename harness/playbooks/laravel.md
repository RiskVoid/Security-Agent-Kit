---
version: 1
title: Laravel application (source-assisted)
standard: OWASP ASVS 5.0 level 2, OWASP API Security Top 10 2023; Laravel security documentation
tiers: passive, active (intrusive steps need approvals)
---
# Laravel application, with source and a staging deployment

Use with the source in scope (`/src/<app>`) and a staging deployment of the same build. Run the web-app and
api-security playbooks alongside for the generic checks; this one covers what the framework changes.

## 1. Orientation and build identity (passive)
- [ ] `laravel_map` on `/src/<app>` with `build_url` set to the deployment's version endpoint or a page that
      sends a build header (ask the user which one). Save the leads, controls and gaps into PLAN.md. Refs: ASVS V15.
- [ ] Build identity: if the deployed build **doesn't match** the source digest, say so in PLAN.md and in the
      report; runtime results then don't prove anything about this source. Ask the user for the matching build.
- [ ] Framework and PHP versions from the map; dependencies: the supply-chain playbook (osv-scanner on
      `composer.lock`). Refs: ASVS V15, API9:2023.
- [ ] Routes: the map's static routes. If the user can provide `php artisan route:list --json` (from the client,
      or `./rvkit php <eng> routes <path>` on the host, which boots the code in an isolated container and asks
      first), pass it as `routes_file` and list routes only one side has. Refs: API9:2023.

## 2. Pattern analysis (passive)
- [ ] `analyze_source` semgrep with rulesets `php` (it includes the laravel rules), on the app's own code. Refs: ASVS V15.
- [ ] Note what Semgrep can't see: Blade templates, authorization that depends on route binding and policies,
      mass assignment through `$guarded`. The map's leads cover those; Semgrep's absence of results isn't a clean
      bill. Joern has no PHP frontend in this kit: no data-flow claims from Joern for PHP.
- [ ] Secrets: the secrets-review playbook (`.env` committed, keys in `config/`). Refs: ASVS V13.

## 3. Identities and fixtures (host, with the user)
- [ ] At least two tenants with two roles each where possible (an admin and a member of tenant A, an admin of
      tenant B). Ask the user to store the credentials and define identities (see docs/authenticated-testing.md),
      with fixtures: one record per tenant per resource you'll test, each with a marker only it contains.
- [ ] `check_identity` each one. Only `valid` identities count; others make the tests blocked.

## 4. Authorization (active; writes need approvals)
For every lead of kind `object-authorization` and every route with a bound model:
- [ ] Propose an authorization matrix: the route as each identity and anonymous, with the expected allow/deny
      from the client's role documentation or the user. Include routes the map shows as **controls** (route
      `can`, `authorize` calls, tenant scopes): they are the protected cases and should pass. Refs: WSTG-ATHZ-04, API1:2023, ASVS V8.
- [ ] Run it once approved. A `FAIL` cell with the other tenant's marker in the response is the evidence; repeat
      it with `replay_request` or `http_request` once, and record it. Refs: WSTG-ATHZ-04, API1:2023, ASVS V8.
- [ ] Function-level: admin-only routes as a member (`can:` middleware, policies' `before`, `is_admin` checks). Refs: WSTG-ATHZ-03, API5:2023, ASVS V8.
- [ ] File downloads (`file-download` sinks, `Storage::download`): another tenant's document id; path
      parameters with `../`. Refs: WSTG-ATHZ-01, ASVS V5.

## 5. Input handling (active; intrusive for injection payloads)
- [ ] `mass-assignment` leads: as a write-capable identity, send the extra field (role, organization_id,
      is_admin) and read the account back. Restore it afterwards (cleanup in the matrix, or by hand) and say so. Refs: API3:2023, ASVS V15.
- [ ] `raw-sql` leads: trace the variable to request input in the source first; then a boolean or error-based
      check on staging with an approval. No data extraction beyond proving it. Refs: WSTG-INPV-05, ASVS V1.
- [ ] `unescaped-output` leads: who can write the field, and who sees it. Store a harmless marker
      (`<b>rv-xss-check</b>`) and look for it unescaped in the page (`browse`), with an approval. Refs: WSTG-INPV-02, ASVS V1.
- [ ] Validation: routes using `validated()` or Form Requests are controls; `$request->all()` into a model is
      the lead. Refs: ASVS V2.

## 6. Configuration (passive and active)
- [ ] Debug mode: a 404 or a malformed request on staging; a debug page (Ignition, stack trace, environment
      values) is the evidence. `APP_DEBUG=true` in a committed `.env` is a source finding. Refs: WSTG-ERRH-01, ASVS V13.
- [ ] Session and cookies: `config/session.php` (secure, http_only, same_site), the cookies the login sets. Refs: WSTG-SESS-02, ASVS V7.
- [ ] Exposed tooling: `/telescope`, `/horizon`, `/_ignition`, `/log-viewer`, `/storage` listings. Refs: WSTG-CONF-05, ASVS V13.
- [ ] External effects: mail, notifications and outbound HTTP the map lists. Don't trigger them on a deployment
      that isn't isolated (ask); a staging that logs or captures mail is fine.

## 7. Findings
- One finding per root cause: a missing policy check on five routes is one finding with five instances.
- Evidence: the map (source locations), the matrix or replay result (runtime), the build identity match.
- Don't report controls as weaknesses, and don't report leads that runtime testing didn't confirm: list them as
  tested, with the result.

## Done when
- The build identity is recorded (matched, or the mismatch stated).
- Every map lead is confirmed, refuted with evidence, or listed as blocked with the reason.
- Every route with a bound model was tested as another tenant, or listed as not tested with the reason.
- Writes made during testing are undone, or listed in the report with what remains.
