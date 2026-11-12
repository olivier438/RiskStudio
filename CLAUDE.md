# Risk Studio | Notes for Claude

## Product constraints (decided, do not reopen)

- **No AI dependency** in the product. Classification is rule-based and traceable (`rule_trace`).
- **Infomaniak shared hosting**: PHP + MariaDB + scheduled tasks. No Node.js, no long-running process in production. Node.js is a build tool only.
- **V1 has no end users**: public read-only, one admin, the collector. V2 adds users who only write their environment profile.
- Keep the v4 look and features (`legacy/` is the reference).

## Conventions

- Never use em dashes or en dashes, anywhere (code, docs, UI, commits).
- Always keep French accents in French text.
- Prefer English terms or full names over francised acronyms (Information Security Policy, not PSSI; CIA, not DIC).
- UI and catalogue content in French, code and docs in English.
- No inline `style` attributes or inline scripts: the CSP forbids `unsafe-inline`.
- ISO/IEC 27001 control titles are copyrighted: store reference numbers only.
- SvelteKit 3: use `#lib/...js` imports, not `$lib`.
- The public API reads only `v_public_*` views and reference tables (`rs_read` user).
- Schema changes go in a new numbered migration; never edit an applied one.
- The catalogue source of truth is `db/catalogue/*.csv`; never edit risks directly in the database. `scripts/legacy/convert-v4-catalogue.php` is a one-shot migration kept for traceability, do not rerun it (it would overwrite edits to risks.csv).
- `db/fixtures/` holds fictitious development data (CVE-2099-*, "Exemple" names). Never load it in production, never use real organisation names in it.
- Tests must not depend on fixtures: integration tests create and clean their own rows.
- Collector: sources only normalise facts, `Classifier` decides, `Store` writes. Classification must stay a pure function of facts + `db/rules/*.csv` (no randomness, no clock, no network). Never store `.onion` links.
- Collector tests run on frozen payloads in `api/tests/fixtures/collector`, never on the network.
- Admin endpoints: always through `AdminController::session()` (authentication + CSRF), answers with `Cache-Control: no-store`, every decision audited. Never add a public write endpoint outside `rs_read` column grants.
- CyFun: store references and NIST CSF 1.1 titles only, never the CCB requirement texts.

## Commands

`make db`, `make catalogue`, `make dev`, `make check`, `make preview` (see Makefile).
