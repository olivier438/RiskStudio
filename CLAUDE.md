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

## Commands

`make db`, `make dev`, `make check`, `make preview` (see Makefile).
