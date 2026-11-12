# Risk Studio v5 | Architecture

## Principles

1. **No AI dependency.** Every classification, score and mapping comes from explicit rules. The rules that fired are stored with each item (`rule_trace`), so any output can be explained and reproduced. This is a feature for NIS2 entities and auditors, not a limitation.
2. **Runs on shared hosting.** Target: Infomaniak web hosting (PHP + MariaDB + scheduled tasks). No long-running process, no container, no Node.js in production.
3. **European hosting, minimal third parties.** No CDN, no external fonts, no analytics. The browser only talks to our own origin.
4. **Least privilege, defence in depth.** The browser never reaches the database. The public API reads through views with a read-only database user.
5. **Two products, one model.** The GRC catalogue and the threat intelligence feed share their vocabularies (categories, sectors, frameworks, vendors) and are linked by `intel_risks`.

## Components

```
            Browser (static Svelte build, strict CSP)
                         |
                  same origin /api/*
                         |
       Apache (Infomaniak) ── api/public/index.php ── PHP 8.3 API
                                                       |
                                     rs_read  (public views, proposals insert)
                                     rs_write (back-office, collector)
                                                       |
                                                  MariaDB 10.6+
                                                       ^
       Scheduled task ── php collector (phase 4) ──────┘
                         |
                 CISA KEV, NVD, EPSS, ENISA EUVD, CERT-FR, CCB, ransomware.live, HIBP
```

| Layer | Technology | Notes |
|---|---|---|
| Front end | SvelteKit 3 + TypeScript, `adapter-static` | Built with Node.js locally or in CI, deployed as plain files |
| API | PHP 8.3, no runtime dependency | Tiny router, PDO, JSON, ETag for cheap polling |
| Database | MariaDB 10.6+ / MySQL 8 | utf8mb4, InnoDB, CHECK constraints, public views |
| Collector | PHP CLI, scheduled task | Phase 4. Small resumable batches to fit shared hosting limits |
| Real time | Polling `/v1/stats` every 60 s (visible tab only), revalidated by ETag | Replaces Supabase Realtime. A 304 costs almost nothing. New items trigger a toast, and a browser notification when critical |

## Database users

| User | Used by | Rights |
|---|---|---|
| `rs_admin` | `api/bin/migrate.php` only | DDL on the schema |
| `rs_write` | Back-office, collector | `SELECT, INSERT, UPDATE, DELETE` |
| `rs_read` | Public API | `SELECT` on reference tables and `v_public_*` views, column-limited `INSERT` on `proposals` (cannot set `status`), `rate_limits` |

Even with an SQL injection in the public API, `rs_read` cannot read drafts, pending items, proposals or admin accounts, and cannot publish anything. The integration tests check these guarantees.

## Data model

- **Reference:** `categories`, `sectors` (NIS2 Annex I and II + Belgian public sectors), `frameworks`, `framework_controls`, `vendors`, `products`.
- **Catalogue:** `risks`, `risk_sectors` (no row means cross-sector), `risk_controls` (with `mapping_source`: `editorial` or `crosswalk`), `control_crosswalk`.
- **Threat intelligence:** `sources`, `intel_items`, `intel_cves`, `intel_cwes`, `intel_products`, `intel_categories`, `intel_sectors`, `intel_risks`, `leaks`.
- **Community and administration:** `proposals`, `admins`, `rate_limits`, `audit_log`, `collector_runs`.

### Catalogue sources

The catalogue lives in `db/catalogue/` as CSV files (risks, framework controls, crosswalk) that can be edited in a spreadsheet and are imported by `api/bin/import-catalogue.php`. Editorial mappings are expanded through the crosswalk into derived mappings, stored separately. See [db/catalogue/README.md](../db/catalogue/README.md).

### Editorial workflow

- Items from **authoritative** sources (`sources.authoritative = 1`: CISA KEV, national CERTs) are published directly.
- Everything else, including community proposals, lands in `pending` and needs an admin decision.
- Every admin and collector action is written to `audit_log`.

### Copyright

ISO/IEC 27001 control titles are copyrighted: only reference numbers (`A.5.1`) are stored. NIS2, DORA and CRA texts are EU legislation, NIST CSF 2.0 is a US government work, CyFun is published by the Centre for Cybersecurity Belgium.

## V2: user environment (planned)

Users stay read-only on all content. They only write their **environment profile**: sectors, IT/OT, followed frameworks, watched vendors and products. The profile has the same shape as the catalogue filters (`RiskFilter`, `RiskQuery` in `web/src/lib/api.ts`), so V2 adds two tables (`users`, `user_environment`) and no rewrite.
