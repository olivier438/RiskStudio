# 🛡️ Risk Studio

> A GRC risk catalogue and a deterministic threat intelligence feed, open and built for cybersecurity professionals.

[![License](https://img.shields.io/badge/license-CC%20BY--SA%204.0-lightgrey)](LICENSE)
[![Frameworks](https://img.shields.io/badge/frameworks-ISO%2027001%20%7C%20NIS2%20%7C%20DORA%20%7C%20CyFun%20%7C%20NIST%20CSF-orange)](docs/architecture.md)

**v5 is a full rebuild, in progress on the `v5` branch.** The v4 application stays online from `main` until v5 replaces it. Its code is kept in [`legacy/`](legacy/) as the visual reference.

## What is Risk Studio?

Two products under one interface:

- **GRC catalogue**: a structured library of cybersecurity risks, mapped to ISO/IEC 27001:2022, NIS2, DORA, CRA, CyFun and NIST CSF 2.0, for IT and OT environments.
- **Threat intelligence feed**: vulnerabilities, advisories and data leaks collected from authoritative sources (CISA KEV, NVD, FIRST EPSS, ENISA EUVD, CERT-FR, CCB...), scored and linked to the catalogue risks they materialise.

## What changes in v5

| | v4 | v5 |
|---|---|---|
| Classification | LLM (Groq / LLaMA) | **No AI.** Explicit, auditable rules, stored with each item |
| Hosting | Supabase, Cloudflare, GitHub Pages (US) | **Infomaniak shared hosting** (Switzerland) |
| Back end | Supabase REST + RLS | PHP 8.3 API + MariaDB, least-privilege users and public views |
| Front end | Single HTML files | SvelteKit static build, strict CSP without `unsafe-inline` |
| Editorial flow | Agent published directly | Only authoritative sources publish directly, the rest is reviewed |

Details: [docs/architecture.md](docs/architecture.md).

## Roadmap

- [x] **Phase 1, foundations**: schema, reference data, PHP API skeleton, Svelte shell, CI
- [x] **Phase 2, catalogue**: 167 risks migrated with corrected ISO 27001:2022 mappings, CyFun 2023, DORA and CRA controls, crosswalk to NIS2, CyFun and NIST CSF 2.0 ([migration report](docs/catalogue-v4-migration.md))
- [x] **Phase 3, front end**: GRC, Cyber and Data Leaks views, shareable filters, selection, CSV and PDF export, local edit mode, polling with toasts and browser notifications, "why" panel showing the rules behind each alert
- [x] **Phase 4, collector**: CISA KEV, ENISA EUVD, CERT-FR, Have I Been Pwned, ransomware.live; FIRST EPSS and NVD enrichment; rule-based classification, scoring and links to the catalogue, all traceable ([rules](db/rules/README.md))
- [ ] **Phase 5, administration**: login with TOTP, moderation, proposals, CRA tab, statistics
- [ ] **Phase 6, deployment**: Infomaniak packaging, documentation, SBOM
- [ ] **V2**: user environment profile (sectors, technologies, frameworks) to filter the feed

## Local development

Requirements: PHP 8.2+ with `pdo_mysql`, Composer, MariaDB 10.6+, Node.js 22+ (build only).

```bash
make setup     # PHP and front-end dependencies
make db        # database, least-privilege users, migrations, seeds, catalogue
make catalogue # validate and import db/catalogue after editing it
make fixtures  # fictitious feed data to work on the UI (development only)
make collect   # run the collector now on every enabled source
make dev       # API on :8080 and front end on :5173
make check     # PHP tests and front-end type check
make preview   # production build served like Apache would, on :8090
```

## Repository layout

```
api/       PHP API (src/, public/, bin/migrate.php, tests/)
web/       SvelteKit front end
db/        migrations/, seeds/, catalogue/ (editable CSV sources), grants.sql
docs/      architecture and deployment
scripts/   local tooling
legacy/    v4 application, reference only
```

## Contributing

- **Propose a risk** from the application (moderated).
- **Issues and pull requests** are welcome on GitHub.
- Catalogue content in French, code and documentation in English.
- Each risk maps to at least one framework reference and declares its CIA impact (Confidentiality, Integrity, Availability).

## License

Catalogue content: [Creative Commons BY-SA 4.0](LICENSE). Source code: MIT.

## Author

Built by **Olivier Delvigne, One Circle IT Solutions srl**: CISO as a Service, ISO 27001 Lead Implementer, GRC consultant with 25+ years in IT. [LinkedIn](https://www.linkedin.com/in/odocits)
