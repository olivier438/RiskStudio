# 🛡️ Risk Studio

> A living, community-driven GRC risk catalogue — open, searchable, and built for cybersecurity professionals.

[![Status](https://img.shields.io/badge/status-active-brightgreen)](https://olivier438.github.io/RiskStudio/)
[![Risks](https://img.shields.io/badge/risks-168-blue)](https://olivier438.github.io/RiskStudio/)
[![License](https://img.shields.io/badge/license-CC%20BY--SA%204.0-lightgrey)](LICENSE)
[![Frameworks](https://img.shields.io/badge/frameworks-ISO%2027001%20%7C%20NIS2%20%7C%20DORA-orange)](https://olivier438.github.io/RiskStudio/)

---

## What is Risk Studio?

Risk Studio is a **free, open-source GRC risk catalogue** designed for cybersecurity consultants, CISOs, risk managers, and compliance professionals.

It provides a structured, searchable library of cybersecurity risks mapped to major regulatory frameworks — **ISO/IEC 27001:2022**, **NIS2**, and **DORA** — covering both IT and OT environments.

No login. No paywall. No bloated platform. Just the risks you need, when you need them.

---

## Why we built it

Most GRC tools are either too expensive, too closed, or too generic.

Risk Studio was born from a simple frustration: every new client engagement starts with rebuilding the same risk catalogue from scratch. Templates are locked behind paywalls. Excel files get stale. Frameworks multiply.

We wanted a **community-maintained, always-current, framework-agnostic** risk library that any GRC professional could use, contribute to, and trust.

---

## Features

- 🔍 **Full-text search** across titles, scenarios, threats, and compliance references
- 🏷️ **Filter by** environment (IT / OT), category, and impact level
- 🗺️ **Multi-framework mapping** — ISO 27001, NIS2, DORA in a single view
- 🔴 **DIC classification** — Disponibilité, Intégrité, Confidentialité per risk
- 📊 **Export to CSV/Excel** with selected risks
- ➕ **Community contributions** — propose new risks via the submission form
- ⚡ **Real-time updates** — agent-powered ingestion from live cyber threat feeds *(coming soon)*
- 🔒 **Security by design** — Supabase backend with Row Level Security, editorial validation

---

## Risk Coverage

| Category | Examples |
|---|---|
| Gouvernance | Absence de politique de sécurité, budget insuffisant |
| Accès & IAM | MFA non activé, privilege escalation |
| Infrastructure | Patch management, misconfiguration cloud |
| Données | Fuite, chiffrement absent, RGPD |
| Continuité | DRP absent, sauvegardes non testées |
| OT / Industrie | SCADA exposure, firmware obsolète |
| Supply Chain | Tiers non audités, dépendance fournisseur |
| IA | Shadow AI, données d'entraînement sensibles |
| ... | 18 categories total, 168+ risks |

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | HTML5 / CSS3 / Vanilla JS — single file, zero dependencies |
| Database | [Supabase](https://supabase.com) (PostgreSQL + REST API + Realtime) |
| Hosting | GitHub Pages |
| Security | Row Level Security (RLS), anon read-only, editorial validation |
| Agent *(coming soon)* | Cloudflare Workers + Claude API |

---

## Roadmap

- [x] Static CSV catalogue (v1–v3)
- [x] Supabase migration with optimised relational schema (v4.0)
- [x] Multi-framework mapping (ISO 27001, NIS2, DORA)
- [x] IT / OT classification
- [x] Community risk submission form
- [ ] Real-time agent ingestion from cyber threat feeds
- [ ] Supabase Realtime — live risk appearance without refresh
- [ ] Admin validation interface
- [ ] CyFun / NIST CSF 2.0 framework mapping
- [ ] Risk scoring & likelihood matrix
- [ ] API public endpoint

---

## Contributing

Risk Studio grows with its community. You can contribute in two ways:

### 1. Propose a risk (no technical skills needed)
Use the **➕ Proposer un risque** button on the live app. Your submission goes into a moderation queue and will be reviewed before publication.

### 2. Contribute via GitHub
```bash
git clone https://github.com/olivier438/RiskStudio.git
cd RiskStudio
```

- **Bug reports & feature requests**: open an [Issue](https://github.com/olivier438/RiskStudio/issues)
- **Pull requests**: welcome for front-end improvements, new framework mappings, documentation

### Contribution guidelines
- Risks must be realistic and based on documented threat scenarios
- Each risk must map to at least one framework reference (ISO 27001, NIS2, DORA, or other)
- DIC classification is mandatory
- Language: French (catalogue), English (code & docs)

---

## License

Risk Studio catalogue content is published under **[Creative Commons BY-SA 4.0](LICENSE)**.  
You are free to use, share, and adapt — with attribution and under the same license.

Source code is MIT licensed.

---

## Author

Built by **Olivier Delvigne / One Circle IT Solutions srl** — CISO as a Service, ISO 27001 Lead Implementer, GRC consultant with 25+ years in IT.

🔗 [LinkedIn] (https://www.linkedin.com/in/odocits)

---

*Risk Studio is part of the ONE CIRCLE IT SOLUTIONS ecosystem.*
