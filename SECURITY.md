# Security Policy — Risk Studio

**ONE CIRCLE IT SOLUTIONS** | [security@onecircle.be](mailto:security@onecircle.be)

---

## Supported Versions

| Version | Supported |
|---------|-----------|
| v4.x (current) | ✅ Active support |
| v3.x and below | ❌ No longer supported |

---

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

Send a report to: **security@onecircle.be**

Include:
- Product and version affected
- Description of the vulnerability
- Steps to reproduce
- CVSS v3.1 score estimate (if available)
- CVE reference (if applicable)
- Impact assessment

PGP encryption available on request.

---

## Coordinated Disclosure Process

| Step | Target |
|------|--------|
| Acknowledgement | ≤ 5 business days |
| Assessment & triage | ≤ 15 days |
| Fix (Critical CVSS ≥ 9) | ≤ 7 days |
| Fix (High CVSS 7–8.9) | ≤ 30 days |
| Fix (Medium CVSS 4–6.9) | ≤ 90 days |
| Fix (Low CVSS < 4) | ≤ 180 days |
| Public disclosure | After fix, max 90-day embargo |

We will credit researchers who wish to be acknowledged.
We will not pursue legal action against reporters acting in good faith.

---

## CRA Regulatory Notification (Art. 14 — Regulation EU 2024/2847)

For actively exploited vulnerabilities in our products, we notify:

| Authority | Deadline |
|-----------|----------|
| **CCB** — Centre for Cybersecurity Belgium (cert@ccb.belgium.be) | **24 hours** (early warning) |
| **ENISA** — EU Agency for Cybersecurity (euvdb.enisa.europa.eu) | **24 hours** (early warning) |
| Intermediate report to CSIRT/ENISA | **72 hours** |
| Final report | **1 month** |

---

## Scope

This policy covers all components of **Risk Studio**:

- Frontend (HTML/CSS/JS — GitHub Pages)
- Supabase backend (PostgreSQL, REST API, Realtime)
- Cloudflare Worker (cyber alert ingestion agent)
- Admin interface (`admin.html`)
- Community submission form (`proposer.html`)

**Out of scope**: Third-party infrastructure (Supabase platform, Cloudflare, GitHub Pages), social engineering, physical attacks.

---

## Security Architecture

Risk Studio is built with the following security controls:

- **Row Level Security (RLS)**: Supabase anon key grants read-only access to `status=published` data only. No writes via anon key.
- **XSS protection**: All user-generated content is HTML-escaped before DOM injection (`escHtml()`).
- **CSP**: Content Security Policy meta tags on all pages limiting script sources, connection targets, and framing.
- **Editorial workflow**: All community submissions are `status=pending` until reviewed by an authenticated admin.
- **Audit trail**: Every moderation action records `reviewed_by`, `reviewed_at`, `admin_note`.
- **No hardcoded secrets**: The Supabase anon (`sb_publishable_*`) key is intentionally public and read-only by design (Supabase publishable key pattern).

---

## Known Limitations & Mitigations

| Limitation | Mitigation |
|-----------|------------|
| `'unsafe-inline'` in CSP (single-file app) | Nonce-based CSP planned for future refactor |
| CDN script without SRI hash | Pin version + add `integrity="sha384-..."` — tracked as open action |
| SBOM not yet published | CycloneDX generation in progress — see admin CRA tab |

---

*Security policy version: 2.0 — March 2026 — aligned with CRA Regulation (EU) 2024/2847*
