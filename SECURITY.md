# Security Policy | Risk Studio

**One Circle IT Solutions srl** | [security@onecircle.be](mailto:security@onecircle.be)

## Supported versions

| Version | Supported |
|---|---|
| v5.x (current) | ✅ |
| v4.x and below | ❌ |

## Reporting a vulnerability

**Please do not open a public GitHub issue for a vulnerability.** Write to **security@onecircle.be** with:

- the affected component (front end, API, collector, back office) and version (shown in `/api/v1/health`);
- a description and the steps to reproduce;
- your impact assessment, with a CVSS v3.1 or v4.0 estimate if you have one.

PGP encryption is available on request. A machine-readable contact is published at `/.well-known/security.txt` (RFC 9116).

## Coordinated disclosure

| Step | Target |
|---|---|
| Acknowledgement | 5 business days at most |
| Assessment and triage | 15 days at most |
| Fix, critical (CVSS 9 and above) | 7 days |
| Fix, high (7 to 8.9) | 30 days |
| Fix, medium (4 to 6.9) | 90 days |
| Fix, low (below 4) | 180 days |
| Public disclosure | After the fix, 90-day embargo at most |

Researchers who wish to be credited will be. No legal action is taken against good-faith reports.

## Regulatory notification (Cyber Resilience Act, Regulation (EU) 2024/2847, Art. 14)

Reporting obligations apply since 11 September 2026. Notifications go through the ENISA single reporting platform to the coordinating CSIRT, the **Centre for Cybersecurity Belgium** (CCB).

| Event | Early warning | Notification | Final report |
|---|---|---|---|
| Actively exploited vulnerability | 24 hours | 72 hours | 14 days after a corrective measure is available |
| Severe incident affecting security | 24 hours | 72 hours | 1 month |

## Scope

- Static front end (public site, proposal form, back office)
- PHP API under `/api`
- Collector (`api/bin/collect.php`) and its sources configuration
- Database schema, grants and migrations

**Out of scope:** the hosting platform (Infomaniak), third-party feeds consumed by the collector, social engineering, physical attacks, denial of service by volume.

## Security architecture

- **Least privilege in the database.** The public API connects as `rs_read`: it can read only the `v_public_*` views and reference tables, and insert a proposal without choosing its status. Back office and collector use `rs_write`; migrations use `rs_admin`. Integration tests verify these guarantees.
- **Back office.** E-mail, argon2id password and TOTP (RFC 6238, replay refused) are all required. Sessions are random tokens in an HttpOnly, Secure, SameSite=Strict `__Host-` cookie; only their SHA-256 is stored. Idle timeout 30 minutes, lifetime 8 hours. Every mutating request carries a CSRF token. Accounts are created from the command line only.
- **Abuse protection.** Login throttling per account and per client; proposals limited per client and per day; honeypot field; 32 KB body limit. Rate-limit buckets are HMACs keyed by a server secret: no IP address or e-mail is stored in clear.
- **Browser.** Strict Content Security Policy without `unsafe-inline` (SvelteKit script hashes), `frame-ancestors 'none'`, HSTS, `nosniff`, Referrer-Policy, Permissions-Policy, COOP. No CDN, no third-party script or font: the browser only talks to Risk Studio.
- **Collector.** HTTPS only, timeouts and size caps, XML parsed without network access or entity expansion (XXE), `.onion` links never stored. Classification is deterministic and every decision is traceable (`rule_trace`); no AI service is involved.
- **Editorial workflow.** Only authoritative sources publish directly; everything else waits for review. Every decision is written to the audit log.
- **Supply chain.** Lockfiles, `composer audit` and `npm audit` in CI, weekly Dependabot updates, CycloneDX SBOM generated for every release (`scripts/sbom.sh`, shipped in `sbom/` of the release package).
- **Secrets.** The production `.env` lives only on the server, outside the web root, mode 600. Deployment credentials are GitHub environment secrets.

## Known limitations

| Limitation | Mitigation |
|---|---|
| The SvelteKit route announcer needs one inline style | Allowed by its exact hash (`'unsafe-hashes'`), nothing else |
| Low-severity advisory on `deepmerge` (build tooling only, not shipped) | Tracked by Dependabot |
| The `Server` header is set by the hosting platform | Out of our control on shared hosting |

*Security policy version 3.0, November 2026, Risk Studio v5.*
