# Collector rules

The threat intelligence feed uses **no AI**. Every classification comes from the rule files of this folder, applied by `api/src/Collector/Classifier.php`. Each item stores the identifiers of the rules that fired (`rule_trace`), shown in the interface under **Pourquoi ?**, plus a fingerprint of these files (`rules_version`).

After editing a file:

```bash
php api/bin/collect.php --reclassify    # re-applies the rules to every stored item
```

Classification is a pure function of the stored facts and of these files: the same inputs always give the same result.

## Files

| File | Effect |
|---|---|
| `cwe_categories.csv` | CWE weakness → catalogue category (`IAM`, `VULN`, `DATA`, `INFRA`, `SUPPLY`). No match: `VULN`. |
| `keywords.csv` | Text found in the title, summary or CERT-FR risk list → category. |
| `environment.csv` | Vendor or product (whole word, case insensitive) → `OT` or `BOTH`, plus sectors. The CERT-FR `scada` flag always gives `OT`. |
| `risk_links.csv` | Condition → catalogue risk. Conditions: `kev`, `kev_ransomware`, `env` (`OT` matches OT and BOTH), `cwe`, `product` (whole word in vendor + product), `text` (whole word in title + summary). |
| `ransomware_sectors.csv` | ransomware.live `activity` → sector. |

## Severity

1. From CVSS: 9.0 and more `critical`, 7.0 `high`, 4.0 `medium`, above 0 `low` (rule `cvss.*`).
2. A source hint can only raise it: a CERT-FR alert is `critical` (rule `hint.critical`).
3. Known exploited without CVSS yet: `high` (rule `kev.no_cvss->high`).

An item is shown as **critical** when it is known exploited (KEV, EUVD exploited) or its severity is critical.

## Score (0 to 100)

| Component | Value |
|---|---|
| Base | CVSS × 6 (max 60). Without CVSS: critical 54, high 42, medium 30, low 12. |
| Exploitation | + 25 when known exploited (KEV, EUVD exploited, CERT-FR alert) |
| EPSS | + EPSS percentile × 15 (max 15), from FIRST |
| Ransomware | + 5 when CISA reports use in ransomware campaigns |

Capped at 100. The detail of each component is stored in `rule_trace.score`.

## Sources and publication

| Source | Content | Publication |
|---|---|---|
| CISA KEV | Known exploited vulnerabilities | Direct (authoritative) |
| ENISA EUVD exploited | Exploited vulnerabilities | Direct (authoritative) |
| ENISA EUVD critical | Critical vulnerabilities | Pending review |
| CERT-FR | Alerts, advisories, CTI reports (news skipped) | Direct (authoritative) |
| Have I Been Pwned | Verified breaches (sensitive, spam, fabricated excluded) | Direct (authoritative) |
| ransomware.live | Ransomware claims, filtered by country | Pending review (claims are unverified) |
| CCB | Belgian advisories | Disabled: the site rejects data-centre requests, to test from the production hosting |

The same CVE reported by several vulnerability feeds is merged into one item; a pending item becomes published when an authoritative source confirms it. A rejected item is never republished. Enrichment: FIRST EPSS for every CVE, NVD for CVSS, CWE and product (5 lookups per run without key, completed over the next runs).
