# Collector rules

The threat intelligence feed uses **no AI**. Every classification comes from the rule files of this folder, applied by `api/src/Collector/Classifier.php`. Each item stores the identifiers of the rules that fired (`rule_trace`), shown in the interface under **Pourquoi ?**, plus a fingerprint of these files (`rules_version`).

After editing a file, the next collector runs re-apply the rules to every item classified with the previous version (50 items per run, rule `rules_version`). No command is needed on FTP-only hosting. With a shell:

```bash
php api/bin/collect.php --reclassify    # re-applies the rules to every stored item, now
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
| `threat_context.csv` | Text (whole word) → `environment` (OT, every item), `country`, `sector`, `severity` (threats only: campaigns and incidents). Severity only raises. |
| `leak_data.csv` | Exposed data class (whole word, French or English wording) → leak severity. For each class the longest matching pattern decides (`carte de fidélité` beats `numéro de carte`), then the most serious class wins. |

## Views

Item types `vulnerability`, `advisory` and `exploitation` are shown in **Vulnérabilités**; `campaign` and `incident` in **Menaces** (`kind` filter of `/v1/intel`).

## Severity

1. From CVSS: 9.0 and more `critical`, 7.0 `high`, 4.0 `medium`, above 0 `low` (rule `cvss.*`).
2. A source hint can only raise it: a CERT-FR alert is `critical` (rule `hint.critical`).
3. Known exploited without CVSS yet: `high` (rule `kev.no_cvss->high`).

An item is shown as **critical** when it is known exploited (KEV, EUVD exploited) or its severity is critical.

## Leak severity

1. Each exposed data class is matched against `leak_data.csv` (rule `data.<pattern>-><severity>`); a class no rule knows counts as `low` (rule `data.other->low`).
2. The most serious class gives the leak severity.
3. A source flag "sensitive" (Bonjour la fuite) raises it to at least `high` (rule `hint.sensitive->high`).
4. No data class at all: a ransomware claim is `high` (rule `type.ransomware->high`), anything else stays unknown.

The confidence stated by the source is kept as is (`confirmed`, `claimed`, `untrusted`, rule `confidence.*`). An authoritative source only publishes confirmed leaks: claims always wait for review, and a pending claim is published when the source later confirms it.

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
| ransomware.live | Ransomware claims, filtered by country | Pending review (claims are unverified). Answers 404 to the production hosting: disabled there |
| CCB | Belgian warnings: vulnerability advisories (Vulnérabilités view) and incidents (Menaces view, country BE) | Direct (authoritative) |
| ZATAZ | French press: incidents and claims, attack categories only | Pending review |
| Bonjour la fuite | Leaks affecting French organisations (RSS, about ten latest entries) | Direct when confirmed (🟢), pending review when claimed (🟠 🔴) |

**Custom sources**: any RSS or Atom feed added from the administration (📡 Sources, "Ajouter une source"), read by `GenericFeed`. Settings in `sources.config`: the view it feeds (`threat` gives incidents, `vulnerability` gives advisories), a default country, words to keep and words to exclude (whole words). CVE numbers in the text are extracted. The addresses only ever reach the public Internet (private and reserved addresses refused, each redirect checked again). Pending review unless marked authoritative.

The same CVE reported by several vulnerability feeds is merged into one item; a pending item becomes published when an authoritative source confirms it. A rejected item is never republished. Enrichment: FIRST EPSS for every CVE, NVD for CVSS, CWE and product (5 lookups per run without key, completed over the next runs).
