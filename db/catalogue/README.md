# Catalogue sources

These files are the **source of truth** of the GRC catalogue. Edit them (a spreadsheet works: semicolon separator, UTF-8), then run:

```bash
make catalogue        # validates everything, then imports
```

Nothing is written if a single row is invalid. The import is idempotent: run it as often as needed.

## `risks.csv`

| Column | Content |
|---|---|
| `code` | Stable identifier, `R-XXX-00`. Never reuse a code. |
| `title`, `threat`, `scenario`, `measures` | French text, no en or em dash (rejected by the importer). |
| `category` | A code from `categories` (`GOV`, `IAM`, `INFRA`, `VULN`, `DATA`, `BCM`, `CRISIS`, `DEV`, `AI`, `LEGAL`, `OT`, `OPS`, `PHYS`, `HR`, `SUPPLY`). |
| `impact` | 1 to 5. |
| `likelihood` | Empty, or 1 to 5. |
| `cia` | `C`, `I`, `A` in that order: `CA`, `CIA`... |
| `environment` | `IT`, `OT` or `BOTH`. |
| `sectors` | Sector codes separated by `\|`. **Empty means cross-sector.** |
| `iso27001` | ISO/IEC 27001:2022 references: Annex A (`A.8.13`) or clauses (`9.3`). |
| `nis2` | NIS2 references **in addition** to those derived from ISO (`Art.21.2.j`, `Art.20`, `Art.23`). |
| `dora` | DORA articles (`Art.9`). |
| `cra` | Cyber Resilience Act references (`AnnexI.II.1`, `Art.13`). |

A risk removed from the file is **archived**, never deleted.

## Editorial and derived mappings

The `iso27001`, `nis2`, `dora` and `cra` columns are **editorial** mappings. On import, each editorial ISO reference is expanded through the crosswalk into **derived** mappings (NIS2, CyFun 2023, NIST CSF 2.0), stored with `mapping_source = 'crosswalk'`. The API returns the source of every mapping, and `?mapping=editorial` restricts a framework filter to editorial mappings.

## `crosswalk/iso27001_2022.csv`

| Target | Basis |
|---|---|
| CyFun 2023 | **CCB references**: each CyFun requirement lists the ISO/IEC 27002:2022 controls it relies on. Reversed here. |
| CyFun 2023, 2022 controls not cited by the CCB | Risk Studio editorial. The CCB references omit the controls introduced in 2022 (`5.7`, `7.4`, `8.9` to `8.12`, `8.16`, `8.23`, `8.28`...), most likely because they were carried over from a 2013 mapping. |
| NIS2 Art. 21(2) | Risk Studio editorial, inspired by the structure of Implementing Regulation (EU) 2024/2690. |
| NIST CSF 2.0 | Risk Studio editorial, at category level. |

The `basis` column states it for every row.

## `controls/*.csv`

Framework controls that are not in the SQL seed. Columns: `framework;ref;label;parent_ref;assurance_level;key_measure_level`.

- **ISO/IEC 27001:2022**: Annex A and clauses as **numbers only**, titles are copyrighted.
- **CyFun 2023**: subcategory references and NIST CSF 1.1 titles (public domain). The CCB requirement texts are not reproduced. Levels come from the public CyFun Important and Essential documents (version 2023-03-01, update 2024-03-15):
  - `ESSENTIAL`: only in the Essential document (7 subcategories).
  - `IMPORTANT`: present from the Important level.
  - `BASIC`: confirmed only for subcategories carrying a Basic key measure (Annex A of the documents). **The full Basic list still needs the CyFun Basic document.**
  - `key_measure_level`: lowest level at which the subcategory carries a key measure.
- **DORA**, **CRA**: article titles from the EU regulations.
