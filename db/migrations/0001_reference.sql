-- =============================================================================
-- Risk Studio v5 | Migration 0001 | Reference data
-- Shared vocabularies used by the GRC catalogue, the threat intelligence feed
-- and, in V2, by the user environment profile.
-- Target: MariaDB 10.6+ / MySQL 8.0+, utf8mb4.
-- =============================================================================

CREATE TABLE categories (
  id          SMALLINT UNSIGNED NOT NULL AUTO_INCREMENT,
  code        VARCHAR(32)  NOT NULL,
  name_fr     VARCHAR(100) NOT NULL,
  name_en     VARCHAR(100) NOT NULL,
  sort_order  SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  PRIMARY KEY (id),
  UNIQUE KEY uq_categories_code (code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- NIS2 Annex I (high criticality) and Annex II (other critical) sectors,
-- plus a few sectors relevant to Belgian public entities (CyFun).
CREATE TABLE sectors (
  id          SMALLINT UNSIGNED NOT NULL AUTO_INCREMENT,
  code        VARCHAR(32)  NOT NULL,
  name_fr     VARCHAR(120) NOT NULL,
  name_en     VARCHAR(120) NOT NULL,
  nis2_annex  ENUM('I','II') NULL,
  sort_order  SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  PRIMARY KEY (id),
  UNIQUE KEY uq_sectors_code (code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE frameworks (
  id          SMALLINT UNSIGNED NOT NULL AUTO_INCREMENT,
  code        VARCHAR(32)  NOT NULL,
  name        VARCHAR(160) NOT NULL,
  short_name  VARCHAR(40)  NOT NULL,
  version     VARCHAR(40)  NULL,
  publisher   VARCHAR(120) NULL,
  url         VARCHAR(500) NULL,
  sort_order  SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  PRIMARY KEY (id),
  UNIQUE KEY uq_frameworks_code (code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Control references. `label` stays NULL when the source text is copyrighted
-- (ISO/IEC 27001 Annex A): only the reference number is stored.
CREATE TABLE framework_controls (
  id            INT UNSIGNED NOT NULL AUTO_INCREMENT,
  framework_id  SMALLINT UNSIGNED NOT NULL,
  ref           VARCHAR(40)  NOT NULL,
  label         VARCHAR(255) NULL,
  parent_id     INT UNSIGNED NULL,
  sort_order    INT UNSIGNED NOT NULL DEFAULT 0,
  PRIMARY KEY (id),
  UNIQUE KEY uq_controls_fw_ref (framework_id, ref),
  KEY ix_controls_parent (parent_id),
  CONSTRAINT fk_controls_framework FOREIGN KEY (framework_id) REFERENCES frameworks (id) ON DELETE CASCADE,
  CONSTRAINT fk_controls_parent    FOREIGN KEY (parent_id)    REFERENCES framework_controls (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Technology inventory vocabulary, aligned on CPE naming.
-- Used by the collector to tag intel items and, in V2, by user watchlists.
CREATE TABLE vendors (
  id          INT UNSIGNED NOT NULL AUTO_INCREMENT,
  name        VARCHAR(120) NOT NULL,
  cpe_vendor  VARCHAR(120) NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_vendors_cpe (cpe_vendor),
  KEY ix_vendors_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE products (
  id           INT UNSIGNED NOT NULL AUTO_INCREMENT,
  vendor_id    INT UNSIGNED NOT NULL,
  name         VARCHAR(160) NOT NULL,
  cpe_product  VARCHAR(160) NULL,
  environment  ENUM('IT','OT','BOTH') NOT NULL DEFAULT 'IT',
  PRIMARY KEY (id),
  UNIQUE KEY uq_products_vendor_cpe (vendor_id, cpe_product),
  CONSTRAINT fk_products_vendor FOREIGN KEY (vendor_id) REFERENCES vendors (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
