-- =============================================================================
-- Risk Studio v5 | Migration 0003 | Threat intelligence feed
-- No AI anywhere: every classification is produced by explicit rules, and the
-- rules that fired are stored in `rule_trace` so each item stays auditable.
-- =============================================================================

CREATE TABLE sources (
  id               SMALLINT UNSIGNED NOT NULL AUTO_INCREMENT,
  code             VARCHAR(32)  NOT NULL,
  name             VARCHAR(120) NOT NULL,
  kind             ENUM('json_api','rss','csv') NOT NULL,
  url              VARCHAR(500) NOT NULL,
  -- Authoritative sources (CISA KEV, national CERTs) are published directly.
  -- Everything else lands in `pending` for editorial review.
  authoritative    TINYINT(1) NOT NULL DEFAULT 0,
  enabled          TINYINT(1) NOT NULL DEFAULT 0,
  poll_minutes     SMALLINT UNSIGNED NOT NULL DEFAULT 60,
  cursor_state     LONGTEXT NULL,
  last_run_at      DATETIME NULL,
  last_success_at  DATETIME NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_sources_code (code),
  CONSTRAINT ck_sources_cursor CHECK (cursor_state IS NULL OR JSON_VALID(cursor_state))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE intel_items (
  id                BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  source_id         SMALLINT UNSIGNED NOT NULL,
  external_id       VARCHAR(191) NOT NULL,
  item_type         ENUM('vulnerability','advisory','exploitation','campaign') NOT NULL,
  title             VARCHAR(500) NOT NULL,
  summary           TEXT NULL,
  url               VARCHAR(2048) NULL,
  source_published_at DATETIME NULL,
  cvss_score        DECIMAL(3,1) NULL,
  cvss_vector       VARCHAR(160) NULL,
  epss_score        DECIMAL(6,5) NULL,
  epss_percentile   DECIMAL(6,5) NULL,
  kev               TINYINT(1) NOT NULL DEFAULT 0,
  kev_due_date      DATE NULL,
  severity          ENUM('low','medium','high','critical') NULL,
  score             TINYINT UNSIGNED NULL,
  environment       ENUM('IT','OT','BOTH') NOT NULL DEFAULT 'IT',
  status            ENUM('pending','published','rejected','archived') NOT NULL DEFAULT 'pending',
  rule_trace        LONGTEXT NULL,
  created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  published_at      DATETIME NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_intel_source_ext (source_id, external_id),
  KEY ix_intel_status_published (status, published_at),
  KEY ix_intel_updated (updated_at),
  KEY ix_intel_score (score),
  FULLTEXT KEY ft_intel (title, summary),
  CONSTRAINT fk_intel_source FOREIGN KEY (source_id) REFERENCES sources (id),
  CONSTRAINT ck_intel_score  CHECK (score IS NULL OR score <= 100),
  CONSTRAINT ck_intel_trace  CHECK (rule_trace IS NULL OR JSON_VALID(rule_trace))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE intel_cves (
  item_id  BIGINT UNSIGNED NOT NULL,
  cve_id   VARCHAR(20) NOT NULL,
  PRIMARY KEY (item_id, cve_id),
  KEY ix_intel_cves_cve (cve_id),
  CONSTRAINT fk_intel_cves_item FOREIGN KEY (item_id) REFERENCES intel_items (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE intel_cwes (
  item_id  BIGINT UNSIGNED NOT NULL,
  cwe_id   VARCHAR(16) NOT NULL,
  PRIMARY KEY (item_id, cwe_id),
  KEY ix_intel_cwes_cwe (cwe_id),
  CONSTRAINT fk_intel_cwes_item FOREIGN KEY (item_id) REFERENCES intel_items (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE intel_products (
  item_id     BIGINT UNSIGNED NOT NULL,
  product_id  INT UNSIGNED NOT NULL,
  PRIMARY KEY (item_id, product_id),
  KEY ix_intel_products_product (product_id),
  CONSTRAINT fk_intel_products_item    FOREIGN KEY (item_id)    REFERENCES intel_items (id) ON DELETE CASCADE,
  CONSTRAINT fk_intel_products_product FOREIGN KEY (product_id) REFERENCES products (id)    ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE intel_categories (
  item_id      BIGINT UNSIGNED NOT NULL,
  category_id  SMALLINT UNSIGNED NOT NULL,
  PRIMARY KEY (item_id, category_id),
  CONSTRAINT fk_intel_categories_item     FOREIGN KEY (item_id)     REFERENCES intel_items (id) ON DELETE CASCADE,
  CONSTRAINT fk_intel_categories_category FOREIGN KEY (category_id) REFERENCES categories (id)  ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE intel_sectors (
  item_id    BIGINT UNSIGNED NOT NULL,
  sector_id  SMALLINT UNSIGNED NOT NULL,
  PRIMARY KEY (item_id, sector_id),
  CONSTRAINT fk_intel_sectors_item   FOREIGN KEY (item_id)   REFERENCES intel_items (id) ON DELETE CASCADE,
  CONSTRAINT fk_intel_sectors_sector FOREIGN KEY (sector_id) REFERENCES sectors (id)     ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- The bridge between the two products: an intel item points to the catalogue
-- risks it materialises. `rule` names the mapping rule that created the link.
CREATE TABLE intel_risks (
  item_id  BIGINT UNSIGNED NOT NULL,
  risk_id  INT UNSIGNED NOT NULL,
  rule     VARCHAR(64) NOT NULL,
  PRIMARY KEY (item_id, risk_id),
  KEY ix_intel_risks_risk (risk_id),
  CONSTRAINT fk_intel_risks_item FOREIGN KEY (item_id) REFERENCES intel_items (id) ON DELETE CASCADE,
  CONSTRAINT fk_intel_risks_risk FOREIGN KEY (risk_id) REFERENCES risks (id)       ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE leaks (
  id               BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  source_id        SMALLINT UNSIGNED NOT NULL,
  external_id      VARCHAR(191) NOT NULL,
  leak_type        ENUM('ransomware','breach','exposure') NOT NULL,
  organisation     VARCHAR(255) NOT NULL,
  country          CHAR(2) NULL,
  sector_id        SMALLINT UNSIGNED NULL,
  actor            VARCHAR(160) NULL,
  records_count    BIGINT UNSIGNED NULL,
  data_classes     LONGTEXT NULL,
  disclosed_at     DATETIME NULL,
  url              VARCHAR(2048) NULL,
  status           ENUM('pending','published','rejected','archived') NOT NULL DEFAULT 'pending',
  rule_trace       LONGTEXT NULL,
  created_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  published_at     DATETIME NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_leaks_source_ext (source_id, external_id),
  KEY ix_leaks_status_published (status, published_at),
  KEY ix_leaks_country (country),
  KEY ix_leaks_updated (updated_at),
  CONSTRAINT fk_leaks_source FOREIGN KEY (source_id) REFERENCES sources (id),
  CONSTRAINT fk_leaks_sector FOREIGN KEY (sector_id) REFERENCES sectors (id) ON DELETE SET NULL,
  CONSTRAINT ck_leaks_classes CHECK (data_classes IS NULL OR JSON_VALID(data_classes)),
  CONSTRAINT ck_leaks_trace   CHECK (rule_trace IS NULL OR JSON_VALID(rule_trace))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
