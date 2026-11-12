-- =============================================================================
-- Risk Studio v5 | Migration 0002 | GRC risk catalogue
-- =============================================================================

CREATE TABLE risks (
  id                   INT UNSIGNED NOT NULL AUTO_INCREMENT,
  code                 VARCHAR(16)  NOT NULL,
  title                VARCHAR(255) NOT NULL,
  category_id          SMALLINT UNSIGNED NOT NULL,
  threat               VARCHAR(255) NOT NULL,
  scenario             TEXT NOT NULL,
  measures             TEXT NOT NULL,
  impact               TINYINT UNSIGNED NOT NULL,
  likelihood           TINYINT UNSIGNED NULL,
  cia_confidentiality  TINYINT(1) NOT NULL DEFAULT 0,
  cia_integrity        TINYINT(1) NOT NULL DEFAULT 0,
  cia_availability     TINYINT(1) NOT NULL DEFAULT 0,
  environment          ENUM('IT','OT','BOTH') NOT NULL DEFAULT 'IT',
  origin               ENUM('catalogue','community') NOT NULL DEFAULT 'catalogue',
  status               ENUM('draft','pending','published','archived') NOT NULL DEFAULT 'draft',
  created_at           DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at           DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  published_at         DATETIME NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_risks_code (code),
  KEY ix_risks_status_category (status, category_id),
  KEY ix_risks_updated (updated_at),
  FULLTEXT KEY ft_risks (title, threat, scenario, measures),
  CONSTRAINT fk_risks_category FOREIGN KEY (category_id) REFERENCES categories (id),
  CONSTRAINT ck_risks_impact     CHECK (impact BETWEEN 1 AND 5),
  CONSTRAINT ck_risks_likelihood CHECK (likelihood IS NULL OR likelihood BETWEEN 1 AND 5),
  CONSTRAINT ck_risks_cia        CHECK (cia_confidentiality + cia_integrity + cia_availability >= 1)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- No row for a risk means the risk is cross-sector (applies to all sectors).
CREATE TABLE risk_sectors (
  risk_id    INT UNSIGNED NOT NULL,
  sector_id  SMALLINT UNSIGNED NOT NULL,
  PRIMARY KEY (risk_id, sector_id),
  KEY ix_risk_sectors_sector (sector_id),
  CONSTRAINT fk_risk_sectors_risk   FOREIGN KEY (risk_id)   REFERENCES risks (id)   ON DELETE CASCADE,
  CONSTRAINT fk_risk_sectors_sector FOREIGN KEY (sector_id) REFERENCES sectors (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE risk_controls (
  risk_id     INT UNSIGNED NOT NULL,
  control_id  INT UNSIGNED NOT NULL,
  PRIMARY KEY (risk_id, control_id),
  KEY ix_risk_controls_control (control_id),
  CONSTRAINT fk_risk_controls_risk    FOREIGN KEY (risk_id)    REFERENCES risks (id)              ON DELETE CASCADE,
  CONSTRAINT fk_risk_controls_control FOREIGN KEY (control_id) REFERENCES framework_controls (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
