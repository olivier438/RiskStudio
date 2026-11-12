-- =============================================================================
-- Risk Studio v5 | Migration 0004 | Community proposals, administration, audit
-- =============================================================================

CREATE TABLE admins (
  id             SMALLINT UNSIGNED NOT NULL AUTO_INCREMENT,
  email          VARCHAR(254) NOT NULL,
  display_name   VARCHAR(100) NOT NULL,
  password_hash  VARCHAR(255) NOT NULL,
  totp_secret    VARCHAR(64)  NULL,
  is_active      TINYINT(1) NOT NULL DEFAULT 1,
  created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_login_at  DATETIME NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_admins_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- `status` is never supplied by the public API: the read-only database user
-- only holds a column-level INSERT grant that excludes it (see db/grants.sql).
CREATE TABLE proposals (
  id                  INT UNSIGNED NOT NULL AUTO_INCREMENT,
  kind                ENUM('risk','leak','correction') NOT NULL,
  payload             LONGTEXT NOT NULL,
  submitter_name      VARCHAR(100) NULL,
  submitter_email     VARCHAR(254) NULL,
  client_fingerprint  CHAR(64) NULL,
  status              ENUM('pending','approved','rejected') NOT NULL DEFAULT 'pending',
  admin_note          VARCHAR(1000) NULL,
  reviewed_by         SMALLINT UNSIGNED NULL,
  reviewed_at         DATETIME NULL,
  created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY ix_proposals_status (status, created_at),
  CONSTRAINT fk_proposals_reviewer FOREIGN KEY (reviewed_by) REFERENCES admins (id) ON DELETE SET NULL,
  CONSTRAINT ck_proposals_payload  CHECK (JSON_VALID(payload))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Fixed-window rate limiting for public write endpoints and admin login.
-- `bucket` is a hash: no raw IP address is ever stored.
CREATE TABLE rate_limits (
  bucket        CHAR(64) NOT NULL,
  window_start  DATETIME NOT NULL,
  hits          SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  PRIMARY KEY (bucket)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE audit_log (
  id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  actor_type  ENUM('admin','collector','system') NOT NULL,
  actor_id    SMALLINT UNSIGNED NULL,
  action      VARCHAR(64) NOT NULL,
  entity      VARCHAR(32) NOT NULL,
  entity_id   VARCHAR(64) NULL,
  details     LONGTEXT NULL,
  created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY ix_audit_entity (entity, entity_id),
  KEY ix_audit_created (created_at),
  CONSTRAINT ck_audit_details CHECK (details IS NULL OR JSON_VALID(details))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE collector_runs (
  id             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  source_id      SMALLINT UNSIGNED NOT NULL,
  started_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  finished_at    DATETIME NULL,
  status         ENUM('running','success','partial','failed') NOT NULL DEFAULT 'running',
  items_new      INT UNSIGNED NOT NULL DEFAULT 0,
  items_updated  INT UNSIGNED NOT NULL DEFAULT 0,
  error          VARCHAR(2000) NULL,
  PRIMARY KEY (id),
  KEY ix_runs_source_started (source_id, started_at),
  CONSTRAINT fk_runs_source FOREIGN KEY (source_id) REFERENCES sources (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
