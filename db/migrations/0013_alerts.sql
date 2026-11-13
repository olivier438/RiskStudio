-- =============================================================================
-- Risk Studio v5 | Migration 0013 | Editorial alerts
-- Short notices written by the administrator about what matters right now
-- (a global cloud outage, a mass campaign...), whatever the feeds say.
-- An alert is public from starts_at until ends_at (or until it is archived).
-- =============================================================================

CREATE TABLE alerts (
  id          INT UNSIGNED NOT NULL AUTO_INCREMENT,
  kind        ENUM('outage','attack','vulnerability','other') NOT NULL DEFAULT 'other',
  level       ENUM('info','warning','critical') NOT NULL DEFAULT 'warning',
  title       VARCHAR(200) NOT NULL,
  summary     TEXT NULL,
  url         VARCHAR(2048) NULL,
  starts_at   DATETIME NOT NULL,
  ends_at     DATETIME NULL,
  status      ENUM('published','archived') NOT NULL DEFAULT 'published',
  created_by  SMALLINT UNSIGNED NULL,
  created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY ix_alerts_active (status, starts_at, ends_at),
  CONSTRAINT fk_alerts_admin FOREIGN KEY (created_by) REFERENCES admins (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Dates are stored in UTC (the application connects with time_zone = '+00:00').
CREATE VIEW v_public_alerts AS
SELECT a.id, a.kind, a.level, a.title, a.summary, a.url, a.starts_at, a.ends_at, a.updated_at
FROM alerts a
WHERE a.status = 'published'
  AND a.starts_at <= UTC_TIMESTAMP()
  AND (a.ends_at IS NULL OR a.ends_at > UTC_TIMESTAMP());
