-- =============================================================================
-- Risk Studio v5 | Migration 0009 | Administration sessions and TOTP replay
-- Sessions live in the database: the cookie carries a random token, only its
-- SHA-256 is stored, so a database leak does not leak usable sessions.
-- =============================================================================

ALTER TABLE admins
  ADD COLUMN totp_last_step BIGINT UNSIGNED NULL AFTER totp_secret;

CREATE TABLE admin_sessions (
  token_hash    CHAR(64) NOT NULL,
  admin_id      SMALLINT UNSIGNED NOT NULL,
  csrf_token    CHAR(64) NOT NULL,
  created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at    DATETIME NOT NULL,
  PRIMARY KEY (token_hash),
  KEY ix_admin_sessions_admin (admin_id),
  KEY ix_admin_sessions_expires (expires_at),
  CONSTRAINT fk_admin_sessions_admin FOREIGN KEY (admin_id) REFERENCES admins (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Community risks get codes R-COM-01, R-COM-02... allocated at approval.
ALTER TABLE risks
  ADD COLUMN proposal_id INT UNSIGNED NULL AFTER origin,
  ADD CONSTRAINT fk_risks_proposal FOREIGN KEY (proposal_id) REFERENCES proposals (id) ON DELETE SET NULL;
