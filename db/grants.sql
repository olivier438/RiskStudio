-- =============================================================================
-- Risk Studio v5 | Least-privilege database users
-- `__DB__` is replaced by the database name (scripts/dev-db.sh does it).
-- Apply AFTER the migrations: column and view grants need existing objects.
--
--   rs_admin  DDL only. Used by bin/migrate.php, never by the web runtime.
--   rs_write  Admin back-office and collector.
--   rs_read   Public API. Reads public views and reference data only, and may
--             insert a proposal without choosing its status.
--
-- On shared hosting where GRANT is not available, see docs/deploy-infomaniak.md.
-- =============================================================================

GRANT ALL PRIVILEGES ON `__DB__`.* TO 'rs_admin'@'localhost';

GRANT SELECT, INSERT, UPDATE, DELETE ON `__DB__`.* TO 'rs_write'@'localhost';

GRANT SELECT ON `__DB__`.categories             TO 'rs_read'@'localhost';
GRANT SELECT ON `__DB__`.sectors                TO 'rs_read'@'localhost';
GRANT SELECT ON `__DB__`.frameworks             TO 'rs_read'@'localhost';
GRANT SELECT ON `__DB__`.framework_controls     TO 'rs_read'@'localhost';
GRANT SELECT ON `__DB__`.control_crosswalk      TO 'rs_read'@'localhost';
GRANT SELECT ON `__DB__`.vendors                TO 'rs_read'@'localhost';
GRANT SELECT ON `__DB__`.products               TO 'rs_read'@'localhost';
GRANT SELECT ON `__DB__`.v_public_risks         TO 'rs_read'@'localhost';
GRANT SELECT ON `__DB__`.v_public_risk_sectors  TO 'rs_read'@'localhost';
GRANT SELECT ON `__DB__`.v_public_risk_controls TO 'rs_read'@'localhost';
GRANT SELECT ON `__DB__`.v_public_intel         TO 'rs_read'@'localhost';
GRANT SELECT ON `__DB__`.v_public_leaks         TO 'rs_read'@'localhost';
GRANT SELECT ON `__DB__`.v_public_intel_cves       TO 'rs_read'@'localhost';
GRANT SELECT ON `__DB__`.v_public_intel_products   TO 'rs_read'@'localhost';
GRANT SELECT ON `__DB__`.v_public_intel_categories TO 'rs_read'@'localhost';
GRANT SELECT ON `__DB__`.v_public_intel_sectors    TO 'rs_read'@'localhost';
GRANT SELECT ON `__DB__`.v_public_intel_risks      TO 'rs_read'@'localhost';
GRANT SELECT ON `__DB__`.v_public_intel_countries  TO 'rs_read'@'localhost';
GRANT INSERT (kind, payload, submitter_name, submitter_email, client_fingerprint)
  ON `__DB__`.proposals TO 'rs_read'@'localhost';
GRANT SELECT, INSERT, UPDATE, DELETE ON `__DB__`.rate_limits TO 'rs_read'@'localhost';

FLUSH PRIVILEGES;
