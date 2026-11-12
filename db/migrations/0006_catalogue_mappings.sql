-- =============================================================================
-- Risk Studio v5 | Migration 0006 | Catalogue mappings
-- - CyFun assurance levels and key measures on framework controls
-- - Crosswalk between controls of different frameworks
-- - Origin of each risk to control mapping: written by an editor, or derived
--   from the crosswalk by the importer (traceable, no AI)
-- =============================================================================

ALTER TABLE framework_controls
  ADD COLUMN assurance_level   ENUM('BASIC','IMPORTANT','ESSENTIAL') NULL AFTER label,
  ADD COLUMN key_measure_level ENUM('BASIC','IMPORTANT','ESSENTIAL') NULL AFTER assurance_level;

-- Directed link: a risk mapped to `from_control` is also mapped to `to_control`.
CREATE TABLE control_crosswalk (
  from_control_id  INT UNSIGNED NOT NULL,
  to_control_id    INT UNSIGNED NOT NULL,
  basis            VARCHAR(120) NOT NULL,
  PRIMARY KEY (from_control_id, to_control_id),
  KEY ix_crosswalk_to (to_control_id),
  CONSTRAINT fk_crosswalk_from FOREIGN KEY (from_control_id) REFERENCES framework_controls (id) ON DELETE CASCADE,
  CONSTRAINT fk_crosswalk_to   FOREIGN KEY (to_control_id)   REFERENCES framework_controls (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

ALTER TABLE risk_controls
  ADD COLUMN mapping_source ENUM('editorial','crosswalk') NOT NULL DEFAULT 'editorial';

CREATE OR REPLACE VIEW v_public_risk_controls AS
SELECT rc.risk_id, rc.control_id, rc.mapping_source
FROM risk_controls rc
JOIN risks r ON r.id = rc.risk_id
WHERE r.status = 'published';
