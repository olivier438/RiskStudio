-- =============================================================================
-- Risk Studio v5 | Migration 0008 | Collector
-- `facts` keeps what the sources said (normalised, never interpreted).
-- Classification is a pure function of facts + rules (db/rules), so any item
-- can be re-classified and the result reproduced. Not exposed publicly.
-- =============================================================================

-- CVSS 4.0 vectors are longer than the 160 characters planned in 0003.
ALTER TABLE intel_items
  MODIFY COLUMN cvss_vector VARCHAR(255) NULL,
  ADD COLUMN facts LONGTEXT NULL AFTER rule_trace,
  ADD CONSTRAINT ck_intel_facts CHECK (facts IS NULL OR JSON_VALID(facts));

ALTER TABLE leaks
  ADD COLUMN facts LONGTEXT NULL AFTER rule_trace,
  ADD CONSTRAINT ck_leaks_facts CHECK (facts IS NULL OR JSON_VALID(facts));

-- Several sources may report the same CVE: the collector merges them into one
-- item and records every reporting source here.
CREATE TABLE intel_item_sources (
  item_id    BIGINT UNSIGNED NOT NULL,
  source_id  SMALLINT UNSIGNED NOT NULL,
  external_id VARCHAR(191) NOT NULL,
  first_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (item_id, source_id),
  KEY ix_item_sources_source (source_id, external_id),
  CONSTRAINT fk_item_sources_item   FOREIGN KEY (item_id)   REFERENCES intel_items (id) ON DELETE CASCADE,
  CONSTRAINT fk_item_sources_source FOREIGN KEY (source_id) REFERENCES sources (id)     ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
