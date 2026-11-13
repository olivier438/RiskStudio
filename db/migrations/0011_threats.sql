-- =============================================================================
-- Risk Studio v5 | Migration 0011 | Threats
-- The intel feed now holds two families, shown as two views:
--   vulnerabilities  vulnerability, advisory, exploitation
--   threats          campaign, incident (new type)
-- Threats carry the countries they concern (sources and db/rules/threat_context.csv).
-- =============================================================================

ALTER TABLE intel_items
  MODIFY COLUMN item_type ENUM('vulnerability','advisory','exploitation','campaign','incident') NOT NULL;

CREATE TABLE intel_countries (
  item_id  BIGINT UNSIGNED NOT NULL,
  country  CHAR(2) NOT NULL,
  PRIMARY KEY (item_id, country),
  KEY ix_intel_countries_country (country),
  CONSTRAINT fk_intel_countries_item FOREIGN KEY (item_id) REFERENCES intel_items (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE VIEW v_public_intel_countries AS
SELECT ic.item_id, ic.country
FROM intel_countries ic
JOIN intel_items i ON i.id = ic.item_id
WHERE i.status = 'published';

-- The CCB publishes RSS feeds: the advisories feed replaces the HTML page
-- that answered 403. Only an untouched seed row is changed.
UPDATE sources SET url = 'https://ccb.belgium.be/advisories.xml', enabled = 1
WHERE code = 'CCB' AND url = 'https://ccb.belgium.be/advisories';
