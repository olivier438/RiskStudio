-- =============================================================================
-- Risk Studio v5 | Migration 0010 | Leak severity and confidence
-- severity   computed by the collector rules (db/rules/leak_data.csv)
-- confidence stated by the source: confirmed, claimed (credible), untrusted
-- The public view now also exposes the rule trace ("Pourquoi ?").
-- =============================================================================

ALTER TABLE leaks
  ADD COLUMN severity   ENUM('low','medium','high','critical') NULL AFTER data_classes,
  ADD COLUMN confidence ENUM('confirmed','claimed','untrusted') NULL AFTER severity,
  ADD KEY ix_leaks_severity (severity);

CREATE OR REPLACE VIEW v_public_leaks AS
SELECT l.id, s.code AS source_code, s.name AS source_name, l.leak_type,
       l.organisation, l.country, l.sector_id, l.actor, l.records_count,
       l.data_classes, l.severity, l.confidence, l.rule_trace,
       l.disclosed_at, l.url, l.updated_at, l.published_at
FROM leaks l
JOIN sources s ON s.id = l.source_id
WHERE l.status = 'published';
