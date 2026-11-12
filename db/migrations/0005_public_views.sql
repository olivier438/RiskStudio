-- =============================================================================
-- Risk Studio v5 | Migration 0005 | Public views
-- The public API reads ONLY through these views. The read-only database user
-- is granted SELECT on the views, never on the underlying tables, so even an
-- injection in the public API cannot reach drafts, pending items or admins.
-- =============================================================================

CREATE VIEW v_public_risks AS
SELECT r.id, r.code, r.title, r.category_id, r.threat, r.scenario, r.measures,
       r.impact, r.likelihood, r.cia_confidentiality, r.cia_integrity,
       r.cia_availability, r.environment, r.origin, r.updated_at, r.published_at
FROM risks r
WHERE r.status = 'published';

CREATE VIEW v_public_risk_sectors AS
SELECT rs.risk_id, rs.sector_id
FROM risk_sectors rs
JOIN risks r ON r.id = rs.risk_id
WHERE r.status = 'published';

CREATE VIEW v_public_risk_controls AS
SELECT rc.risk_id, rc.control_id
FROM risk_controls rc
JOIN risks r ON r.id = rc.risk_id
WHERE r.status = 'published';

CREATE VIEW v_public_intel AS
SELECT i.id, s.code AS source_code, s.name AS source_name, i.external_id,
       i.item_type, i.title, i.summary, i.url, i.source_published_at,
       i.cvss_score, i.cvss_vector, i.epss_score, i.epss_percentile, i.kev,
       i.kev_due_date, i.severity, i.score, i.environment, i.rule_trace,
       i.updated_at, i.published_at
FROM intel_items i
JOIN sources s ON s.id = i.source_id
WHERE i.status = 'published';

CREATE VIEW v_public_leaks AS
SELECT l.id, s.code AS source_code, s.name AS source_name, l.leak_type,
       l.organisation, l.country, l.sector_id, l.actor, l.records_count,
       l.data_classes, l.disclosed_at, l.url, l.updated_at, l.published_at
FROM leaks l
JOIN sources s ON s.id = l.source_id
WHERE l.status = 'published';
