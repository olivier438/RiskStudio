-- =============================================================================
-- Risk Studio v5 | Migration 0007 | Public views for the threat intelligence feed
-- Same rule as 0005: the read-only user only sees published items.
-- =============================================================================

CREATE VIEW v_public_intel_cves AS
SELECT ic.item_id, ic.cve_id
FROM intel_cves ic
JOIN intel_items i ON i.id = ic.item_id
WHERE i.status = 'published';

CREATE VIEW v_public_intel_products AS
SELECT ip.item_id, v.name AS vendor, p.name AS product, p.environment
FROM intel_products ip
JOIN intel_items i ON i.id = ip.item_id
JOIN products p ON p.id = ip.product_id
JOIN vendors v ON v.id = p.vendor_id
WHERE i.status = 'published';

CREATE VIEW v_public_intel_categories AS
SELECT ic.item_id, c.code AS category_code
FROM intel_categories ic
JOIN intel_items i ON i.id = ic.item_id
JOIN categories c ON c.id = ic.category_id
WHERE i.status = 'published';

CREATE VIEW v_public_intel_sectors AS
SELECT isec.item_id, s.code AS sector_code
FROM intel_sectors isec
JOIN intel_items i ON i.id = isec.item_id
JOIN sectors s ON s.id = isec.sector_id
WHERE i.status = 'published';

-- Bridge to the catalogue: only when both sides are published.
CREATE VIEW v_public_intel_risks AS
SELECT ir.item_id, r.code AS risk_code, r.title AS risk_title, ir.rule
FROM intel_risks ir
JOIN intel_items i ON i.id = ir.item_id
JOIN risks r ON r.id = ir.risk_id
WHERE i.status = 'published' AND r.status = 'published';
