-- =============================================================================
-- Risk Studio v5 | DEVELOPMENT FIXTURES ONLY. NEVER LOAD IN PRODUCTION.
-- Fictitious threat intelligence and leak items to build and test the UI
-- before the collector (phase 4) exists. Every identifier is obviously fake:
-- CVE-2099-*, "Exemple" vendors and organisations, example.org URLs.
-- Loaded by: scripts/dev-db.sh --fixtures

SET NAMES utf8mb4;
-- =============================================================================

INSERT IGNORE INTO sources (code, name, kind, url, authoritative, enabled) VALUES
  ('DEV_KEV',   'Exemple KEV (dev)',        'json_api', 'https://example.org/kev.json', 1, 0),
  ('DEV_CERT',  'Exemple CERT (dev)',       'rss',      'https://example.org/cert.xml', 1, 0),
  ('DEV_NVD',   'Exemple NVD (dev)',        'json_api', 'https://example.org/nvd.json', 0, 0),
  ('DEV_LEAKS', 'Exemple Leak Watch (dev)', 'json_api', 'https://example.org/leaks',    0, 0);

INSERT IGNORE INTO vendors (name, cpe_vendor) VALUES
  ('Exemple Networks', 'exemple_networks'),
  ('Exemple Automation', 'exemple_automation'),
  ('Exemple Soft', 'exemple_soft');

INSERT IGNORE INTO products (vendor_id, name, cpe_product, environment)
SELECT v.id, x.name, x.cpe, x.env FROM vendors v JOIN (
  SELECT 'exemple_networks' AS vendor, 'SecureGate VPN' AS name, 'securegate_vpn' AS cpe, 'IT' AS env
  UNION ALL SELECT 'exemple_networks', 'EdgeFirewall', 'edgefirewall', 'IT'
  UNION ALL SELECT 'exemple_automation', 'PLC Série 7', 'plc_serie_7', 'OT'
  UNION ALL SELECT 'exemple_automation', 'SCADA Vision', 'scada_vision', 'OT'
  UNION ALL SELECT 'exemple_soft', 'MailServer', 'mailserver', 'IT'
  UNION ALL SELECT 'exemple_soft', 'BuildRunner CI', 'buildrunner_ci', 'IT'
) x ON x.vendor = v.cpe_vendor;

DELETE FROM intel_items WHERE external_id LIKE 'CVE-2099-%' OR external_id LIKE 'DEV-ADV-%';
DELETE FROM leaks WHERE external_id LIKE 'DEV-LEAK-%';

INSERT INTO intel_items (source_id, external_id, item_type, title, summary, url, source_published_at,
                         cvss_score, cvss_vector, epss_score, epss_percentile, kev, kev_due_date,
                         severity, score, environment, status, rule_trace, published_at)
SELECT s.id, x.ext, x.type, x.title, x.summary, x.url, UTC_TIMESTAMP() - INTERVAL x.age HOUR,
       x.cvss, x.vector, x.epss, x.pct, x.kev, x.due, x.sev, x.score, x.env, 'published', x.trace,
       UTC_TIMESTAMP() - INTERVAL x.age HOUR
FROM sources s JOIN (
  SELECT 'DEV_KEV' AS src, 'CVE-2099-0001' AS ext, 'exploitation' AS type,
         '[Exemple] Contournement d''authentification sur SecureGate VPN' AS title,
         'Exemple fictif : une requête forgée permet de contourner l''authentification du portail VPN. Exploitation active signalée.' AS summary,
         'https://example.org/advisories/0001' AS url, 3 AS age, 9.8 AS cvss,
         'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' AS vector, 0.94210 AS epss, 0.99850 AS pct, 1 AS kev,
         CURRENT_DATE + INTERVAL 21 DAY AS due, 'critical' AS sev, 98 AS score, 'IT' AS env,
         '{"rules":["kev.listed","cvss.critical","epss.top1pct","cwe.CWE-287->IAM","product.exemple_networks/securegate_vpn"]}' AS trace
  UNION ALL SELECT 'DEV_CERT', 'DEV-ADV-0002', 'advisory',
         '[Exemple] Avis de sécurité : multiples vulnérabilités dans PLC Série 7',
         'Exemple fictif : plusieurs vulnérabilités permettent un déni de service et une modification de la logique automate.',
         'https://example.org/advisories/0002', 10, 8.6, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H', 0.12000, 0.94000, 0,
         NULL, 'high', 74, 'OT',
         '{"rules":["cert.advisory","cvss.high","product.exemple_automation/plc_serie_7->OT","sector.ENERGY","sector.MANUFACTURING"]}'
  UNION ALL SELECT 'DEV_NVD', 'CVE-2099-0003', 'vulnerability',
         '[Exemple] Injection de commandes dans BuildRunner CI',
         'Exemple fictif : un paramètre de pipeline non filtré permet l''exécution de commandes sur l''agent de build.',
         'https://example.org/advisories/0003', 30, 8.8, 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', 0.03100, 0.81000, 0,
         NULL, 'high', 61, 'IT', '{"rules":["cvss.high","cwe.CWE-78->DEV","product.exemple_soft/buildrunner_ci"]}'
  UNION ALL SELECT 'DEV_KEV', 'CVE-2099-0004', 'exploitation',
         '[Exemple] Exécution de code à distance sur MailServer',
         'Exemple fictif : une vulnérabilité de désérialisation est exploitée pour déposer un webshell.',
         'https://example.org/advisories/0004', 50, 9.1, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N', 0.71000, 0.98700, 1,
         CURRENT_DATE + INTERVAL 7 DAY, 'critical', 95, 'IT', '{"rules":["kev.listed","cvss.critical","cwe.CWE-502->VULN"]}'
  UNION ALL SELECT 'DEV_NVD', 'CVE-2099-0005', 'vulnerability',
         '[Exemple] Fuite d''informations dans EdgeFirewall',
         'Exemple fictif : une page de diagnostic expose la configuration à un utilisateur authentifié.',
         'https://example.org/advisories/0005', 75, 5.3, 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N', 0.00400, 0.31000, 0,
         NULL, 'medium', 28, 'IT', '{"rules":["cvss.medium","cwe.CWE-200->DATA"]}'
  UNION ALL SELECT 'DEV_CERT', 'DEV-ADV-0006', 'campaign',
         '[Exemple] Campagne de phishing ciblant les services comptables',
         'Exemple fictif : des courriels imitant un fournisseur demandent un changement de coordonnées bancaires.',
         'https://example.org/advisories/0006', 120, NULL, NULL, NULL, NULL, 0, NULL, 'medium', 40, 'IT',
         '{"rules":["cert.advisory","keyword.phishing->HR","keyword.virement->risk.R-RH-01"]}'
  UNION ALL SELECT 'DEV_NVD', 'CVE-2099-0007', 'vulnerability',
         '[Exemple] Identifiants codés en dur dans SCADA Vision',
         'Exemple fictif : un compte de maintenance avec mot de passe statique permet l''accès à l''interface de supervision.',
         'https://example.org/advisories/0007', 200, 9.0, 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H', 0.02000, 0.70000, 0,
         NULL, 'critical', 70, 'OT', '{"rules":["cvss.critical","cwe.CWE-798->IAM","product.exemple_automation/scada_vision->OT"]}'
) x ON x.src = s.code;

INSERT INTO intel_cves (item_id, cve_id)
SELECT id, external_id FROM intel_items WHERE external_id LIKE 'CVE-2099-%';
INSERT INTO intel_cves (item_id, cve_id)
SELECT id, 'CVE-2099-0021' FROM intel_items WHERE external_id = 'DEV-ADV-0002'
UNION ALL SELECT id, 'CVE-2099-0022' FROM intel_items WHERE external_id = 'DEV-ADV-0002';

INSERT INTO intel_products (item_id, product_id)
SELECT i.id, p.id FROM intel_items i JOIN products p ON p.cpe_product = CASE i.external_id
  WHEN 'CVE-2099-0001' THEN 'securegate_vpn' WHEN 'DEV-ADV-0002' THEN 'plc_serie_7'
  WHEN 'CVE-2099-0003' THEN 'buildrunner_ci' WHEN 'CVE-2099-0004' THEN 'mailserver'
  WHEN 'CVE-2099-0005' THEN 'edgefirewall'   WHEN 'CVE-2099-0007' THEN 'scada_vision' END;

INSERT INTO intel_categories (item_id, category_id)
SELECT i.id, c.id FROM intel_items i JOIN categories c ON c.code = CASE i.external_id
  WHEN 'CVE-2099-0001' THEN 'IAM' WHEN 'DEV-ADV-0002' THEN 'OT' WHEN 'CVE-2099-0003' THEN 'DEV'
  WHEN 'CVE-2099-0004' THEN 'VULN' WHEN 'CVE-2099-0005' THEN 'DATA' WHEN 'DEV-ADV-0006' THEN 'HR'
  WHEN 'CVE-2099-0007' THEN 'OT' END;

INSERT INTO intel_sectors (item_id, sector_id)
SELECT i.id, s.id FROM intel_items i JOIN sectors s ON s.code IN ('ENERGY', 'MANUFACTURING')
WHERE i.external_id IN ('DEV-ADV-0002', 'CVE-2099-0007');

INSERT INTO intel_risks (item_id, risk_id, rule)
SELECT i.id, r.id, x.rule FROM intel_items i JOIN (
  SELECT 'CVE-2099-0001' AS ext, 'R-ACC-01' AS code, 'cwe.CWE-287' AS rule
  UNION ALL SELECT 'CVE-2099-0001', 'R-OPS-01', 'kev.listed'
  UNION ALL SELECT 'DEV-ADV-0002', 'R-OT-05', 'product.ot'
  UNION ALL SELECT 'DEV-ADV-0002', 'R-OT-03', 'product.ot'
  UNION ALL SELECT 'CVE-2099-0003', 'R-IT-24', 'cwe.CWE-78'
  UNION ALL SELECT 'CVE-2099-0004', 'R-OPS-01', 'kev.listed'
  UNION ALL SELECT 'DEV-ADV-0006', 'R-RH-01', 'keyword.phishing'
  UNION ALL SELECT 'CVE-2099-0007', 'R-IAM-05', 'cwe.CWE-798'
) x ON x.ext = i.external_id JOIN risks r ON r.code = x.code;

INSERT INTO leaks (source_id, external_id, leak_type, organisation, country, sector_id, actor, records_count,
                   data_classes, disclosed_at, url, status, published_at)
SELECT s.id, x.ext, x.type, x.org, x.country, (SELECT id FROM sectors WHERE code = x.sector), x.actor, x.records,
       x.classes, UTC_TIMESTAMP() - INTERVAL x.age HOUR, x.url, 'published', UTC_TIMESTAMP() - INTERVAL x.age HOUR
FROM sources s JOIN (
  SELECT 'DEV-LEAK-01' AS ext, 'ransomware' AS type, 'Commune Exemple-sur-Meuse' AS org, 'BE' AS country,
         'LOCAL_GOV' AS sector, 'ExempleLocker' AS actor, NULL AS records, '["Documents internes","Données personnelles"]' AS classes,
         6 AS age, 'https://example.org/leaks/01' AS url
  UNION ALL SELECT 'DEV-LEAK-02', 'breach', 'Clinique Exemple SA', 'BE', 'HEALTH', NULL, 125000,
         '["Noms","Adresses e-mail","Données de santé"]', 26, 'https://example.org/leaks/02'
  UNION ALL SELECT 'DEV-LEAK-03', 'ransomware', 'Exemple Industries NV', 'NL', 'MANUFACTURING', 'ExempleLocker', NULL,
         '["Plans techniques"]', 54, 'https://example.org/leaks/03'
  UNION ALL SELECT 'DEV-LEAK-04', 'exposure', 'Exemple Logistics GmbH', 'DE', 'TRANSPORT', NULL, 2400000,
         '["Adresses e-mail","Numéros de téléphone"]', 96, 'https://example.org/leaks/04'
  UNION ALL SELECT 'DEV-LEAK-05', 'breach', 'Exemple Shop SRL', 'FR', NULL, NULL, 38000,
         '["Mots de passe hachés","Adresses e-mail"]', 170, 'https://example.org/leaks/05'
) x ON s.code = 'DEV_LEAKS';
