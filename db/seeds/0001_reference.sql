-- =============================================================================
-- Risk Studio v5 | Seed 0001 | Reference data (idempotent)
-- ISO/IEC 27001:2022 Annex A: reference numbers only, titles are copyrighted.
-- NIS2 and NIST CSF 2.0 labels come from public texts.
-- =============================================================================

INSERT INTO categories (code, name_fr, name_en, sort_order) VALUES
  ('GOV', 'Gouvernance', 'Governance', 10),
  ('IAM', 'Identités et accès', 'Identity and access', 20),
  ('INFRA', 'Infrastructure et réseau', 'Infrastructure and network', 30),
  ('VULN', 'Vulnérabilités et correctifs', 'Vulnerabilities and patching', 40),
  ('DATA', 'Données et vie privée', 'Data and privacy', 50),
  ('BCM', 'Continuité d''activité', 'Business continuity', 60),
  ('CRISIS', 'Gestion de crise', 'Crisis management', 70),
  ('DEV', 'Développement sécurisé', 'Secure development', 80),
  ('AI', 'Intelligence artificielle', 'Artificial intelligence', 90),
  ('LEGAL', 'Juridique et conformité', 'Legal and compliance', 100),
  ('OT', 'Systèmes industriels (OT)', 'Operational technology', 110),
  ('OPS', 'Opérations', 'Operations', 120),
  ('PHYS', 'Sécurité physique', 'Physical security', 130),
  ('HR', 'Ressources humaines', 'Human resources', 140),
  ('SUPPLY', 'Chaîne d''approvisionnement', 'Supply chain', 150)
ON DUPLICATE KEY UPDATE name_fr = VALUES(name_fr), name_en = VALUES(name_en), sort_order = VALUES(sort_order);

INSERT INTO sectors (code, name_fr, name_en, nis2_annex, sort_order) VALUES
  ('ENERGY', 'Énergie', 'Energy', 'I', 10),
  ('TRANSPORT', 'Transports', 'Transport', 'I', 20),
  ('BANKING', 'Secteur bancaire', 'Banking', 'I', 30),
  ('FMI', 'Infrastructures des marchés financiers', 'Financial market infrastructures', 'I', 40),
  ('HEALTH', 'Santé', 'Health', 'I', 50),
  ('DRINKING_WATER', 'Eau potable', 'Drinking water', 'I', 60),
  ('WASTE_WATER', 'Eaux usées', 'Waste water', 'I', 70),
  ('DIGITAL_INFRA', 'Infrastructures numériques', 'Digital infrastructure', 'I', 80),
  ('ICT_B2B', 'Gestion des services ICT (B2B)', 'ICT service management (B2B)', 'I', 90),
  ('PUBLIC_ADMIN', 'Administration publique', 'Public administration', 'I', 100),
  ('SPACE', 'Espace', 'Space', 'I', 110),
  ('POSTAL', 'Services postaux et d''expédition', 'Postal and courier services', 'II', 120),
  ('WASTE', 'Gestion des déchets', 'Waste management', 'II', 130),
  ('CHEMICALS', 'Produits chimiques', 'Chemicals', 'II', 140),
  ('FOOD', 'Denrées alimentaires', 'Food', 'II', 150),
  ('MANUFACTURING', 'Fabrication', 'Manufacturing', 'II', 160),
  ('DIGITAL_PROVIDERS', 'Fournisseurs numériques', 'Digital providers', 'II', 170),
  ('RESEARCH', 'Recherche', 'Research', 'II', 180),
  ('LOCAL_GOV', 'Pouvoirs locaux', 'Local government', NULL, 190),
  ('EDUCATION', 'Enseignement', 'Education', NULL, 200),
  ('INSURANCE', 'Assurances', 'Insurance', NULL, 210),
  ('DEFENCE', 'Défense', 'Defence', NULL, 220),
  ('OTHER', 'Autre', 'Other', NULL, 230)
ON DUPLICATE KEY UPDATE name_fr = VALUES(name_fr), name_en = VALUES(name_en), nis2_annex = VALUES(nis2_annex), sort_order = VALUES(sort_order);

INSERT INTO frameworks (code, name, short_name, version, publisher, url, sort_order) VALUES
  ('ISO27001_2022', 'ISO/IEC 27001:2022', 'ISO 27001', '2022', 'ISO/IEC', 'https://www.iso.org/standard/27001', 10),
  ('NIS2', 'Directive (EU) 2022/2555 (NIS2)', 'NIS2', '2022', 'European Union', 'https://eur-lex.europa.eu/eli/dir/2022/2555/oj', 20),
  ('DORA', 'Regulation (EU) 2022/2554 (DORA)', 'DORA', '2022', 'European Union', 'https://eur-lex.europa.eu/eli/reg/2022/2554/oj', 30),
  ('CRA', 'Regulation (EU) 2024/2847 (Cyber Resilience Act)', 'CRA', '2024', 'European Union', 'https://eur-lex.europa.eu/eli/reg/2024/2847/oj', 40),
  ('CYFUN_2023', 'CyberFundamentals Framework', 'CyFun', '2023', 'Centre for Cybersecurity Belgium', 'https://atwork.safeonweb.be/tools-resources/cyberfundamentals-framework', 50),
  ('NIST_CSF_2', 'NIST Cybersecurity Framework', 'NIST CSF', '2.0', 'NIST', 'https://www.nist.gov/cyberframework', 60)
ON DUPLICATE KEY UPDATE name = VALUES(name), short_name = VALUES(short_name), version = VALUES(version), publisher = VALUES(publisher), url = VALUES(url), sort_order = VALUES(sort_order);

-- Controls: ISO27001_2022
INSERT INTO framework_controls (framework_id, ref, label, sort_order)
  SELECT f.id, 'A.5', 'Organizational controls', 10 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.5.1', NULL, 20 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.5.2', NULL, 30 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.5.3', NULL, 40 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.5.4', NULL, 50 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.5.5', NULL, 60 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.5.6', NULL, 70 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.5.7', NULL, 80 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.5.8', NULL, 90 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.5.9', NULL, 100 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.5.10', NULL, 110 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.5.11', NULL, 120 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.5.12', NULL, 130 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.5.13', NULL, 140 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.5.14', NULL, 150 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.5.15', NULL, 160 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.5.16', NULL, 170 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.5.17', NULL, 180 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.5.18', NULL, 190 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.5.19', NULL, 200 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.5.20', NULL, 210 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.5.21', NULL, 220 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.5.22', NULL, 230 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.5.23', NULL, 240 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.5.24', NULL, 250 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.5.25', NULL, 260 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.5.26', NULL, 270 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.5.27', NULL, 280 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.5.28', NULL, 290 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.5.29', NULL, 300 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.5.30', NULL, 310 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.5.31', NULL, 320 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.5.32', NULL, 330 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.5.33', NULL, 340 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.5.34', NULL, 350 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.5.35', NULL, 360 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.5.36', NULL, 370 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.5.37', NULL, 380 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.6', 'People controls', 390 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.6.1', NULL, 400 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.6.2', NULL, 410 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.6.3', NULL, 420 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.6.4', NULL, 430 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.6.5', NULL, 440 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.6.6', NULL, 450 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.6.7', NULL, 460 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.6.8', NULL, 470 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.7', 'Physical controls', 480 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.7.1', NULL, 490 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.7.2', NULL, 500 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.7.3', NULL, 510 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.7.4', NULL, 520 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.7.5', NULL, 530 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.7.6', NULL, 540 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.7.7', NULL, 550 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.7.8', NULL, 560 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.7.9', NULL, 570 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.7.10', NULL, 580 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.7.11', NULL, 590 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.7.12', NULL, 600 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.7.13', NULL, 610 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.7.14', NULL, 620 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.8', 'Technological controls', 630 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.8.1', NULL, 640 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.8.2', NULL, 650 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.8.3', NULL, 660 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.8.4', NULL, 670 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.8.5', NULL, 680 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.8.6', NULL, 690 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.8.7', NULL, 700 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.8.8', NULL, 710 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.8.9', NULL, 720 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.8.10', NULL, 730 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.8.11', NULL, 740 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.8.12', NULL, 750 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.8.13', NULL, 760 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.8.14', NULL, 770 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.8.15', NULL, 780 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.8.16', NULL, 790 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.8.17', NULL, 800 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.8.18', NULL, 810 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.8.19', NULL, 820 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.8.20', NULL, 830 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.8.21', NULL, 840 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.8.22', NULL, 850 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.8.23', NULL, 860 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.8.24', NULL, 870 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.8.25', NULL, 880 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.8.26', NULL, 890 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.8.27', NULL, 900 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.8.28', NULL, 910 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.8.29', NULL, 920 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.8.30', NULL, 930 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.8.31', NULL, 940 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.8.32', NULL, 950 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.8.33', NULL, 960 FROM frameworks f WHERE f.code = 'ISO27001_2022'
  UNION ALL
  SELECT f.id, 'A.8.34', NULL, 970 FROM frameworks f WHERE f.code = 'ISO27001_2022'
ON DUPLICATE KEY UPDATE label = VALUES(label), sort_order = VALUES(sort_order);
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.5' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.5.1';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.5' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.5.2';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.5' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.5.3';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.5' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.5.4';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.5' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.5.5';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.5' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.5.6';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.5' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.5.7';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.5' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.5.8';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.5' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.5.9';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.5' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.5.10';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.5' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.5.11';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.5' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.5.12';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.5' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.5.13';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.5' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.5.14';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.5' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.5.15';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.5' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.5.16';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.5' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.5.17';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.5' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.5.18';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.5' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.5.19';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.5' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.5.20';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.5' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.5.21';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.5' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.5.22';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.5' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.5.23';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.5' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.5.24';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.5' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.5.25';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.5' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.5.26';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.5' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.5.27';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.5' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.5.28';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.5' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.5.29';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.5' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.5.30';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.5' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.5.31';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.5' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.5.32';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.5' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.5.33';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.5' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.5.34';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.5' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.5.35';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.5' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.5.36';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.5' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.5.37';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.6' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.6.1';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.6' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.6.2';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.6' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.6.3';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.6' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.6.4';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.6' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.6.5';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.6' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.6.6';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.6' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.6.7';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.6' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.6.8';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.7' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.7.1';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.7' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.7.2';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.7' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.7.3';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.7' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.7.4';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.7' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.7.5';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.7' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.7.6';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.7' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.7.7';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.7' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.7.8';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.7' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.7.9';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.7' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.7.10';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.7' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.7.11';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.7' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.7.12';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.7' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.7.13';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.7' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.7.14';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.8' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.8.1';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.8' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.8.2';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.8' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.8.3';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.8' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.8.4';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.8' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.8.5';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.8' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.8.6';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.8' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.8.7';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.8' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.8.8';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.8' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.8.9';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.8' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.8.10';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.8' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.8.11';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.8' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.8.12';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.8' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.8.13';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.8' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.8.14';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.8' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.8.15';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.8' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.8.16';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.8' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.8.17';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.8' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.8.18';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.8' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.8.19';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.8' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.8.20';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.8' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.8.21';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.8' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.8.22';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.8' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.8.23';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.8' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.8.24';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.8' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.8.25';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.8' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.8.26';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.8' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.8.27';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.8' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.8.28';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.8' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.8.29';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.8' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.8.30';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.8' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.8.31';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.8' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.8.32';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.8' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.8.33';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'A.8' SET c.parent_id = p.id WHERE f.code = 'ISO27001_2022' AND c.ref = 'A.8.34';

-- Controls: NIS2
INSERT INTO framework_controls (framework_id, ref, label, sort_order)
  SELECT f.id, 'Art.20', 'Governance: management body approval, oversight and training', 10 FROM frameworks f WHERE f.code = 'NIS2'
  UNION ALL
  SELECT f.id, 'Art.21', 'Cybersecurity risk-management measures', 20 FROM frameworks f WHERE f.code = 'NIS2'
  UNION ALL
  SELECT f.id, 'Art.21.2.a', 'Policies on risk analysis and information system security', 30 FROM frameworks f WHERE f.code = 'NIS2'
  UNION ALL
  SELECT f.id, 'Art.21.2.b', 'Incident handling', 40 FROM frameworks f WHERE f.code = 'NIS2'
  UNION ALL
  SELECT f.id, 'Art.21.2.c', 'Business continuity, backup management, disaster recovery and crisis management', 50 FROM frameworks f WHERE f.code = 'NIS2'
  UNION ALL
  SELECT f.id, 'Art.21.2.d', 'Supply chain security', 60 FROM frameworks f WHERE f.code = 'NIS2'
  UNION ALL
  SELECT f.id, 'Art.21.2.e', 'Security in acquisition, development and maintenance, including vulnerability handling and disclosure', 70 FROM frameworks f WHERE f.code = 'NIS2'
  UNION ALL
  SELECT f.id, 'Art.21.2.f', 'Policies and procedures to assess the effectiveness of risk-management measures', 80 FROM frameworks f WHERE f.code = 'NIS2'
  UNION ALL
  SELECT f.id, 'Art.21.2.g', 'Basic cyber hygiene practices and cybersecurity training', 90 FROM frameworks f WHERE f.code = 'NIS2'
  UNION ALL
  SELECT f.id, 'Art.21.2.h', 'Policies and procedures regarding the use of cryptography and encryption', 100 FROM frameworks f WHERE f.code = 'NIS2'
  UNION ALL
  SELECT f.id, 'Art.21.2.i', 'Human resources security, access control policies and asset management', 110 FROM frameworks f WHERE f.code = 'NIS2'
  UNION ALL
  SELECT f.id, 'Art.21.2.j', 'Multi-factor or continuous authentication, secured communications and emergency communication systems', 120 FROM frameworks f WHERE f.code = 'NIS2'
  UNION ALL
  SELECT f.id, 'Art.23', 'Reporting obligations for significant incidents', 130 FROM frameworks f WHERE f.code = 'NIS2'
ON DUPLICATE KEY UPDATE label = VALUES(label), sort_order = VALUES(sort_order);
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'Art.21' SET c.parent_id = p.id WHERE f.code = 'NIS2' AND c.ref = 'Art.21.2.a';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'Art.21' SET c.parent_id = p.id WHERE f.code = 'NIS2' AND c.ref = 'Art.21.2.b';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'Art.21' SET c.parent_id = p.id WHERE f.code = 'NIS2' AND c.ref = 'Art.21.2.c';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'Art.21' SET c.parent_id = p.id WHERE f.code = 'NIS2' AND c.ref = 'Art.21.2.d';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'Art.21' SET c.parent_id = p.id WHERE f.code = 'NIS2' AND c.ref = 'Art.21.2.e';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'Art.21' SET c.parent_id = p.id WHERE f.code = 'NIS2' AND c.ref = 'Art.21.2.f';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'Art.21' SET c.parent_id = p.id WHERE f.code = 'NIS2' AND c.ref = 'Art.21.2.g';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'Art.21' SET c.parent_id = p.id WHERE f.code = 'NIS2' AND c.ref = 'Art.21.2.h';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'Art.21' SET c.parent_id = p.id WHERE f.code = 'NIS2' AND c.ref = 'Art.21.2.i';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'Art.21' SET c.parent_id = p.id WHERE f.code = 'NIS2' AND c.ref = 'Art.21.2.j';

-- Controls: NIST_CSF_2
INSERT INTO framework_controls (framework_id, ref, label, sort_order)
  SELECT f.id, 'GV', 'Govern', 10 FROM frameworks f WHERE f.code = 'NIST_CSF_2'
  UNION ALL
  SELECT f.id, 'GV.OC', 'Organizational Context', 20 FROM frameworks f WHERE f.code = 'NIST_CSF_2'
  UNION ALL
  SELECT f.id, 'GV.RM', 'Risk Management Strategy', 30 FROM frameworks f WHERE f.code = 'NIST_CSF_2'
  UNION ALL
  SELECT f.id, 'GV.RR', 'Roles, Responsibilities, and Authorities', 40 FROM frameworks f WHERE f.code = 'NIST_CSF_2'
  UNION ALL
  SELECT f.id, 'GV.PO', 'Policy', 50 FROM frameworks f WHERE f.code = 'NIST_CSF_2'
  UNION ALL
  SELECT f.id, 'GV.OV', 'Oversight', 60 FROM frameworks f WHERE f.code = 'NIST_CSF_2'
  UNION ALL
  SELECT f.id, 'GV.SC', 'Cybersecurity Supply Chain Risk Management', 70 FROM frameworks f WHERE f.code = 'NIST_CSF_2'
  UNION ALL
  SELECT f.id, 'ID', 'Identify', 80 FROM frameworks f WHERE f.code = 'NIST_CSF_2'
  UNION ALL
  SELECT f.id, 'ID.AM', 'Asset Management', 90 FROM frameworks f WHERE f.code = 'NIST_CSF_2'
  UNION ALL
  SELECT f.id, 'ID.RA', 'Risk Assessment', 100 FROM frameworks f WHERE f.code = 'NIST_CSF_2'
  UNION ALL
  SELECT f.id, 'ID.IM', 'Improvement', 110 FROM frameworks f WHERE f.code = 'NIST_CSF_2'
  UNION ALL
  SELECT f.id, 'PR', 'Protect', 120 FROM frameworks f WHERE f.code = 'NIST_CSF_2'
  UNION ALL
  SELECT f.id, 'PR.AA', 'Identity Management, Authentication, and Access Control', 130 FROM frameworks f WHERE f.code = 'NIST_CSF_2'
  UNION ALL
  SELECT f.id, 'PR.AT', 'Awareness and Training', 140 FROM frameworks f WHERE f.code = 'NIST_CSF_2'
  UNION ALL
  SELECT f.id, 'PR.DS', 'Data Security', 150 FROM frameworks f WHERE f.code = 'NIST_CSF_2'
  UNION ALL
  SELECT f.id, 'PR.PS', 'Platform Security', 160 FROM frameworks f WHERE f.code = 'NIST_CSF_2'
  UNION ALL
  SELECT f.id, 'PR.IR', 'Technology Infrastructure Resilience', 170 FROM frameworks f WHERE f.code = 'NIST_CSF_2'
  UNION ALL
  SELECT f.id, 'DE', 'Detect', 180 FROM frameworks f WHERE f.code = 'NIST_CSF_2'
  UNION ALL
  SELECT f.id, 'DE.CM', 'Continuous Monitoring', 190 FROM frameworks f WHERE f.code = 'NIST_CSF_2'
  UNION ALL
  SELECT f.id, 'DE.AE', 'Adverse Event Analysis', 200 FROM frameworks f WHERE f.code = 'NIST_CSF_2'
  UNION ALL
  SELECT f.id, 'RS', 'Respond', 210 FROM frameworks f WHERE f.code = 'NIST_CSF_2'
  UNION ALL
  SELECT f.id, 'RS.MA', 'Incident Management', 220 FROM frameworks f WHERE f.code = 'NIST_CSF_2'
  UNION ALL
  SELECT f.id, 'RS.AN', 'Incident Analysis', 230 FROM frameworks f WHERE f.code = 'NIST_CSF_2'
  UNION ALL
  SELECT f.id, 'RS.CO', 'Incident Response Reporting and Communication', 240 FROM frameworks f WHERE f.code = 'NIST_CSF_2'
  UNION ALL
  SELECT f.id, 'RS.MI', 'Incident Mitigation', 250 FROM frameworks f WHERE f.code = 'NIST_CSF_2'
  UNION ALL
  SELECT f.id, 'RC', 'Recover', 260 FROM frameworks f WHERE f.code = 'NIST_CSF_2'
  UNION ALL
  SELECT f.id, 'RC.RP', 'Incident Recovery Plan Execution', 270 FROM frameworks f WHERE f.code = 'NIST_CSF_2'
  UNION ALL
  SELECT f.id, 'RC.CO', 'Incident Recovery Communication', 280 FROM frameworks f WHERE f.code = 'NIST_CSF_2'
ON DUPLICATE KEY UPDATE label = VALUES(label), sort_order = VALUES(sort_order);
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'GV' SET c.parent_id = p.id WHERE f.code = 'NIST_CSF_2' AND c.ref = 'GV.OC';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'GV' SET c.parent_id = p.id WHERE f.code = 'NIST_CSF_2' AND c.ref = 'GV.RM';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'GV' SET c.parent_id = p.id WHERE f.code = 'NIST_CSF_2' AND c.ref = 'GV.RR';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'GV' SET c.parent_id = p.id WHERE f.code = 'NIST_CSF_2' AND c.ref = 'GV.PO';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'GV' SET c.parent_id = p.id WHERE f.code = 'NIST_CSF_2' AND c.ref = 'GV.OV';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'GV' SET c.parent_id = p.id WHERE f.code = 'NIST_CSF_2' AND c.ref = 'GV.SC';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'ID' SET c.parent_id = p.id WHERE f.code = 'NIST_CSF_2' AND c.ref = 'ID.AM';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'ID' SET c.parent_id = p.id WHERE f.code = 'NIST_CSF_2' AND c.ref = 'ID.RA';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'ID' SET c.parent_id = p.id WHERE f.code = 'NIST_CSF_2' AND c.ref = 'ID.IM';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'PR' SET c.parent_id = p.id WHERE f.code = 'NIST_CSF_2' AND c.ref = 'PR.AA';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'PR' SET c.parent_id = p.id WHERE f.code = 'NIST_CSF_2' AND c.ref = 'PR.AT';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'PR' SET c.parent_id = p.id WHERE f.code = 'NIST_CSF_2' AND c.ref = 'PR.DS';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'PR' SET c.parent_id = p.id WHERE f.code = 'NIST_CSF_2' AND c.ref = 'PR.PS';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'PR' SET c.parent_id = p.id WHERE f.code = 'NIST_CSF_2' AND c.ref = 'PR.IR';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'DE' SET c.parent_id = p.id WHERE f.code = 'NIST_CSF_2' AND c.ref = 'DE.CM';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'DE' SET c.parent_id = p.id WHERE f.code = 'NIST_CSF_2' AND c.ref = 'DE.AE';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'RS' SET c.parent_id = p.id WHERE f.code = 'NIST_CSF_2' AND c.ref = 'RS.MA';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'RS' SET c.parent_id = p.id WHERE f.code = 'NIST_CSF_2' AND c.ref = 'RS.AN';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'RS' SET c.parent_id = p.id WHERE f.code = 'NIST_CSF_2' AND c.ref = 'RS.CO';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'RS' SET c.parent_id = p.id WHERE f.code = 'NIST_CSF_2' AND c.ref = 'RS.MI';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'RC' SET c.parent_id = p.id WHERE f.code = 'NIST_CSF_2' AND c.ref = 'RC.RP';
UPDATE framework_controls c JOIN frameworks f ON f.id = c.framework_id JOIN framework_controls p ON p.framework_id = f.id AND p.ref = 'RC' SET c.parent_id = p.id WHERE f.code = 'NIST_CSF_2' AND c.ref = 'RC.CO';
