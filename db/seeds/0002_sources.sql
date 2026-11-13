-- =============================================================================
-- Risk Studio v5 | Seed 0002 | Collector sources
-- INSERT IGNORE: created once, then managed in the database (an admin may
-- disable a source or change its editorial status without this seed undoing it).
--
-- authoritative = 1  items are published directly
-- authoritative = 0  items wait for an editorial decision (status pending)
-- =============================================================================

INSERT IGNORE INTO sources (code, name, kind, url, authoritative, enabled, poll_minutes) VALUES
  ('CISA_KEV',        'CISA KEV',            'json_api', 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', 1, 1, 60),
  ('EUVD_EXPLOITED',  'ENISA EUVD (exploitées)', 'json_api', 'https://euvdservices.enisa.europa.eu/api/exploitedvulnerabilities', 1, 1, 60),
  ('EUVD_CRITICAL',   'ENISA EUVD (critiques)',  'json_api', 'https://euvdservices.enisa.europa.eu/api/criticalvulnerabilities', 0, 1, 60),
  ('CERT_FR',         'CERT-FR',             'rss',      'https://www.cert.ssi.gouv.fr/feed/', 1, 1, 30),
  -- The CCB site rejects requests from data centres (HTTP 403): disabled until
  -- the feed is confirmed from the production hosting.
  ('CCB',             'CCB (CERT.be)',       'rss',      'https://ccb.belgium.be/advisories', 1, 0, 60),
  ('HIBP',            'Have I Been Pwned',   'json_api', 'https://haveibeenpwned.com/api/v3/breaches', 1, 1, 720),
  ('RANSOMWARE_LIVE', 'ransomware.live',     'json_api', 'https://api.ransomware.live/v2/recentvictims', 0, 1, 120),
  -- Leaks affecting French organisations. Authoritative for confirmed leaks
  -- only: claims (🟠 🔴) always wait for review.
  ('BONJOUR_LA_FUITE', 'Bonjour la fuite',   'rss',      'https://bonjourlafuite.eu.org/feed.xml', 1, 1, 60);
