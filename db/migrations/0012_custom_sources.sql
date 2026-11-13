-- =============================================================================
-- Risk Studio v5 | Migration 0012 | Sources added from the administration
-- A custom source is an RSS or Atom feed read by the generic reader, set up
-- without code: `config` holds the view it feeds, a default country and
-- keyword filters (api/src/Collector/SourceConfig.php).
-- =============================================================================

ALTER TABLE sources
  ADD COLUMN custom TINYINT(1) NOT NULL DEFAULT 0 AFTER poll_minutes,
  ADD COLUMN config LONGTEXT NULL AFTER custom,
  ADD CONSTRAINT ck_sources_config CHECK (config IS NULL OR JSON_VALID(config));
