-- ============================================================
-- Migration : Auto-publication des alertes cyber du worker
-- Objectif  : Les alertes insérées par le worker (significant)
--             sont publiées automatiquement sans validation manuelle.
--             Seules les soumissions communautaires (proposals)
--             conservent le workflow de validation.
--
-- À exécuter dans : Supabase Dashboard → SQL Editor
-- ============================================================

-- ------------------------------------------------------------
-- OPTION A (recommandée) : Trigger sur la table proposals
-- Si le worker insère dans proposals avec type='cyber'
-- et triage IN ('critical','significant'), on auto-approuve.
-- ------------------------------------------------------------

CREATE OR REPLACE FUNCTION auto_publish_cyber_proposals()
RETURNS TRIGGER AS $$
BEGIN
    -- Auto-publier uniquement les alertes cyber du worker
    -- (pas les soumissions communautaires qui n'ont pas de triage)
    IF NEW.type = 'cyber' AND NEW.triage IN ('critical', 'significant') AND NEW.status = 'pending' THEN

        -- Insérer directement dans risks comme publié
        INSERT INTO risks (
            titre, scenario, mesures, menace, impact,
            type, triage, status,
            cve_id, cvss_score, produits, patch_dispo, source_url,
            created_at
        ) VALUES (
            NEW.titre, NEW.scenario, NEW.mesures, NEW.menace, NEW.impact,
            NEW.type, NEW.triage, 'published',
            NEW.cve_id, NEW.cvss_score, NEW.produits, NEW.patch_dispo, NEW.source_url,
            NOW()
        );

        -- Marquer la proposal comme approuvée automatiquement
        NEW.status       := 'approved';
        NEW.reviewed_by  := 'auto-worker';
        NEW.reviewed_at  := NOW();
        NEW.admin_note   := 'Auto-publié par trigger (source: worker)';
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Attacher le trigger BEFORE INSERT sur proposals
DROP TRIGGER IF EXISTS trg_auto_publish_cyber ON proposals;
CREATE TRIGGER trg_auto_publish_cyber
    BEFORE INSERT ON proposals
    FOR EACH ROW
    EXECUTE FUNCTION auto_publish_cyber_proposals();

-- ------------------------------------------------------------
-- OPTION B (si le worker insère directement dans risks) :
-- Auto-publier les risks cyber pending insérés par le worker.
-- ------------------------------------------------------------

-- CREATE OR REPLACE FUNCTION auto_publish_cyber_risks()
-- RETURNS TRIGGER AS $$
-- BEGIN
--     IF NEW.type = 'cyber' AND NEW.triage IN ('critical', 'significant') AND NEW.status = 'pending' THEN
--         NEW.status := 'published';
--     END IF;
--     RETURN NEW;
-- END;
-- $$ LANGUAGE plpgsql;
--
-- DROP TRIGGER IF EXISTS trg_auto_publish_cyber_risks ON risks;
-- CREATE TRIGGER trg_auto_publish_cyber_risks
--     BEFORE INSERT ON risks
--     FOR EACH ROW
--     EXECUTE FUNCTION auto_publish_cyber_risks();

-- ------------------------------------------------------------
-- Vérification post-migration
-- ------------------------------------------------------------
-- SELECT trigger_name, event_manipulation, event_object_table
-- FROM information_schema.triggers
-- WHERE trigger_name LIKE 'trg_auto_publish%';
