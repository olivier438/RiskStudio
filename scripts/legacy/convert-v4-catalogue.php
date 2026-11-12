<?php

/**
 * One-shot conversion of the v4 catalogue (legacy/risques.csv) into the v5
 * source file (db/catalogue/risks.csv), plus a review report.
 *
 * Kept in the repository for traceability: every editorial decision taken
 * during the migration is written below, explicitly, and lands in the report
 * docs/catalogue-v4-migration.md. Once the v5 file is validated, it becomes the
 * source of truth and this script is not run again.
 *
 *   php scripts/legacy/convert-v4-catalogue.php
 */

declare(strict_types=1);

$root = dirname(__DIR__, 2);

// -----------------------------------------------------------------------------
// Category: v4 label -> v5 code. Per-risk overrides below take precedence.
// -----------------------------------------------------------------------------
const CATEGORY = [
    'Gouvernance' => 'GOV', 'Accès' => 'IAM', 'IAM' => 'IAM', 'Opérations' => 'OPS',
    'Supply Chain' => 'SUPPLY', 'RH' => 'HR', 'Physique' => 'PHYS', 'Développement' => 'DEV',
    'Données' => 'DATA', 'Continuité' => 'BCM', 'Infrastructure' => 'INFRA', 'IA' => 'AI',
    'OT' => 'OT', 'Juridique' => 'LEGAL', 'Crise' => 'CRISIS',
];

// v4 sector label -> v5 sector codes. "Tous" and pseudo-sectors mean cross-sector.
const SECTORS = [
    'Tous' => [], 'Santé' => ['HEALTH'], 'Finance' => ['BANKING', 'INSURANCE'],
    'Industrie' => ['MANUFACTURING'], 'Énergie' => ['ENERGY'],
    'Secteur Public' => ['PUBLIC_ADMIN', 'LOCAL_GOV'], 'Défense' => ['DEFENCE'],
    'Technologie' => ['DIGITAL_PROVIDERS', 'ICT_B2B'],
    // These were categories or functions, not sectors: treated as cross-sector.
    'Développement' => [], 'RH' => [],
];

// -----------------------------------------------------------------------------
// Per-risk editorial decisions.
//   iso   ISO/IEC 27001:2022 references (Annex A "A.x.y" or clauses "9.3")
//   dora  DORA articles, only when the v4 value was wrong or missing
//   nis2  NIS2 references added on top of the crosswalk
//   cra   Cyber Resilience Act references
//   cat, env, sectors, cia, title, threat, scenario, measures: corrections
// -----------------------------------------------------------------------------
const RISKS = [
    'R-GOV-01' => ['iso' => '5.2|A.5.1', 'cia' => 'CIA', 'title' => "Absence d'Information Security Policy",
                   'measures' => "Rédiger, faire approuver par la direction et diffuser une Information Security Policy."],
    'R-GOV-02' => ['iso' => '9.3|A.5.4', 'nis2' => 'Art.20'],
    'R-GOV-03' => ['iso' => '7.1|5.1', 'nis2' => 'Art.20'],
    'R-ACC-01' => ['iso' => 'A.8.5|A.5.17', 'nis2' => 'Art.21.2.j'],
    'R-ACC-02' => ['iso' => 'A.5.16|A.8.2'],
    'R-ACC-03' => ['iso' => 'A.5.15|A.5.18|A.8.3'],
    'R-ACC-04' => ['iso' => 'A.5.17'],
    'R-OPS-01' => ['iso' => 'A.8.8', 'cat' => 'VULN'],
    'R-OPS-02' => ['iso' => 'A.8.13', 'cat' => 'BCM'],
    'R-OPS-03' => ['iso' => 'A.8.22|A.8.20', 'cat' => 'OT', 'env' => 'BOTH', 'sectors' => 'MANUFACTURING|ENERGY',
                   'threat' => 'Propagation de malware',
                   'scenario' => "Un malware introduit sur le réseau bureautique se propage jusqu'aux automates faute de cloisonnement entre IT et OT."],
    'R-OPS-04' => ['iso' => 'A.8.15|A.8.16'],
    'R-SUP-01' => ['iso' => 'A.5.19|A.5.23|A.5.30'],
    'R-SUP-02' => ['iso' => 'A.5.15|A.5.19|A.5.20'],
    'R-RH-01'  => ['iso' => 'A.6.3'],
    'R-RH-02'  => ['iso' => 'A.6.5|A.5.11|A.5.18'],
    'R-PHY-01' => ['iso' => 'A.7.1|A.7.2|A.7.3'],
    'R-PHY-02' => ['iso' => 'A.7.9|A.8.1|A.8.24'],
    'R-DEV-01' => ['iso' => 'A.8.4|A.8.25|A.8.28', 'cra' => 'AnnexI.I.1'],
    'R-DAT-01' => ['iso' => 'A.5.12|A.5.13'],
    'R-BCP-01' => ['iso' => 'A.5.29|A.5.30', 'title' => 'Disaster Recovery Plan non documenté',
                   'measures' => 'Rédiger un Disaster Recovery Plan détaillé et le tester.'],
    'R-IT-21'  => ['iso' => 'A.5.9|A.5.23'],
    'R-IT-22'  => ['merged_into' => 'R-AIA-02'],
    'R-IT-23'  => ['iso' => 'A.8.6|A.5.23', 'scenario' => "Une boucle infinie ou une attaque DDoS fait exploser la facture Cloud et coupe le service."],
    'R-IT-24'  => ['iso' => 'A.8.25|A.8.32|A.8.4|A.8.31', 'dora' => 'Art.9', 'cra' => 'AnnexI.I.2.f|AnnexI.II.7'],
    'R-IT-25'  => ['iso' => 'A.8.4|A.8.9|A.8.25', 'cat' => 'DEV'],
    'R-IT-26'  => ['iso' => 'A.6.3|A.5.37'],
    'R-IT-27'  => ['iso' => 'A.5.9|A.8.10|A.5.23'],
    'R-IT-28'  => ['iso' => 'A.8.20|A.8.22', 'cat' => 'INFRA'],
    'R-IT-29'  => ['iso' => 'A.8.13', 'cat' => 'BCM'],
    'R-IT-30'  => ['iso' => 'A.8.16|A.8.12'],
    'R-OT-01'  => ['iso' => 'A.5.19|A.5.22|A.8.5'],
    'R-OT-02'  => ['iso' => 'A.7.10|A.8.7'],
    'R-OT-03'  => ['iso' => 'A.8.22|A.8.20|A.8.6'],
    'R-OT-04'  => ['iso' => 'A.8.8|A.8.22', 'cat' => 'VULN', 'env' => 'OT'],
    'R-OT-05'  => ['iso' => 'A.8.9|A.8.32|A.8.19'],
    'R-OT-06'  => ['iso' => 'A.8.16|A.8.20'],
    'R-OT-07'  => ['iso' => 'A.8.14|A.8.20'],
    'R-OT-08'  => ['iso' => 'A.7.2|A.8.20'],
    'R-OT-09'  => ['iso' => 'A.5.9'],
    'R-OT-10'  => ['iso' => 'A.8.22|A.8.20', 'env' => 'BOTH',
                   'measures' => "Mise en œuvre d'une DMZ industrielle et de pare-feu à inspection profonde (Deep Packet Inspection)."],
    'R-PHY-03' => ['iso' => 'A.7.2|A.6.3'],
    'R-PHY-04' => ['iso' => 'A.7.2'],
    'R-PHY-05' => ['iso' => 'A.7.2', 'env' => 'BOTH'],
    'R-PHY-06' => ['iso' => 'A.7.2|A.7.3'],
    'R-PHY-07' => ['iso' => 'A.7.5'],
    'R-PHY-08' => ['iso' => 'A.7.5|A.7.8'],
    'R-PHY-09' => ['iso' => 'A.7.9|A.7.10|A.8.24'],
    'R-PHY-10' => ['iso' => 'A.7.7|A.7.8'],
    'R-PHY-11' => ['iso' => 'A.7.7'],
    'R-PHY-12' => ['iso' => 'A.7.8'],
    'R-PHY-13' => ['iso' => 'A.7.11'],
    'R-PHY-14' => ['iso' => 'A.7.12|A.8.14'],
    'R-PHY-15' => ['iso' => 'A.7.11'],
    'R-PHY-16' => ['iso' => 'A.7.8|A.7.12|A.8.20'],
    'R-PHY-17' => ['iso' => 'A.6.3|A.7.7'],
    'R-PHY-18' => ['iso' => 'A.7.1|A.7.3'],
    'R-PHY-19' => ['iso' => 'A.7.8|A.7.2'],
    'R-PHY-20' => ['iso' => 'A.7.4'],
    'R-SUP-03' => ['iso' => 'A.5.21|A.8.28', 'cra' => 'AnnexI.II.1'],
    'R-SUP-04' => ['iso' => 'A.5.19|A.5.22|A.8.5', 'dora' => 'Art.28', 'env' => 'BOTH',
                   'scenario' => "Un attaquant compromet le PC d'un technicien de maintenance et utilise son VPN actif pour entrer chez le client."],
    'R-SUP-05' => ['iso' => 'A.5.23|A.5.30|A.8.14',
                   'scenario' => "Une panne majeure chez Microsoft Entra ID ou Okta empêche tous les employés de se connecter aux outils."],
    'R-SUP-06' => ['iso' => 'A.5.21', 'cra' => 'AnnexI.I.2.f'],
    'R-SUP-07' => ['iso' => 'A.5.19|A.5.20|A.5.30'],
    'R-SUP-08' => ['iso' => 'A.5.22|A.5.20'],
    'R-SUP-09' => ['iso' => 'A.5.20|A.5.14'],
    'R-SUP-10' => ['iso' => 'A.5.23|A.5.31|A.5.34'],
    'R-SUP-11' => ['iso' => 'A.5.21|A.7.9'],
    'R-SUP-12' => ['iso' => 'A.5.20|A.5.34', 'threat' => 'Violation GDPR'],
    'R-SUP-13' => ['iso' => 'A.5.21|A.5.20'],
    'R-SUP-14' => ['iso' => 'A.5.21|A.8.8', 'cra' => 'Art.13|AnnexI.II.2'],
    'R-SUP-15' => ['iso' => 'A.5.21|A.8.16'],
    'R-SUP-16' => ['iso' => 'A.5.30'],
    'R-SUP-17' => ['iso' => 'A.5.22|A.8.24'],
    'R-SUP-18' => ['iso' => 'A.5.19|A.5.20|A.5.22'],
    'R-SUP-19' => ['iso' => 'A.5.21|A.8.7'],
    'R-SUP-20' => ['iso' => 'A.5.22|A.8.7'],
    'R-AIA-01' => ['iso' => 'A.5.10|A.8.12|A.5.23'],
    'R-AIA-02' => ['iso' => 'A.8.25|A.8.26|A.8.28'],
    'R-AIA-03' => ['iso' => 'A.8.25'],
    'R-AIA-04' => ['iso' => ''],
    'R-AIA-05' => ['iso' => 'A.5.32|A.5.31'],
    'R-AIA-06' => ['iso' => 'A.8.26'],
    'R-AIA-07' => ['iso' => 'A.5.31', 'sectors' => 'PUBLIC_ADMIN|LOCAL_GOV'],
    'R-AIA-08' => ['iso' => 'A.5.19|A.5.23|A.5.30'],
    'R-AIA-09' => ['iso' => '', 'env' => 'BOTH'],
    'R-AIA-10' => ['iso' => 'A.6.3'],
    'R-AIA-11' => ['iso' => 'A.5.31'],
    'R-AIA-12' => ['iso' => 'A.8.15|A.8.11'],
    'R-AIA-13' => ['iso' => ''],
    'R-AIA-14' => ['iso' => 'A.5.10|A.5.17'],
    'R-AIA-15' => ['iso' => 'A.8.5'],
    'R-AIA-16' => ['iso' => ''],
    'R-AIA-17' => ['iso' => 'A.5.31'],
    'R-AIA-18' => ['iso' => 'A.8.26|A.8.29'],
    'R-AIA-19' => ['iso' => 'A.5.21|A.8.7|A.8.19'],
    'R-AIA-20' => ['iso' => ''],
    'R-HOS-01' => ['iso' => 'A.5.29|A.5.30|A.8.13', 'cat' => 'BCM', 'title' => 'Indisponibilité du Dossier Patient Informatisé'],
    'R-HOS-02' => ['iso' => 'A.8.20|A.8.22', 'cat' => 'INFRA', 'env' => 'BOTH',
                   'measures' => 'Segmentation VLAN dédiée aux dispositifs médicaux connectés.'],
    'R-HOS-03' => ['iso' => 'A.8.12|A.8.24|A.5.34',
                   'scenario' => "La base de données des patients est revendue sur le Darkweb, violant gravement le GDPR."],
    'R-HOS-04' => ['iso' => 'A.5.15|A.8.15|A.8.16', 'cat' => 'IAM'],
    'R-HOS-05' => ['iso' => 'A.8.14|A.8.20', 'cat' => 'INFRA'],
    'R-HOS-06' => ['iso' => 'A.8.5|A.7.7', 'cat' => 'IAM'],
    'R-HOS-07' => ['iso' => 'A.7.11', 'cat' => 'PHYS'],
    'R-HOS-08' => ['iso' => 'A.5.19|A.5.22|A.8.7'],
    'R-HOS-09' => ['iso' => 'A.5.33|A.8.13', 'cat' => 'DATA'],
    'R-HOS-10' => ['iso' => 'A.8.8|A.8.22', 'cat' => 'VULN'],
    'R-HOS-11' => ['iso' => 'A.7.11|A.5.30'],
    'R-HOS-12' => ['iso' => 'A.8.26|A.5.23|A.8.24', 'cat' => 'DATA',
                   'measures' => 'Utilisation de solutions certifiées pour l\'hébergement de données de santé et chiffrement de bout en bout.'],
    'R-HOS-13' => ['iso' => 'A.8.20|A.8.22|A.8.6', 'cat' => 'INFRA'],
    'R-HOS-14' => ['iso' => ''],
    'R-HOS-15' => ['iso' => 'A.7.2|A.8.24'],
    'R-HOS-16' => ['iso' => 'A.5.30', 'cat' => 'BCM'],
    'R-HOS-17' => ['iso' => 'A.8.11|A.5.34'],
    'R-HOS-18' => ['iso' => 'A.6.3'],
    'R-HOS-19' => ['iso' => 'A.5.23|A.5.30'],
    'R-HOS-20' => ['iso' => 'A.7.11|A.8.22', 'env' => 'BOTH',
                   'title' => 'Sabotage du Building Management System (BMS)',
                   'measures' => "Isolation du réseau du Building Management System du réseau IT et contrôle d'accès physique."],
    'R-LEG-01' => ['iso' => 'A.5.31|A.5.34', 'title' => 'Non-conformité majeure au GDPR',
                   'measures' => "Désignation d'un Data Protection Officer et tenue du registre des traitements."],
    'R-LEG-02' => ['iso' => 'A.5.31|A.5.36', 'nis2' => 'Art.20',
                   'scenario' => "L'autorité nationale (le CCB en Belgique) impose une amende pour défaut de mesures de sécurité essentielles."],
    'R-LEG-03' => ['iso' => 'A.5.32'],
    'R-LEG-04' => ['iso' => 'A.5.24|A.5.26|A.5.31', 'nis2' => 'Art.23',
                   'scenario' => "L'entreprise cache un incident significatif et manque les délais légaux de notification (24h pour l'alerte précoce NIS2, 72h pour le GDPR)."],
    'R-LEG-05' => ['iso' => 'A.5.31|A.5.36'],
    'R-LEG-06' => ['iso' => 'A.8.15|A.5.28'],
    'R-LEG-07' => ['iso' => 'A.5.23|A.5.31|A.5.34',
                   'measures' => 'Hébergement sur un Cloud souverain qualifié (SecNumCloud, EUCS) ou chiffrement avec gestion des clés par le client.'],
    'R-CRI-01' => ['iso' => 'A.5.24|A.5.29'],
    'R-CRI-02' => ['iso' => 'A.5.24|A.5.29'],
    'R-CRI-03' => ['iso' => 'A.5.37'],
    'R-CRI-04' => ['iso' => 'A.5.29|A.5.30|A.6.7'],
    'R-CRI-05' => ['iso' => 'A.5.24|A.5.20'],
    'R-HUM-01' => ['iso' => ''],
    'R-HUM-02' => ['iso' => 'A.6.3|A.5.17'],
    'R-HUM-03' => ['iso' => 'A.8.2|A.5.3|A.6.5'],
    'R-HUM-04' => ['iso' => 'A.5.10|A.6.4'],
    'R-HUM-05' => ['iso' => 'A.6.6|A.5.15'],
    'R-TEC-01' => ['iso' => 'A.8.24', 'cat' => 'INFRA', 'title' => 'Algorithmes cryptographiques obsolètes'],
    'R-TEC-02' => ['iso' => 'A.7.8', 'cat' => 'PHYS'],
    'R-TEC-03' => ['iso' => 'A.8.17', 'cat' => 'OPS'],
    'R-EXT-01' => ['iso' => 'A.5.31'],
    'R-EXT-02' => ['iso' => 'A.5.29|A.5.30'],
    'R-EXT-03' => ['iso' => 'A.5.29|A.5.30',
                   'measures' => "Business Continuity Plan spécifique aux pandémies."],
    'R-EXT-04' => ['iso' => 'A.7.5|A.8.14|A.5.30'],
    'R-EXT-05' => ['iso' => 'A.8.26|A.8.16'],
    'R-LEG-08' => ['iso' => 'A.5.31'],
    'R-LEG-09' => ['iso' => 'A.5.34|A.5.20', 'measures' => 'Convention de responsabilité conjointe (Art. 26 GDPR).'],
    'R-LEG-10' => ['iso' => 'A.5.31'],
    'R-CRI-06' => ['iso' => 'A.8.13|A.5.37'],
    'R-TEC-04' => ['iso' => 'A.8.17', 'env' => 'OT'],
    'R-HUM-06' => ['iso' => 'A.6.3|A.7.2'],
    'R-TEC-05' => ['iso' => 'A.8.15|A.8.16'],
    'R-IAM-01' => ['iso' => 'A.5.18|A.6.5'],
    'R-IAM-02' => ['iso' => 'A.8.5|A.6.3', 'nis2' => 'Art.21.2.j'],
    'R-IAM-03' => ['iso' => 'A.5.18'],
    'R-IAM-04' => ['iso' => 'A.8.5|A.8.24'],
    'R-IAM-05' => ['iso' => 'A.5.17|A.8.2'],
    'R-IAM-06' => ['iso' => 'A.8.2|A.8.5', 'nis2' => 'Art.21.2.j'],
    'R-IAM-07' => ['iso' => 'A.8.2|A.5.18'],
    'R-IAM-08' => ['iso' => 'A.5.16|A.5.18'],
    'R-IAM-09' => ['iso' => 'A.5.17|A.8.5'],
    'R-IAM-10' => ['iso' => 'A.8.2|A.8.5|A.8.16'],
    'R-IAM-11' => ['iso' => 'A.5.3'],
    'R-IAM-12' => ['iso' => 'A.5.18|A.5.19'],
    'R-IAM-13' => ['iso' => 'A.8.24|A.5.17', 'cra' => 'AnnexI.I.2.e'],
    'R-IAM-14' => ['iso' => 'A.8.5'],
    'R-IAM-15' => ['iso' => 'A.5.15|A.8.5'],
    'R-IAM-16' => ['iso' => 'A.7.7|A.8.5'],
    'R-IAM-17' => ['iso' => 'A.8.5', 'nis2' => 'Art.21.2.j'],
    'R-IAM-18' => ['iso' => 'A.8.15|A.5.18'],
    'R-IAM-19' => ['iso' => 'A.8.2|A.8.19'],
    'R-IAM-20' => ['iso' => 'A.5.16|A.8.5', 'env' => 'BOTH'],
];

// Wrong v4 DORA references, fixed wherever they appear.
const DORA_FIX = ['Art.15' => 'Art.9', 'Art.29' => 'Art.28'];

// -----------------------------------------------------------------------------

function cia(string $dic): string
{
    $out = '';
    foreach (['C' => 'C', 'I' => 'I', 'D' => 'A'] as $from => $to) {
        if (str_contains($dic, $from)) {
            $out .= $to;
        }
    }

    return $out;
}

function clean(string $text): string
{
    $text = trim(preg_replace('/\s+/u', ' ', $text) ?? $text);

    return strtr($text, ['RGPD' => 'GDPR', 'DDOS' => 'DDoS', 'Azure AD' => 'Microsoft Entra ID']);
}

$in = fopen($root . '/legacy/risques.csv', 'rb');
$header = fgetcsv($in, null, ';', '"', '');
$header[0] = preg_replace('/^\xEF\xBB\xBF/', '', $header[0]);

$out = [];
$report = [];
$seen = [];
while (($row = fgetcsv($in, null, ';', '"', '')) !== false) {
    if ($row === [null]) {
        continue;
    }
    $v4 = array_combine($header, $row);
    $code = $v4['ID'];
    if (isset($seen[$code])) {
        throw new RuntimeException("Duplicate code in v4: {$code}");
    }
    $seen[$code] = true;
    $fix = RISKS[$code] ?? throw new RuntimeException("No editorial decision for {$code}");

    if (isset($fix['merged_into'])) {
        $report[] = ['code' => $code, 'title' => $v4['Titre'], 'changes' => ["Fusionné dans {$fix['merged_into']} (doublon)"]];
        continue;
    }

    $changes = [];
    $category = $fix['cat'] ?? CATEGORY[$v4['Catégorie']] ?? throw new RuntimeException("Unknown category for {$code}");
    if (isset($fix['cat'])) {
        $changes[] = "Catégorie : {$v4['Catégorie']} → {$category}";
    }

    if (isset($fix['sectors'])) {
        $sectors = $fix['sectors'] === '' ? [] : explode('|', $fix['sectors']);
        $changes[] = "Secteurs : {$v4['Secteurs']} → " . ($sectors === [] ? 'transversal' : implode(', ', $sectors));
    } else {
        $sectors = [];
        foreach (array_map('trim', explode(',', $v4['Secteurs'])) as $label) {
            $sectors = array_merge($sectors, SECTORS[$label] ?? throw new RuntimeException("Unknown sector '{$label}' for {$code}"));
        }
        $sectors = array_values(array_unique($sectors));
    }

    $cia = $fix['cia'] ?? cia($v4['DIC']);
    if (isset($fix['cia'])) {
        $changes[] = "CIA : {$v4['DIC']} (DIC) → {$cia}";
    }

    $environment = $fix['env'] ?? ($category === 'OT' ? 'OT' : 'IT');

    $iso = $fix['iso'];
    $v4Iso = $v4['ISO27001'];
    $normalisedV4 = $v4Iso === 'N/A' ? '' : (str_starts_with($v4Iso, 'A.') ? $v4Iso : 'A.' . $v4Iso);
    if ($iso !== $normalisedV4) {
        $changes[] = "ISO 27001 : {$v4Iso} → " . ($iso === '' ? 'aucun contrôle pertinent' : str_replace('|', ', ', $iso));
    }

    $dora = $v4['DORA'] === 'N/A' ? '' : str_replace(' ', '', $v4['DORA']);
    $dora = $fix['dora'] ?? (DORA_FIX[$dora] ?? $dora);
    if ($dora !== str_replace(' ', '', $v4['DORA']) && $v4['DORA'] !== 'N/A') {
        $changes[] = "DORA : {$v4['DORA']} → {$dora}";
    }
    if (isset($fix['nis2'])) {
        $changes[] = "NIS2 : « {$v4['NIS2']} » → {$fix['nis2']} (en plus des correspondances ISO)";
    }
    if (isset($fix['cra'])) {
        $changes[] = 'CRA : ajout ' . str_replace('|', ', ', $fix['cra']);
    }

    $fields = [];
    foreach (['title' => 'Titre', 'threat' => 'Menace', 'scenario' => 'Scénario', 'measures' => 'Mesures'] as $key => $col) {
        $fields[$key] = clean($fix[$key] ?? $v4[$col]);
        if ($fields[$key] !== trim($v4[$col])) {
            $changes[] = ucfirst(['title' => 'titre', 'threat' => 'menace', 'scenario' => 'scénario', 'measures' => 'mesures'][$key])
                . ' : « ' . trim($v4[$col]) . ' » → « ' . $fields[$key] . ' »';
        }
    }

    $out[] = [
        $code, $fields['title'], $category, $fields['threat'], $fields['scenario'], $fields['measures'],
        $v4['Impact'], '', $cia, $environment, implode('|', $sectors), $iso, $fix['nis2'] ?? '', $dora, $fix['cra'] ?? '',
    ];
    $report[] = ['code' => $code, 'title' => $fields['title'], 'changes' => $changes];
}
fclose($in);

$unused = array_diff(array_keys(RISKS), array_keys($seen));
if ($unused !== []) {
    throw new RuntimeException('Editorial decisions for unknown codes: ' . implode(', ', $unused));
}

// db/catalogue/risks.csv --------------------------------------------------------
$fh = fopen($root . '/db/catalogue/risks.csv', 'wb');
fputcsv($fh, ['code', 'title', 'category', 'threat', 'scenario', 'measures', 'impact', 'likelihood', 'cia',
    'environment', 'sectors', 'iso27001', 'nis2', 'dora', 'cra'], ';', '"', '');
foreach ($out as $line) {
    fputcsv($fh, $line, ';', '"', '');
}
fclose($fh);

// docs/catalogue-v4-migration.md -----------------------------------------------
$changed = array_filter($report, static fn (array $r): bool => $r['changes'] !== []);
$md = "# Catalogue v4 → v5 : rapport de migration\n\n"
    . "Généré par `scripts/legacy/convert-v4-catalogue.php`. À relire et valider.\n\n"
    . sprintf("- Risques v4 : %d\n- Risques v5 : %d\n- Risques modifiés : %d\n\n", count($report), count($out), count($changed))
    . "## Règles appliquées à tout le catalogue\n\n"
    . "- **DIC → CIA** : Disponibilité devient Availability (A), les lettres C et I restent.\n"
    . "- **Secteurs** : Finance devient Banking + Insurance, Secteur Public devient Public administration + Local government, Industrie devient Manufacturing, Technologie devient Digital providers + ICT service management. \"Tous\", \"Développement\" et \"RH\" deviennent transversaux (aucun secteur).\n"
    . "- **NIS2** : le texte libre v4 (\"Hygiène informatique\", \"Gouvernance\"...) est abandonné. Les articles NIS2 sont dérivés des contrôles ISO par la table de correspondance, plus quelques ajouts explicites.\n"
    . "- **CyFun 2023 et NIST CSF 2.0** : dérivés des contrôles ISO par la table de correspondance.\n"
    . "- **Termes** : RGPD devient GDPR, Azure AD devient Microsoft Entra ID.\n\n"
    . "## Détail par risque\n\n";
foreach ($changed as $r) {
    $md .= "### {$r['code']} | {$r['title']}\n\n";
    foreach ($r['changes'] as $c) {
        $md .= "- {$c}\n";
    }
    $md .= "\n";
}
file_put_contents($root . '/docs/catalogue-v4-migration.md', $md);

printf("%d risks written, %d changed, report in docs/catalogue-v4-migration.md\n", count($out), count($changed));
