<?php

declare(strict_types=1);

namespace RiskStudio\Catalogue;

use PDO;

/**
 * Loads the editable catalogue sources (db/catalogue) into the database:
 *
 *   controls/*.csv     framework controls (refs, labels, CyFun levels)
 *   crosswalk/*.csv    links between controls of different frameworks
 *   risks.csv          the GRC catalogue, with editorial mappings
 *
 * Everything is validated first; any error aborts the whole import. Writes
 * happen in one transaction. Mappings derived from the crosswalk are stored
 * with mapping_source = 'crosswalk', so editorial and derived links never mix.
 */
final class CatalogueImporter
{
    public const CIA = ['C', 'I', 'A'];
    public const ENVIRONMENTS = ['IT', 'OT', 'BOTH'];
    public const LEVELS = ['BASIC', 'IMPORTANT', 'ESSENTIAL'];
    private const MAPPING_COLUMNS = [
        'iso27001' => 'ISO27001_2022',
        'nis2' => 'NIS2',
        'dora' => 'DORA',
        'cra' => 'CRA',
    ];

    /** @var list<string> */
    private array $errors = [];
    /** @var list<string> */
    private array $warnings = [];

    public function __construct(
        private readonly PDO $pdo,
        private readonly string $dir,
    ) {
    }

    /** @return array<string, int|list<string>> statistics, plus warnings */
    public function import(bool $dryRun = false): array
    {
        $this->errors = [];
        $this->warnings = [];

        $controls = $this->readControls();
        $crosswalk = $this->readCsv($this->dir . '/crosswalk', ['from_framework', 'from_ref', 'to_framework', 'to_ref', 'basis']);
        $risks = $this->readCsv($this->dir . '/risks.csv', [
            'code', 'title', 'category', 'threat', 'scenario', 'measures', 'impact', 'likelihood', 'cia',
            'environment', 'sectors', 'iso27001', 'nis2', 'dora', 'cra',
        ]);

        $this->pdo->beginTransaction();
        try {
            $stats = ['controls' => $this->upsertControls($controls)];
            $index = $this->controlIndex();
            $stats['crosswalk'] = $this->replaceCrosswalk($crosswalk, $index);
            $stats += $this->upsertRisks($risks, $index);

            if ($this->errors !== []) {
                throw new ImportException($this->errors);
            }
            $this->audit($stats, $dryRun);
            $dryRun ? $this->pdo->rollBack() : $this->pdo->commit();
        } catch (\Throwable $e) {
            if ($this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }
            throw $e;
        }

        return $stats + ['warnings' => $this->warnings];
    }

    // -------------------------------------------------------------------------
    // Reading
    // -------------------------------------------------------------------------

    /** @return list<array<string, string>> */
    private function readControls(): array
    {
        return $this->readCsv($this->dir . '/controls', [
            'framework', 'ref', 'label', 'parent_ref', 'assurance_level', 'key_measure_level',
        ]);
    }

    /**
     * Reads one CSV file, or every *.csv file of a directory, with a strict
     * header check. Rows carry their origin for error messages.
     *
     * @param list<string> $expected
     * @return list<array<string, string>>
     */
    private function readCsv(string $path, array $expected): array
    {
        $files = is_dir($path) ? (glob($path . '/*.csv') ?: []) : [$path];
        sort($files);
        $rows = [];
        foreach ($files as $file) {
            $fh = fopen($file, 'rb');
            if ($fh === false) {
                throw new \RuntimeException("Cannot read {$file}");
            }
            $header = fgetcsv($fh, null, ';', '"', '');
            if ($header !== $expected) {
                throw new ImportException([basename($file) . ': unexpected header, expected ' . implode(';', $expected)]);
            }
            $line = 1;
            while (($row = fgetcsv($fh, null, ';', '"', '')) !== false) {
                $line++;
                if ($row === [null]) {
                    continue;
                }
                if (count($row) !== count($expected)) {
                    $this->errors[] = basename($file) . ":{$line}: expected " . count($expected) . ' columns, got ' . count($row);
                    continue;
                }
                $rows[] = array_map('trim', array_combine($expected, $row)) + ['_at' => basename($file) . ":{$line}"];
            }
            fclose($fh);
        }

        return $rows;
    }

    // -------------------------------------------------------------------------
    // Controls and crosswalk
    // -------------------------------------------------------------------------

    /** @param list<array<string, string>> $rows */
    private function upsertControls(array $rows): int
    {
        $frameworks = $this->pdo->query('SELECT code, id FROM frameworks')->fetchAll(PDO::FETCH_KEY_PAIR);
        $upsert = $this->pdo->prepare(
            'INSERT INTO framework_controls (framework_id, ref, label, assurance_level, key_measure_level, sort_order)
             VALUES (?, ?, ?, ?, ?, ?)
             ON DUPLICATE KEY UPDATE label = VALUES(label), assurance_level = VALUES(assurance_level),
                                     key_measure_level = VALUES(key_measure_level), sort_order = VALUES(sort_order)'
        );
        $parent = $this->pdo->prepare(
            'UPDATE framework_controls c JOIN framework_controls p ON p.framework_id = c.framework_id AND p.ref = ?
             SET c.parent_id = p.id WHERE c.framework_id = ? AND c.ref = ?'
        );

        $order = [];
        foreach ($rows as $r) {
            $fw = $frameworks[$r['framework']] ?? null;
            if ($fw === null) {
                $this->errors[] = "{$r['_at']}: unknown framework {$r['framework']}";
                continue;
            }
            foreach (['assurance_level', 'key_measure_level'] as $col) {
                if ($r[$col] !== '' && !in_array($r[$col], self::LEVELS, true)) {
                    $this->errors[] = "{$r['_at']}: invalid {$col} {$r[$col]}";
                }
            }
            $order[$fw] = ($order[$fw] ?? 1000) + 10;
            $upsert->execute([
                $fw, $r['ref'], $r['label'] === '' ? null : $r['label'],
                $r['assurance_level'] === '' ? null : $r['assurance_level'],
                $r['key_measure_level'] === '' ? null : $r['key_measure_level'],
                $order[$fw],
            ]);
        }
        foreach ($rows as $r) {
            if ($r['parent_ref'] !== '' && isset($frameworks[$r['framework']])) {
                $parent->execute([$r['parent_ref'], $frameworks[$r['framework']], $r['ref']]);
                if ($parent->rowCount() === 0 && !$this->controlExists($frameworks[$r['framework']], $r['parent_ref'])) {
                    $this->errors[] = "{$r['_at']}: unknown parent {$r['parent_ref']}";
                }
            }
        }

        return count($rows);
    }

    private function controlExists(int|string $frameworkId, string $ref): bool
    {
        $stmt = $this->pdo->prepare('SELECT 1 FROM framework_controls WHERE framework_id = ? AND ref = ?');
        $stmt->execute([$frameworkId, $ref]);

        return $stmt->fetchColumn() !== false;
    }

    /** @return array<string, int> "FRAMEWORK|ref" => control id */
    private function controlIndex(): array
    {
        $index = [];
        $rows = $this->pdo->query(
            'SELECT f.code, c.ref, c.id FROM framework_controls c JOIN frameworks f ON f.id = c.framework_id'
        )->fetchAll();
        foreach ($rows as $r) {
            $index[$r['code'] . '|' . $r['ref']] = (int) $r['id'];
        }

        return $index;
    }

    /**
     * @param list<array<string, string>> $rows
     * @param array<string, int> $index
     */
    private function replaceCrosswalk(array $rows, array $index): int
    {
        $this->pdo->exec('DELETE FROM control_crosswalk');
        $insert = $this->pdo->prepare(
            'INSERT IGNORE INTO control_crosswalk (from_control_id, to_control_id, basis) VALUES (?, ?, ?)'
        );
        $count = 0;
        foreach ($rows as $r) {
            $from = $index[$r['from_framework'] . '|' . $r['from_ref']] ?? null;
            $to = $index[$r['to_framework'] . '|' . $r['to_ref']] ?? null;
            if ($from === null || $to === null) {
                $this->errors[] = "{$r['_at']}: unknown control "
                    . ($from === null ? "{$r['from_framework']} {$r['from_ref']}" : "{$r['to_framework']} {$r['to_ref']}");
                continue;
            }
            $insert->execute([$from, $to, mb_substr($r['basis'], 0, 120)]);
            $count += $insert->rowCount();
        }

        return $count;
    }

    // -------------------------------------------------------------------------
    // Risks
    // -------------------------------------------------------------------------

    /**
     * @param list<array<string, string>> $rows
     * @param array<string, int> $index
     * @return array<string, int>
     */
    private function upsertRisks(array $rows, array $index): array
    {
        $categories = $this->pdo->query('SELECT code, id FROM categories')->fetchAll(PDO::FETCH_KEY_PAIR);
        $sectors = $this->pdo->query('SELECT code, id FROM sectors')->fetchAll(PDO::FETCH_KEY_PAIR);
        $crosswalk = [];
        foreach ($this->pdo->query('SELECT from_control_id, to_control_id FROM control_crosswalk')->fetchAll() as $c) {
            $crosswalk[(int) $c['from_control_id']][] = (int) $c['to_control_id'];
        }

        $upsert = $this->pdo->prepare(
            "INSERT INTO risks (code, title, category_id, threat, scenario, measures, impact, likelihood,
                                cia_confidentiality, cia_integrity, cia_availability, environment, origin, status, published_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'catalogue', 'published', UTC_TIMESTAMP())
             ON DUPLICATE KEY UPDATE title = VALUES(title), category_id = VALUES(category_id), threat = VALUES(threat),
                scenario = VALUES(scenario), measures = VALUES(measures), impact = VALUES(impact),
                likelihood = VALUES(likelihood), cia_confidentiality = VALUES(cia_confidentiality),
                cia_integrity = VALUES(cia_integrity), cia_availability = VALUES(cia_availability),
                environment = VALUES(environment), status = 'published',
                published_at = COALESCE(published_at, UTC_TIMESTAMP())"
        );
        $riskId = $this->pdo->prepare('SELECT id FROM risks WHERE code = ?');
        $clearSectors = $this->pdo->prepare('DELETE FROM risk_sectors WHERE risk_id = ?');
        $addSector = $this->pdo->prepare('INSERT INTO risk_sectors (risk_id, sector_id) VALUES (?, ?)');
        $clearControls = $this->pdo->prepare('DELETE FROM risk_controls WHERE risk_id = ?');
        $addControl = $this->pdo->prepare('INSERT INTO risk_controls (risk_id, control_id, mapping_source) VALUES (?, ?, ?)');

        $stats = ['risks' => 0, 'editorial_mappings' => 0, 'crosswalk_mappings' => 0, 'archived' => 0];
        $codes = [];

        foreach ($rows as $r) {
            $at = "{$r['_at']} {$r['code']}";
            if (!preg_match('/^R-[A-Z]{2,4}-\d{2}$/', $r['code'])) {
                $this->errors[] = "{$at}: invalid code";
                continue;
            }
            if (isset($codes[$r['code']])) {
                $this->errors[] = "{$at}: duplicate code";
                continue;
            }
            $codes[$r['code']] = true;

            $valid = $this->validateRisk($r, $at, $categories, $sectors);
            $controlIds = $this->resolveMappings($r, $at, $index);
            if (!$valid) {
                continue;
            }

            $cia = $r['cia'];
            $upsert->execute([
                $r['code'], $r['title'], $categories[$r['category']], $r['threat'], $r['scenario'], $r['measures'],
                (int) $r['impact'], $r['likelihood'] === '' ? null : (int) $r['likelihood'],
                (int) str_contains($cia, 'C'), (int) str_contains($cia, 'I'), (int) str_contains($cia, 'A'),
                $r['environment'],
            ]);
            $riskId->execute([$r['code']]);
            $id = (int) $riskId->fetchColumn();

            $clearSectors->execute([$id]);
            foreach ($this->split($r['sectors']) as $s) {
                $addSector->execute([$id, $sectors[$s]]);
            }

            $clearControls->execute([$id]);
            $editorial = array_fill_keys($controlIds, true);
            foreach (array_keys($editorial) as $controlId) {
                $addControl->execute([$id, $controlId, 'editorial']);
                $stats['editorial_mappings']++;
            }
            $derived = [];
            foreach (array_keys($editorial) as $controlId) {
                foreach ($crosswalk[$controlId] ?? [] as $to) {
                    if (!isset($editorial[$to])) {
                        $derived[$to] = true;
                    }
                }
            }
            foreach (array_keys($derived) as $controlId) {
                $addControl->execute([$id, $controlId, 'crosswalk']);
                $stats['crosswalk_mappings']++;
            }
            if ($editorial === []) {
                $this->warnings[] = "{$at}: no framework mapping";
            }
            $stats['risks']++;
        }

        // Catalogue risks removed from the source file are archived, never deleted.
        if ($codes !== []) {
            $in = implode(',', array_fill(0, count($codes), '?'));
            $archive = $this->pdo->prepare(
                "UPDATE risks SET status = 'archived'
                 WHERE origin = 'catalogue' AND status <> 'archived' AND code NOT IN ({$in})"
            );
            $archive->execute(array_keys($codes));
            $stats['archived'] = $archive->rowCount();
        }

        return $stats;
    }

    /**
     * @param array<string, string> $r
     * @param array<string, int|string> $categories
     * @param array<string, int|string> $sectors
     */
    private function validateRisk(array $r, string $at, array $categories, array $sectors): bool
    {
        $before = count($this->errors);
        foreach (['title' => 255, 'threat' => 255, 'scenario' => 5000, 'measures' => 5000] as $field => $max) {
            if ($r[$field] === '') {
                $this->errors[] = "{$at}: {$field} is empty";
            } elseif (mb_strlen($r[$field]) > $max) {
                $this->errors[] = "{$at}: {$field} longer than {$max} characters";
            }
            if (preg_match('/[\x{2013}\x{2014}]/u', $r[$field])) {
                $this->errors[] = "{$at}: {$field} contains an en or em dash";
            }
        }
        if (!isset($categories[$r['category']])) {
            $this->errors[] = "{$at}: unknown category {$r['category']}";
        }
        foreach ($this->split($r['sectors']) as $s) {
            if (!isset($sectors[$s])) {
                $this->errors[] = "{$at}: unknown sector {$s}";
            }
        }
        if (!preg_match('/^[1-5]$/', $r['impact'])) {
            $this->errors[] = "{$at}: impact must be 1 to 5";
        }
        if ($r['likelihood'] !== '' && !preg_match('/^[1-5]$/', $r['likelihood'])) {
            $this->errors[] = "{$at}: likelihood must be empty or 1 to 5";
        }
        if (!preg_match('/^C?I?A?$/', $r['cia']) || $r['cia'] === '') {
            $this->errors[] = "{$at}: cia must be a non-empty combination of C, I, A in that order";
        }
        if (!in_array($r['environment'], self::ENVIRONMENTS, true)) {
            $this->errors[] = "{$at}: environment must be IT, OT or BOTH";
        }

        return count($this->errors) === $before;
    }

    /**
     * @param array<string, string> $r
     * @param array<string, int> $index
     * @return list<int>
     */
    private function resolveMappings(array $r, string $at, array $index): array
    {
        $ids = [];
        foreach (self::MAPPING_COLUMNS as $column => $framework) {
            foreach ($this->split($r[$column]) as $ref) {
                $id = $index[$framework . '|' . $ref] ?? null;
                if ($id === null) {
                    $this->errors[] = "{$at}: unknown {$framework} reference {$ref}";
                    continue;
                }
                $ids[] = $id;
            }
        }

        return $ids;
    }

    /** @return list<string> */
    private function split(string $value): array
    {
        return $value === '' ? [] : array_values(array_filter(array_map('trim', explode('|', $value)), 'strlen'));
    }

    /** @param array<string, int> $stats */
    private function audit(array $stats, bool $dryRun): void
    {
        if ($dryRun) {
            return;
        }
        $stmt = $this->pdo->prepare(
            "INSERT INTO audit_log (actor_type, action, entity, details) VALUES ('system', 'catalogue.import', 'risks', ?)"
        );
        $stmt->execute([json_encode($stats, JSON_THROW_ON_ERROR)]);
    }
}
