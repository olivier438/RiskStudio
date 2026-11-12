<?php

declare(strict_types=1);

namespace RiskStudio\Repository;

use PDO;

/** Read-only access to the published catalogue, through the public views. */
final class RiskRepository
{
    public function __construct(private readonly PDO $pdo)
    {
    }

    /** @return array{items: list<array<string, mixed>>, total: int} */
    public function search(RiskFilter $filter): array
    {
        [$where, $params] = $this->conditions($filter);

        $count = $this->pdo->prepare("SELECT COUNT(*) FROM v_public_risks r {$where}");
        $count->execute($params);
        $total = (int) $count->fetchColumn();

        $offset = ($filter->page - 1) * $filter->perPage;
        $stmt = $this->pdo->prepare(
            "SELECT r.*, c.code AS category_code, c.name_fr AS category_name_fr, c.name_en AS category_name_en
             FROM v_public_risks r
             JOIN categories c ON c.id = r.category_id
             {$where}
             ORDER BY r.impact DESC, r.code
             LIMIT {$filter->perPage} OFFSET {$offset}"
        );
        $stmt->execute($params);

        return ['items' => $this->hydrate($stmt->fetchAll()), 'total' => $total];
    }

    /** @return array<string, mixed>|null */
    public function findByCode(string $code): ?array
    {
        $stmt = $this->pdo->prepare(
            'SELECT r.*, c.code AS category_code, c.name_fr AS category_name_fr, c.name_en AS category_name_en
             FROM v_public_risks r
             JOIN categories c ON c.id = r.category_id
             WHERE r.code = ?'
        );
        $stmt->execute([$code]);
        $row = $stmt->fetch();

        return $row === false ? null : $this->hydrate([$row])[0];
    }

    /** @return array{0: string, 1: list<string|int>} */
    private function conditions(RiskFilter $filter): array
    {
        $sql = [];
        $params = [];

        if ($filter->search !== null) {
            $like = '%' . addcslashes($filter->search, '%_\\') . '%';
            $sql[] = '(r.title LIKE ? OR r.threat LIKE ? OR r.scenario LIKE ? OR r.measures LIKE ? OR r.code LIKE ?)';
            array_push($params, $like, $like, $like, $like, $like);
        }
        if ($filter->category !== null) {
            $sql[] = 'r.category_id = (SELECT id FROM categories WHERE code = ?)';
            $params[] = $filter->category;
        }
        if ($filter->environment !== null) {
            $sql[] = "r.environment IN (?, 'BOTH')";
            $params[] = $filter->environment;
        }
        if ($filter->impactMin !== null) {
            $sql[] = 'r.impact >= ?';
            $params[] = $filter->impactMin;
        }
        if ($filter->sector !== null) {
            // A risk without any sector row is cross-sector and always matches.
            $sql[] = '(EXISTS (SELECT 1 FROM v_public_risk_sectors rs JOIN sectors s ON s.id = rs.sector_id
                               WHERE rs.risk_id = r.id AND s.code = ?)
                       OR NOT EXISTS (SELECT 1 FROM v_public_risk_sectors rs2 WHERE rs2.risk_id = r.id))';
            $params[] = $filter->sector;
        }
        if ($filter->framework !== null) {
            $editorial = $filter->editorialOnly ? "AND rc.mapping_source = 'editorial'" : '';
            $sql[] = "EXISTS (SELECT 1 FROM v_public_risk_controls rc
                              JOIN framework_controls fc ON fc.id = rc.control_id
                              JOIN frameworks f ON f.id = fc.framework_id
                              WHERE rc.risk_id = r.id AND f.code = ? {$editorial})";
            $params[] = $filter->framework;
        }
        if ($filter->control !== null) {
            // Matches the control and its direct children (A.8 matches A.8.8,
            // ID.AM matches ID.AM-1). Refs are only unique within a framework.
            $sql[] = "EXISTS (SELECT 1 FROM v_public_risk_controls rc
                              JOIN framework_controls fc ON fc.id = rc.control_id
                              JOIN frameworks f ON f.id = fc.framework_id
                              LEFT JOIN framework_controls pc ON pc.id = fc.parent_id
                              WHERE rc.risk_id = r.id AND f.code = ? AND (fc.ref = ? OR pc.ref = ?))";
            array_push($params, $filter->framework, $filter->control, $filter->control);
        }

        return [$sql === [] ? '' : 'WHERE ' . implode(' AND ', $sql), $params];
    }

    /**
     * @param list<array<string, mixed>> $rows
     * @return list<array<string, mixed>>
     */
    private function hydrate(array $rows): array
    {
        if ($rows === []) {
            return [];
        }
        $ids = array_map(static fn (array $r): int => (int) $r['id'], $rows);
        $in = implode(',', array_fill(0, count($ids), '?'));

        $sectors = [];
        $stmt = $this->pdo->prepare(
            "SELECT rs.risk_id, s.code FROM v_public_risk_sectors rs JOIN sectors s ON s.id = rs.sector_id
             WHERE rs.risk_id IN ({$in}) ORDER BY s.sort_order"
        );
        $stmt->execute($ids);
        foreach ($stmt->fetchAll() as $s) {
            $sectors[(int) $s['risk_id']][] = $s['code'];
        }

        $controls = [];
        $stmt = $this->pdo->prepare(
            "SELECT rc.risk_id, f.code AS framework, fc.ref, rc.mapping_source
             FROM v_public_risk_controls rc
             JOIN framework_controls fc ON fc.id = rc.control_id
             JOIN frameworks f ON f.id = fc.framework_id
             WHERE rc.risk_id IN ({$in}) ORDER BY f.sort_order, rc.mapping_source, fc.sort_order"
        );
        $stmt->execute($ids);
        foreach ($stmt->fetchAll() as $c) {
            $controls[(int) $c['risk_id']][] = [
                'framework' => $c['framework'],
                'ref' => $c['ref'],
                'source' => $c['mapping_source'],
            ];
        }

        return array_map(static function (array $r) use ($sectors, $controls): array {
            $id = (int) $r['id'];

            return [
                'code' => $r['code'],
                'title' => $r['title'],
                'category' => [
                    'code' => $r['category_code'],
                    'name_fr' => $r['category_name_fr'],
                    'name_en' => $r['category_name_en'],
                ],
                'threat' => $r['threat'],
                'scenario' => $r['scenario'],
                'measures' => $r['measures'],
                'impact' => (int) $r['impact'],
                'likelihood' => $r['likelihood'] === null ? null : (int) $r['likelihood'],
                'cia' => [
                    'confidentiality' => (bool) $r['cia_confidentiality'],
                    'integrity' => (bool) $r['cia_integrity'],
                    'availability' => (bool) $r['cia_availability'],
                ],
                'environment' => $r['environment'],
                'origin' => $r['origin'],
                'sectors' => $sectors[$id] ?? [],
                'controls' => $controls[$id] ?? [],
                'updated_at' => Dates::iso($r['updated_at']),
                'published_at' => Dates::iso($r['published_at']),
            ];
        }, $rows);
    }
}
