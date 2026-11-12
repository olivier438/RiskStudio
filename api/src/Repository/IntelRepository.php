<?php

declare(strict_types=1);

namespace RiskStudio\Repository;

use PDO;

/** Read-only access to the published threat intelligence feed. */
final class IntelRepository
{
    /** An item is "critical" when it is known to be exploited or rated critical. */
    public const CRITICAL_SQL = "(i.kev = 1 OR i.severity = 'critical')";

    public function __construct(private readonly PDO $pdo)
    {
    }

    /** @return array{items: list<array<string, mixed>>, total: int} */
    public function search(FeedFilter $filter): array
    {
        [$where, $params] = $this->conditions($filter);

        $count = $this->pdo->prepare("SELECT COUNT(*) FROM v_public_intel i {$where}");
        $count->execute($params);

        $offset = ($filter->page - 1) * $filter->perPage;
        $stmt = $this->pdo->prepare(
            "SELECT i.* FROM v_public_intel i {$where}
             ORDER BY COALESCE(i.source_published_at, i.published_at) DESC, i.id DESC
             LIMIT {$filter->perPage} OFFSET {$offset}"
        );
        $stmt->execute($params);

        return ['items' => $this->hydrate($stmt->fetchAll()), 'total' => (int) $count->fetchColumn()];
    }

    /** @return array<string, mixed>|null */
    public function find(int $id): ?array
    {
        $stmt = $this->pdo->prepare('SELECT i.* FROM v_public_intel i WHERE i.id = ?');
        $stmt->execute([$id]);
        $row = $stmt->fetch();

        return $row === false ? null : $this->hydrate([$row])[0];
    }

    /** @return array{0: string, 1: list<string|int>} */
    private function conditions(FeedFilter $f): array
    {
        $sql = [];
        $params = [];

        if ($f->search !== null) {
            $like = '%' . addcslashes($f->search, '%_\\') . '%';
            $sql[] = '(i.title LIKE ? OR i.summary LIKE ? OR i.external_id LIKE ?
                       OR EXISTS (SELECT 1 FROM v_public_intel_cves c WHERE c.item_id = i.id AND c.cve_id LIKE ?)
                       OR EXISTS (SELECT 1 FROM v_public_intel_products p WHERE p.item_id = i.id
                                  AND (p.vendor LIKE ? OR p.product LIKE ?)))';
            array_push($params, $like, $like, $like, $like, $like, $like);
        }
        if ($f->environment !== null) {
            $sql[] = "i.environment IN (?, 'BOTH')";
            $params[] = $f->environment;
        }
        if ($f->severityMin !== null) {
            $sql[] = 'i.severity IN (' . implode(',', array_fill(0, count($f->severities()), '?')) . ')';
            array_push($params, ...$f->severities());
        }
        if ($f->kevOnly) {
            $sql[] = 'i.kev = 1';
        }
        if ($f->source !== null) {
            $sql[] = 'i.source_code = ?';
            $params[] = $f->source;
        }
        if ($f->category !== null) {
            $sql[] = 'EXISTS (SELECT 1 FROM v_public_intel_categories c WHERE c.item_id = i.id AND c.category_code = ?)';
            $params[] = $f->category;
        }
        if ($f->sector !== null) {
            // Items without any sector apply to every sector.
            $sql[] = '(EXISTS (SELECT 1 FROM v_public_intel_sectors s WHERE s.item_id = i.id AND s.sector_code = ?)
                       OR NOT EXISTS (SELECT 1 FROM v_public_intel_sectors s2 WHERE s2.item_id = i.id))';
            $params[] = $f->sector;
        }
        if ($f->since !== null) {
            $sql[] = 'i.published_at > ?';
            $params[] = $f->since;
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

        $collect = function (string $sql) use ($ids): array {
            $stmt = $this->pdo->prepare($sql);
            $stmt->execute($ids);
            $out = [];
            foreach ($stmt->fetchAll() as $row) {
                $out[(int) $row['item_id']][] = $row;
            }

            return $out;
        };

        $cves = $collect("SELECT item_id, cve_id FROM v_public_intel_cves WHERE item_id IN ({$in}) ORDER BY cve_id");
        $products = $collect("SELECT item_id, vendor, product, environment FROM v_public_intel_products WHERE item_id IN ({$in})");
        $categories = $collect("SELECT item_id, category_code FROM v_public_intel_categories WHERE item_id IN ({$in})");
        $sectors = $collect("SELECT item_id, sector_code FROM v_public_intel_sectors WHERE item_id IN ({$in})");
        $risks = $collect("SELECT item_id, risk_code, risk_title, rule FROM v_public_intel_risks WHERE item_id IN ({$in}) ORDER BY risk_code");

        return array_map(static function (array $r) use ($cves, $products, $categories, $sectors, $risks): array {
            $id = (int) $r['id'];
            $trace = $r['rule_trace'] === null ? null : json_decode((string) $r['rule_trace'], true);

            return [
                'id' => $id,
                'source' => ['code' => $r['source_code'], 'name' => $r['source_name']],
                'external_id' => $r['external_id'],
                'type' => $r['item_type'],
                'title' => $r['title'],
                'summary' => $r['summary'],
                'url' => $r['url'],
                'cves' => array_column($cves[$id] ?? [], 'cve_id'),
                'cvss' => $r['cvss_score'] === null ? null : ['score' => (float) $r['cvss_score'], 'vector' => $r['cvss_vector']],
                'epss' => $r['epss_score'] === null ? null : [
                    'score' => (float) $r['epss_score'],
                    'percentile' => $r['epss_percentile'] === null ? null : (float) $r['epss_percentile'],
                ],
                'kev' => (bool) $r['kev'],
                'kev_due_date' => $r['kev_due_date'],
                'severity' => $r['severity'],
                'critical' => (bool) $r['kev'] || $r['severity'] === 'critical',
                'score' => $r['score'] === null ? null : (int) $r['score'],
                'environment' => $r['environment'],
                'products' => array_map(
                    static fn (array $p): array => ['vendor' => $p['vendor'], 'product' => $p['product'], 'environment' => $p['environment']],
                    $products[$id] ?? [],
                ),
                'categories' => array_column($categories[$id] ?? [], 'category_code'),
                'sectors' => array_column($sectors[$id] ?? [], 'sector_code'),
                'risks' => array_map(
                    static fn (array $k): array => ['code' => $k['risk_code'], 'title' => $k['risk_title'], 'rule' => $k['rule']],
                    $risks[$id] ?? [],
                ),
                'rule_trace' => is_array($trace) ? $trace : null,
                'source_published_at' => Dates::iso($r['source_published_at']),
                'published_at' => Dates::iso($r['published_at']),
                'updated_at' => Dates::iso($r['updated_at']),
            ];
        }, $rows);
    }
}
