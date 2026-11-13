<?php

declare(strict_types=1);

namespace RiskStudio\Repository;

use PDO;

/** Read-only access to the published data leaks feed. */
final class LeakRepository
{
    public function __construct(private readonly PDO $pdo)
    {
    }

    /** @return array{items: list<array<string, mixed>>, total: int} */
    public function search(FeedFilter $f): array
    {
        $sql = [];
        $params = [];
        if ($f->search !== null) {
            $like = '%' . addcslashes($f->search, '%_\\') . '%';
            $sql[] = '(l.organisation LIKE ? OR l.actor LIKE ?)';
            array_push($params, $like, $like);
        }
        if ($f->leakType !== null) {
            $sql[] = 'l.leak_type = ?';
            $params[] = $f->leakType;
        }
        if ($f->country !== null) {
            $sql[] = 'l.country = ?';
            $params[] = $f->country;
        }
        if ($f->sector !== null) {
            $sql[] = 'l.sector_id = (SELECT id FROM sectors WHERE code = ?)';
            $params[] = $f->sector;
        }
        if ($f->source !== null) {
            $sql[] = 'l.source_code = ?';
            $params[] = $f->source;
        }
        if ($f->since !== null) {
            $sql[] = 'l.published_at > ?';
            $params[] = $f->since;
        }
        $where = $sql === [] ? '' : 'WHERE ' . implode(' AND ', $sql);

        $count = $this->pdo->prepare("SELECT COUNT(*) FROM v_public_leaks l {$where}");
        $count->execute($params);

        $offset = ($f->page - 1) * $f->perPage;
        $stmt = $this->pdo->prepare(
            "SELECT l.*, s.code AS sector_code FROM v_public_leaks l
             LEFT JOIN sectors s ON s.id = l.sector_id
             {$where}
             ORDER BY COALESCE(l.disclosed_at, l.published_at) DESC, l.id DESC
             LIMIT {$f->perPage} OFFSET {$offset}"
        );
        $stmt->execute($params);

        $items = array_map(static function (array $l): array {
            $classes = $l['data_classes'] === null ? [] : json_decode((string) $l['data_classes'], true);
            $trace = $l['rule_trace'] === null ? null : json_decode((string) $l['rule_trace'], true);

            return [
                'id' => (int) $l['id'],
                'source' => ['code' => $l['source_code'], 'name' => $l['source_name']],
                'type' => $l['leak_type'],
                'organisation' => $l['organisation'],
                'country' => $l['country'],
                'sector' => $l['sector_code'],
                'actor' => $l['actor'],
                'records_count' => $l['records_count'] === null ? null : (int) $l['records_count'],
                'data_classes' => is_array($classes) ? array_values($classes) : [],
                'severity' => $l['severity'],
                'confidence' => $l['confidence'],
                'rule_trace' => is_array($trace) ? $trace : null,
                'url' => $l['url'],
                'disclosed_at' => Dates::iso($l['disclosed_at']),
                'published_at' => Dates::iso($l['published_at']),
                'updated_at' => Dates::iso($l['updated_at']),
            ];
        }, $stmt->fetchAll());

        return ['items' => $items, 'total' => (int) $count->fetchColumn()];
    }
}
