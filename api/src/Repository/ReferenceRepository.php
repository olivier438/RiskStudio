<?php

declare(strict_types=1);

namespace RiskStudio\Repository;

use PDO;

final class ReferenceRepository
{
    public function __construct(private readonly PDO $pdo)
    {
    }

    /** @return list<array<string, mixed>> */
    public function categories(): array
    {
        return $this->pdo
            ->query('SELECT code, name_fr, name_en FROM categories ORDER BY sort_order, code')
            ->fetchAll();
    }

    /** @return list<array<string, mixed>> */
    public function sectors(): array
    {
        return $this->pdo
            ->query('SELECT code, name_fr, name_en, nis2_annex FROM sectors ORDER BY sort_order, code')
            ->fetchAll();
    }

    /** @return list<array<string, mixed>> */
    public function frameworks(): array
    {
        $rows = $this->pdo->query(
            'SELECT f.code, f.name, f.short_name, f.version, f.publisher, f.url,
                    COUNT(c.id) AS controls_count
             FROM frameworks f
             LEFT JOIN framework_controls c ON c.framework_id = f.id
             GROUP BY f.id, f.code, f.name, f.short_name, f.version, f.publisher, f.url, f.sort_order
             ORDER BY f.sort_order, f.code'
        )->fetchAll();

        return array_map(static fn (array $r): array => ['controls_count' => (int) $r['controls_count']] + $r, $rows);
    }

    /** @return list<array<string, mixed>>|null  null when the framework does not exist */
    public function controls(string $frameworkCode): ?array
    {
        $exists = $this->pdo->prepare('SELECT id FROM frameworks WHERE code = ?');
        $exists->execute([$frameworkCode]);
        $frameworkId = $exists->fetchColumn();
        if ($frameworkId === false) {
            return null;
        }

        $stmt = $this->pdo->prepare(
            'SELECT c.ref, c.label, p.ref AS parent_ref, c.assurance_level, c.key_measure_level
             FROM framework_controls c
             LEFT JOIN framework_controls p ON p.id = c.parent_id
             WHERE c.framework_id = ?
             ORDER BY c.sort_order, c.ref'
        );
        $stmt->execute([$frameworkId]);

        return $stmt->fetchAll();
    }
}
