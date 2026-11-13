<?php

declare(strict_types=1);

namespace RiskStudio\Repository;

use PDO;

/**
 * Small summary used by the dashboard and by the 60-second polling.
 * It changes only when published content changes, so the ETag makes most
 * polls a 304.
 */
final class StatsRepository
{
    public const CRITICAL_WINDOW_DAYS = 7;

    public function __construct(private readonly PDO $pdo)
    {
    }

    /** @return array<string, mixed> */
    public function summary(): array
    {
        $risks = $this->pdo->query(
            'SELECT COUNT(*) AS total, MAX(updated_at) AS updated_at FROM v_public_risks'
        )->fetch();

        $intel = $this->pdo->prepare(
            'SELECT COUNT(*) AS total, MAX(id) AS latest_id, MAX(published_at) AS latest_published_at,
                    MAX(updated_at) AS updated_at,
                    SUM(CASE WHEN ' . IntelRepository::THREAT_SQL . ' THEN 1 ELSE 0 END) AS threats,
                    SUM(CASE WHEN ' . IntelRepository::CRITICAL_SQL . ' AND NOT ' . IntelRepository::THREAT_SQL . '
                             AND COALESCE(i.source_published_at, i.published_at) >= UTC_TIMESTAMP() - INTERVAL ? DAY
                        THEN 1 ELSE 0 END) AS critical_recent
             FROM v_public_intel i'
        );
        $intel->execute([self::CRITICAL_WINDOW_DAYS]);
        $intel = $intel->fetch();

        $leaks = $this->pdo->query(
            'SELECT COUNT(*) AS total, MAX(id) AS latest_id, MAX(updated_at) AS updated_at FROM v_public_leaks'
        )->fetch();

        $updated = array_filter([$risks['updated_at'], $intel['updated_at'], $leaks['updated_at']]);

        return [
            'risks' => ['total' => (int) $risks['total']],
            'intel' => [
                'total' => (int) $intel['total'],
                'vulnerabilities' => (int) $intel['total'] - (int) $intel['threats'],
                'threats' => (int) $intel['threats'],
                'critical_recent' => (int) $intel['critical_recent'],
                'critical_window_days' => self::CRITICAL_WINDOW_DAYS,
                'latest_id' => $intel['latest_id'] === null ? null : (int) $intel['latest_id'],
                'latest_published_at' => Dates::iso($intel['latest_published_at']),
            ],
            'leaks' => [
                'total' => (int) $leaks['total'],
                'latest_id' => $leaks['latest_id'] === null ? null : (int) $leaks['latest_id'],
            ],
            'last_update' => $updated === [] ? null : Dates::iso(max($updated)),
        ];
    }

    /** @return list<array{code: string, name: string}> sources that have published content */
    public function sources(): array
    {
        return $this->pdo->query(
            'SELECT source_code AS code, source_name AS name FROM v_public_intel
             UNION SELECT source_code, source_name FROM v_public_leaks
             ORDER BY name'
        )->fetchAll();
    }
}
