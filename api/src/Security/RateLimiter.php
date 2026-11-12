<?php

declare(strict_types=1);

namespace RiskStudio\Security;

use PDO;

/**
 * Fixed-window counters in the `rate_limits` table. Buckets are HMACs of the
 * key (IP address, e-mail...) with the application secret: no personal data
 * is stored in clear, and buckets cannot be precomputed without the secret.
 */
final class RateLimiter
{
    public function __construct(private readonly PDO $pdo, private readonly string $secret)
    {
    }

    public function bucket(string $scope, string $key): string
    {
        return hash_hmac('sha256', $scope . '|' . mb_strtolower($key), $this->secret);
    }

    /** Counts one hit; returns false when the limit is exceeded. */
    public function hit(string $scope, string $key, int $limit, int $windowSeconds): bool
    {
        $bucket = $this->bucket($scope, $key);
        $this->pdo->prepare(
            'INSERT INTO rate_limits (bucket, window_start, hits) VALUES (?, UTC_TIMESTAMP(), 1)
             ON DUPLICATE KEY UPDATE
               hits = IF(window_start < UTC_TIMESTAMP() - INTERVAL ? SECOND, 1, hits + 1),
               window_start = IF(window_start < UTC_TIMESTAMP() - INTERVAL ? SECOND, UTC_TIMESTAMP(), window_start)'
        )->execute([$bucket, $windowSeconds, $windowSeconds]);

        return $this->count($scope, $key, $windowSeconds) <= $limit;
    }

    /** Current count without adding a hit. */
    public function count(string $scope, string $key, int $windowSeconds): int
    {
        $stmt = $this->pdo->prepare(
            'SELECT hits FROM rate_limits WHERE bucket = ? AND window_start >= UTC_TIMESTAMP() - INTERVAL ? SECOND'
        );
        $stmt->execute([$this->bucket($scope, $key), $windowSeconds]);

        return (int) $stmt->fetchColumn();
    }

    public function reset(string $scope, string $key): void
    {
        $this->pdo->prepare('DELETE FROM rate_limits WHERE bucket = ?')->execute([$this->bucket($scope, $key)]);
    }
}
