<?php

declare(strict_types=1);

namespace RiskStudio;

use PDO;

/**
 * Lazy PDO connections, one per privilege level.
 *
 *   read   public API (rs_read): public views and reference data only
 *   write  back-office and collector (rs_write)
 *   admin  migrations only (rs_admin)
 */
final class Database
{
    public const READ = 'read';
    public const WRITE = 'write';
    public const ADMIN = 'admin';

    /** @var array<string, PDO> */
    private array $connections = [];

    public function __construct(private readonly Config $config)
    {
    }

    public function connection(string $role = self::READ): PDO
    {
        return $this->connections[$role] ??= $this->connect($role);
    }

    private function connect(string $role): PDO
    {
        $prefix = match ($role) {
            self::READ => 'DB_READ_',
            self::WRITE => 'DB_WRITE_',
            self::ADMIN => 'DB_ADMIN_',
            default => throw new \InvalidArgumentException("Unknown database role: {$role}"),
        };

        $dsn = sprintf(
            'mysql:host=%s;port=%s;dbname=%s;charset=utf8mb4',
            $this->config->require('DB_HOST'),
            $this->config->get('DB_PORT', '3306'),
            $this->config->require('DB_NAME'),
        );

        $pdo = new PDO($dsn, $this->config->require($prefix . 'USER'), $this->config->get($prefix . 'PASSWORD', ''), [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
            PDO::ATTR_STRINGIFY_FETCHES => false,
        ]);
        // All timestamps are stored and served in UTC.
        $pdo->exec("SET time_zone = '+00:00'");

        return $pdo;
    }
}
