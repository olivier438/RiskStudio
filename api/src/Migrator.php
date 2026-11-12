<?php

declare(strict_types=1);

namespace RiskStudio;

use PDO;

/**
 * Plain SQL migrations, applied in file-name order and recorded with a
 * checksum. An applied migration that changed on disk is a hard error:
 * fix forward with a new migration instead.
 */
final class Migrator
{
    public function __construct(
        private readonly PDO $pdo,
        private readonly string $migrationsDir,
    ) {
    }

    /** @return list<string> versions applied during this run */
    public function migrate(?callable $log = null): array
    {
        $log ??= static fn (string $m) => null;
        $this->pdo->exec(
            'CREATE TABLE IF NOT EXISTS schema_migrations (
               version     VARCHAR(100) NOT NULL PRIMARY KEY,
               checksum    CHAR(64) NOT NULL,
               applied_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
             ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci'
        );

        $applied = $this->pdo->query('SELECT version, checksum FROM schema_migrations')->fetchAll(PDO::FETCH_KEY_PAIR);
        $done = [];

        foreach ($this->files() as $version => $path) {
            $sql = (string) file_get_contents($path);
            $checksum = hash('sha256', $sql);

            if (isset($applied[$version])) {
                if (!hash_equals($applied[$version], $checksum)) {
                    throw new \RuntimeException("Migration {$version} was modified after being applied.");
                }
                continue;
            }

            $log("Applying {$version}");
            // MariaDB commits DDL implicitly: statements run one by one and a
            // failure stops the run before the version is recorded.
            foreach (self::splitStatements($sql) as $statement) {
                $this->pdo->exec($statement);
            }
            $stmt = $this->pdo->prepare('INSERT INTO schema_migrations (version, checksum) VALUES (?, ?)');
            $stmt->execute([$version, $checksum]);
            $done[] = $version;
        }

        return $done;
    }

    /** Runs every seed file. Seeds must be idempotent. */
    public function seed(string $seedsDir, ?callable $log = null): int
    {
        $log ??= static fn (string $m) => null;
        $count = 0;
        foreach ($this->files($seedsDir) as $name => $path) {
            $log("Seeding {$name}");
            foreach (self::splitStatements((string) file_get_contents($path)) as $statement) {
                $this->pdo->exec($statement);
            }
            $count++;
        }

        return $count;
    }

    /** @return array<string, string> version => path, sorted */
    private function files(?string $dir = null): array
    {
        $files = [];
        foreach (glob(($dir ?? $this->migrationsDir) . '/*.sql') ?: [] as $path) {
            $files[basename($path, '.sql')] = $path;
        }
        ksort($files, SORT_STRING);

        return $files;
    }

    /**
     * Splits a SQL script on semicolons that end a line, skipping full-line
     * `--` comments. Enough for our migrations: no procedures, no triggers.
     *
     * @return list<string>
     */
    public static function splitStatements(string $sql): array
    {
        $lines = array_filter(
            preg_split('/\R/', $sql) ?: [],
            static fn (string $line): bool => !str_starts_with(ltrim($line), '--'),
        );
        $statements = preg_split('/;\s*$/m', implode("\n", $lines)) ?: [];

        return array_values(array_filter(array_map('trim', $statements), static fn (string $s): bool => $s !== ''));
    }
}
