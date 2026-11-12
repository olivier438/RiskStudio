<?php

/**
 * Applies pending migrations, then (with --seed) the idempotent seeds.
 * Runs as the DB_ADMIN_* user.
 *
 *   php api/bin/migrate.php [--seed]
 */

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

$appRoot = dirname(__DIR__);
require $appRoot . '/vendor/autoload.php';

use RiskStudio\Config;
use RiskStudio\Database;
use RiskStudio\Migrator;

$config = Config::fromFile($appRoot . '/.env');
$dbDir = getenv('RS_DB_DIR') ?: dirname($appRoot) . '/db';
$log = static fn (string $message) => fwrite(STDOUT, $message . PHP_EOL);

try {
    $migrator = new Migrator((new Database($config))->connection(Database::ADMIN), $dbDir . '/migrations');
    $applied = $migrator->migrate($log);
    $log($applied === [] ? 'Schema is up to date.' : sprintf('%d migration(s) applied.', count($applied)));

    if (in_array('--seed', $argv, true)) {
        $log(sprintf('%d seed file(s) applied.', $migrator->seed($dbDir . '/seeds', $log)));
    }
} catch (\Throwable $e) {
    fwrite(STDERR, 'Migration failed: ' . $e->getMessage() . PHP_EOL);
    exit(1);
}
