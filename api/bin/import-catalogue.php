<?php

/**
 * Imports db/catalogue (controls, crosswalk, risks) into the database.
 * Runs as the DB_WRITE_* user. Validates everything before writing.
 *
 *   php api/bin/import-catalogue.php [--dry-run]
 */

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

$appRoot = dirname(__DIR__);
require $appRoot . '/vendor/autoload.php';

use RiskStudio\Catalogue\CatalogueImporter;
use RiskStudio\Config;
use RiskStudio\Database;

$config = Config::fromFile($appRoot . '/.env');
$dbDir = getenv('RS_DB_DIR') ?: dirname($appRoot) . '/db';
$dryRun = in_array('--dry-run', $argv, true);

try {
    $importer = new CatalogueImporter((new Database($config))->connection(Database::WRITE), $dbDir . '/catalogue');
    $stats = $importer->import($dryRun);
} catch (\Throwable $e) {
    fwrite(STDERR, 'Catalogue import failed: ' . $e->getMessage() . PHP_EOL);
    exit(1);
}

foreach ($stats['warnings'] as $warning) {
    fwrite(STDOUT, "warning: {$warning}" . PHP_EOL);
}
unset($stats['warnings']);
fwrite(STDOUT, ($dryRun ? '[dry run, nothing written] ' : '') . json_encode($stats) . PHP_EOL);
