<?php

/**
 * Risk Studio collector. Meant for a scheduled task every 15 minutes:
 *
 *   php api/bin/collect.php                 due sources only
 *   php api/bin/collect.php --source=CERT_FR [--force]
 *   php api/bin/collect.php --force         every enabled source now
 *   php api/bin/collect.php --reclassify    re-apply db/rules to every item
 *
 * Configuration (.env): COLLECTOR_TIME_BUDGET (seconds, default 50),
 * COLLECTOR_BACKFILL_DAYS (first run history, default 30),
 * COLLECTOR_LEAK_COUNTRIES (ransomware claims kept, default BE,FR,NL,LU,DE),
 * NVD_API_KEY (optional, raises the NVD rate limit), COLLECTOR_NVD_BUDGET.
 */

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

$appRoot = dirname(__DIR__);
require $appRoot . '/vendor/autoload.php';

use RiskStudio\Collector\Factory;
use RiskStudio\Collector\Rules;
use RiskStudio\Config;
use RiskStudio\Database;

$options = getopt('', ['source:', 'force', 'reclassify']);
$config = Config::fromFile($appRoot . '/.env');
// Release package: db/ sits inside the application root. Repository: next to api/.
$dbDir = getenv('RS_DB_DIR') ?: (is_dir($appRoot . '/db') ? $appRoot . '/db' : dirname($appRoot) . '/db');
$log = static fn (string $m) => fwrite(STDOUT, gmdate('Y-m-d H:i:s') . " {$m}" . PHP_EOL);

try {
    $pdo = (new Database($config))->connection(Database::WRITE);

    if (isset($options['reclassify'])) {
        $count = Factory::store($pdo, $dbDir)->reclassify();
        $log(sprintf('Reclassified %d item(s) with rules %s.', $count, Rules::load($dbDir . '/rules')->version));
        exit(0);
    }

    $budget = (int) $config->get('COLLECTOR_TIME_BUDGET', '50');
    $summary = Factory::collector($config, $pdo, $dbDir, $budget, $log)->run($options['source'] ?? null, isset($options['force']));
} catch (\Throwable $e) {
    fwrite(STDERR, 'Collector failed: ' . $e->getMessage() . PHP_EOL);
    exit(1);
}

$failed = array_filter($summary, static fn (array $s): bool => ($s['status'] ?? '') === 'failed');
exit($failed === [] ? 0 : 2);
