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

use RiskStudio\Collector\Classifier;
use RiskStudio\Collector\Collector;
use RiskStudio\Collector\Enricher;
use RiskStudio\Collector\Http;
use RiskStudio\Collector\Rules;
use RiskStudio\Collector\Store;
use RiskStudio\Config;
use RiskStudio\Database;

$options = getopt('', ['source:', 'force', 'reclassify']);
$config = Config::fromFile($appRoot . '/.env');
$dbDir = getenv('RS_DB_DIR') ?: dirname($appRoot) . '/db';
$log = static fn (string $m) => fwrite(STDOUT, gmdate('Y-m-d H:i:s') . " {$m}" . PHP_EOL);

try {
    $pdo = (new Database($config))->connection(Database::WRITE);
    $rules = Rules::load($dbDir . '/rules');
    $store = new Store($pdo, new Classifier($rules));

    if (isset($options['reclassify'])) {
        $log(sprintf('Reclassified %d item(s) with rules %s.', $store->reclassify(), $rules->version));
        exit(0);
    }

    $budget = max(10, (int) $config->get('COLLECTOR_TIME_BUDGET', '50'));
    $countries = array_values(array_filter(array_map('trim', explode(',', strtoupper((string) $config->get('COLLECTOR_LEAK_COUNTRIES', 'BE,FR,NL,LU,DE'))))));
    $http = new Http();
    $collector = null;
    $enricher = new Enricher(
        $http,
        new Http(8),
        $config->get('NVD_API_KEY') ?: null,
        max(0, (int) $config->get('COLLECTOR_NVD_BUDGET', $config->get('NVD_API_KEY') ? '40' : '5')),
        static function () use (&$collector): bool {
            return $collector === null || $collector->hasTime(8);
        },
    );
    $collector = new Collector(
        $pdo, $store, $http, $enricher, $budget,
        max(1, (int) $config->get('COLLECTOR_BACKFILL_DAYS', '30')), $countries, $log,
    );
    $summary = $collector->run($options['source'] ?? null, isset($options['force']));
} catch (\Throwable $e) {
    fwrite(STDERR, 'Collector failed: ' . $e->getMessage() . PHP_EOL);
    exit(1);
}

$failed = array_filter($summary, static fn (array $s): bool => ($s['status'] ?? '') === 'failed');
exit($failed === [] ? 0 : 2);
