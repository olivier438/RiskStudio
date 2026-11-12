<?php

declare(strict_types=1);

namespace RiskStudio\Collector;

use PDO;
use RiskStudio\Config;

/** Builds a collector from the configuration: shared by the CLI and the web trigger. */
final class Factory
{
    public static function store(PDO $pdo, string $dbDir): Store
    {
        return new Store($pdo, new Classifier(Rules::load($dbDir . '/rules')));
    }

    public static function collector(Config $config, PDO $pdo, string $dbDir, int $timeBudget, ?callable $log = null): Collector
    {
        $countries = array_values(array_filter(array_map(
            'trim',
            explode(',', strtoupper((string) $config->get('COLLECTOR_LEAK_COUNTRIES', 'BE,FR,NL,LU,DE'))),
        )));
        $nvdKey = $config->get('NVD_API_KEY') ?: null;
        $http = new Http();
        $collector = null;
        $enricher = new Enricher(
            $http,
            new Http(8),
            $nvdKey,
            max(0, (int) $config->get('COLLECTOR_NVD_BUDGET', $nvdKey ? '40' : '5')),
            static function () use (&$collector): bool {
                return $collector === null || $collector->hasTime(8);
            },
        );

        return $collector = new Collector(
            $pdo,
            self::store($pdo, $dbDir),
            $http,
            $enricher,
            max(10, $timeBudget),
            max(1, (int) $config->get('COLLECTOR_BACKFILL_DAYS', '30')),
            $countries,
            $log,
        );
    }
}
