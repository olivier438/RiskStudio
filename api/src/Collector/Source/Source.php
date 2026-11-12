<?php

declare(strict_types=1);

namespace RiskStudio\Collector\Source;

use RiskStudio\Collector\Facts;
use RiskStudio\Collector\Http;
use RiskStudio\Collector\LeakFacts;

/**
 * A source turns one remote feed into normalised facts. It never classifies
 * and never writes to the database: that is the collector's job.
 *
 * `$cursor` is the state saved after the previous successful run (for example
 * the latest date seen). `$since` is the oldest date worth importing on a
 * first run, so a new installation does not import years of history.
 */
interface Source
{
    /**
     * @param array<string, mixed> $cursor
     * @return array{intel: list<Facts>, leaks: list<LeakFacts>, cursor: array<string, mixed>}
     */
    public function fetch(Http $http, string $url, array $cursor, \DateTimeImmutable $since): array;
}
