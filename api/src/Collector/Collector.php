<?php

declare(strict_types=1);

namespace RiskStudio\Collector;

use PDO;
use RiskStudio\Collector\Source\CertFr;
use RiskStudio\Collector\Source\CisaKev;
use RiskStudio\Collector\Source\Euvd;
use RiskStudio\Collector\Source\Hibp;
use RiskStudio\Collector\Source\RansomwareLive;
use RiskStudio\Collector\Source\Source;

/**
 * One collector run, started by a scheduled task (every 15 minutes):
 *
 *   1. take a database lock (two runs never overlap)
 *   2. for each due source: fetch, enrich, classify, store, save the cursor
 *   3. spend the remaining time completing items still missing CVSS
 *
 * Each source is isolated: one failing feed never stops the others. The run
 * stops starting new work once its time budget is spent (shared hosting
 * limits the duration of scheduled tasks).
 */
final class Collector
{
    private const LOCK = 'riskstudio_collector';

    private float $deadline;
    /** @var callable(string): void */
    private $log;

    public function __construct(
        private readonly PDO $pdo,
        private readonly Store $store,
        private readonly Http $http,
        private readonly Enricher $enricher,
        private readonly int $timeBudget = 50,
        private readonly int $backfillDays = 30,
        /** @var list<string> */
        private readonly array $leakCountries = [],
        ?callable $log = null,
    ) {
        $this->log = $log ?? static fn (string $m) => null;
        $this->deadline = microtime(true) + $timeBudget;
    }

    public function hasTime(int $reserveSeconds = 5): bool
    {
        return microtime(true) + $reserveSeconds < $this->deadline;
    }

    /** @return array<string, array<string, mixed>> per-source summary */
    public function run(?string $only = null, bool $force = false): array
    {
        if ((int) $this->pdo->query("SELECT GET_LOCK('" . self::LOCK . "', 0)")->fetchColumn() !== 1) {
            ($this->log)('Another collector run is in progress, exiting.');

            return [];
        }
        try {
            $summary = [];
            foreach ($this->dueSources($only, $force) as $source) {
                if (!$this->hasTime(10)) {
                    ($this->log)("Time budget spent, {$source['code']} postponed.");
                    break;
                }
                $summary[$source['code']] = $this->runSource($source);
            }
            $summary['_enrichment'] = ['completed' => $this->completeEnrichment()];
            // The run journal is for monitoring, not history: 30 days are enough.
            $this->pdo->exec('DELETE FROM collector_runs WHERE started_at < UTC_TIMESTAMP() - INTERVAL 30 DAY');

            return $summary;
        } finally {
            $this->pdo->query("SELECT RELEASE_LOCK('" . self::LOCK . "')");
        }
    }

    public static function sourceFor(string $code, array $leakCountries = []): ?Source
    {
        return match ($code) {
            CisaKev::CODE => new CisaKev(),
            'EUVD_EXPLOITED' => new Euvd('EUVD_EXPLOITED', true),
            'EUVD_CRITICAL' => new Euvd('EUVD_CRITICAL', false),
            CertFr::CODE => new CertFr(),
            'HIBP' => new Hibp(),
            'RANSOMWARE_LIVE' => new RansomwareLive($leakCountries),
            default => null,
        };
    }

    /** @return list<array<string, mixed>> */
    private function dueSources(?string $only, bool $force): array
    {
        $sql = 'SELECT * FROM sources WHERE ' . ($only !== null ? 'code = ?' : 'enabled = 1');
        if (!$force && $only === null) {
            $sql .= ' AND (last_run_at IS NULL OR last_run_at <= UTC_TIMESTAMP() - INTERVAL poll_minutes MINUTE)';
        }
        $stmt = $this->pdo->prepare($sql . ' ORDER BY last_run_at IS NOT NULL, last_run_at');
        $stmt->execute($only !== null ? [$only] : []);

        return $stmt->fetchAll();
    }

    /** @param array<string, mixed> $source @return array<string, mixed> */
    private function runSource(array $source): array
    {
        $code = (string) $source['code'];
        $this->pdo->prepare('INSERT INTO collector_runs (source_id) VALUES (?)')->execute([$source['id']]);
        $runId = (int) $this->pdo->lastInsertId();
        $this->pdo->prepare('UPDATE sources SET last_run_at = UTC_TIMESTAMP() WHERE id = ?')->execute([$source['id']]);
        $counts = ['new' => 0, 'updated' => 0, 'unchanged' => 0];
        $problems = [];

        try {
            $impl = self::sourceFor($code, $this->leakCountries) ?? throw new \RuntimeException("No implementation for source {$code}");
            $cursor = json_decode((string) ($source['cursor_state'] ?? ''), true) ?: [];
            $since = new \DateTimeImmutable("-{$this->backfillDays} days", new \DateTimeZone('UTC'));
            $result = $impl->fetch($this->http, (string) $source['url'], $cursor, $since);

            $problems = $this->enricher->enrich($result['intel']);
            foreach ($result['intel'] as $facts) {
                $counts[$this->store->saveIntel($source, $facts)]++;
            }
            foreach ($result['leaks'] as $leak) {
                $counts[$this->store->saveLeak($source, $leak)]++;
            }

            $this->pdo->prepare('UPDATE sources SET cursor_state = ?, last_success_at = UTC_TIMESTAMP() WHERE id = ?')
                ->execute([json_encode($result['cursor']), $source['id']]);
            $status = $problems === [] ? 'success' : 'partial';
        } catch (\Throwable $e) {
            $status = 'failed';
            $problems[] = $e->getMessage();
        }

        $this->pdo->prepare(
            'UPDATE collector_runs SET finished_at = UTC_TIMESTAMP(), status = ?, items_new = ?, items_updated = ?, error = ? WHERE id = ?'
        )->execute([$status, $counts['new'], $counts['updated'], $problems === [] ? null : mb_substr(implode(' | ', $problems), 0, 2000), $runId]);

        ($this->log)(sprintf('%-16s %-8s new %d, updated %d, unchanged %d%s', $code, $status, $counts['new'], $counts['updated'],
            $counts['unchanged'], $problems === [] ? '' : ' | ' . mb_substr(implode(' | ', $problems), 0, 300)));

        return ['status' => $status] + $counts + ['problems' => $problems];
    }

    /** Uses the time left to fetch CVSS for items stored without it. */
    private function completeEnrichment(): int
    {
        $done = 0;
        foreach ($this->store->awaitingEnrichment(20) as $row) {
            if (!$this->enricher->nvdAvailable()) {
                break;
            }
            $this->enricher->enrich([$row['facts']]);
            if ($row['facts']->cvss !== null) {
                $this->store->updateFacts($row['id'], $row['facts']);
                $done++;
            }
        }
        if ($done > 0) {
            ($this->log)("Enrichment: CVSS completed for {$done} item(s).");
        }

        return $done;
    }
}
