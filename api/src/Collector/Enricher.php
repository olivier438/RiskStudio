<?php

declare(strict_types=1);

namespace RiskStudio\Collector;

/**
 * Adds what the reporting source does not say:
 *   FIRST EPSS  exploitation probability (batches of 100 CVEs)
 *   NVD         CVSS, CWE and CPE vendor/product, one CVE per request
 *
 * NVD allows 5 requests per 30 s without key, 50 with NVD_API_KEY. Lookups
 * are capped per run; items left without CVSS are completed on later runs.
 */
class Enricher
{
    private const EPSS_URL = 'https://api.first.org/data/v1/epss?cve=';
    private const NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=';

    private int $nvdCalls = 0;
    private float $lastNvdCall = 0.0;
    /** Circuit breaker: after one NVD failure, no more NVD calls this run. */
    private bool $nvdDown = false;

    public function __construct(
        private readonly Http $http,
        /** Separate client with a short timeout: NVD is often slow. */
        private readonly Http $nvdHttp,
        private readonly ?string $nvdApiKey = null,
        private readonly int $nvdBudget = 5,
        /** Returns false once the run's time budget is spent. */
        private readonly ?\Closure $hasTime = null,
    ) {
    }

    /**
     * @param list<Facts> $items
     * @return list<string> problems worth logging (never fatal)
     */
    public function enrich(array $items): array
    {
        $problems = [];
        try {
            $this->epss($items);
        } catch (\Throwable $e) {
            $problems[] = 'EPSS: ' . $e->getMessage();
        }
        foreach ($items as $facts) {
            if ($facts->cvss !== null || $facts->cves === [] || !$this->nvdAvailable()) {
                continue;
            }
            try {
                $this->nvd($facts);
            } catch (\Throwable $e) {
                $this->nvdDown = true;
                $problems[] = "NVD {$facts->cves[0]}: " . $e->getMessage() . ' (NVD paused until next run)';
            }
        }

        return $problems;
    }

    public function nvdAvailable(): bool
    {
        $timeLeft = $this->hasTime === null || ($this->hasTime)();

        return !$this->nvdDown && $this->nvdCalls < $this->nvdBudget && $timeLeft;
    }

    /** @param list<Facts> $items */
    private function epss(array $items): void
    {
        $byCve = [];
        foreach ($items as $facts) {
            if ($facts->cves !== []) {
                $byCve[$facts->cves[0]][] = $facts;
            }
        }
        foreach (array_chunk(array_keys($byCve), 100) as $chunk) {
            $data = $this->http->json(self::EPSS_URL . implode(',', $chunk));
            foreach ($data['data'] ?? [] as $row) {
                foreach ($byCve[$row['cve'] ?? ''] ?? [] as $facts) {
                    $facts->epss = isset($row['epss']) ? round((float) $row['epss'], 5) : null;
                    $facts->epssPercentile = isset($row['percentile']) ? round((float) $row['percentile'], 5) : null;
                }
            }
        }
    }

    private function nvd(Facts $facts): void
    {
        // Rate limit: 6 s between calls without key, 0.6 s with a key.
        $gap = $this->nvdApiKey ? 0.6 : 6.0;
        $wait = $this->lastNvdCall + $gap - microtime(true);
        if ($wait > 0) {
            usleep((int) ($wait * 1_000_000));
        }
        $this->lastNvdCall = microtime(true);
        $this->nvdCalls++;

        $data = $this->nvdHttp->json(self::NVD_URL . rawurlencode($facts->cves[0]), $this->nvdApiKey ? ['apiKey' => $this->nvdApiKey] : []);
        $cve = $data['vulnerabilities'][0]['cve'] ?? null;
        if (!is_array($cve)) {
            return;
        }
        self::applyNvd($facts, $cve);
    }

    /** @param array<mixed> $cve one NVD 2.0 `cve` object */
    public static function applyNvd(Facts $facts, array $cve): void
    {
        // Prefer CVSS 4.0, then 3.1, then 3.0; the NVD "Primary" score first.
        foreach (['cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30'] as $key) {
            $metrics = $cve['metrics'][$key] ?? [];
            if ($metrics === []) {
                continue;
            }
            usort($metrics, static fn ($a, $b) => (($b['type'] ?? '') === 'Primary') <=> (($a['type'] ?? '') === 'Primary'));
            $data = $metrics[0]['cvssData'] ?? [];
            if (isset($data['baseScore'])) {
                $facts->cvss = (float) $data['baseScore'];
                $facts->cvssVector = isset($data['vectorString']) ? (string) $data['vectorString'] : null;
                break;
            }
        }
        foreach ($cve['weaknesses'] ?? [] as $weakness) {
            foreach ($weakness['description'] ?? [] as $d) {
                $value = (string) ($d['value'] ?? '');
                if (preg_match('/^CWE-\d+$/', $value) && !in_array($value, $facts->cwes, true)) {
                    $facts->cwes[] = $value;
                }
            }
        }
        if ($facts->vendor === null || $facts->product === null) {
            foreach ($cve['configurations'] ?? [] as $config) {
                foreach ($config['nodes'] ?? [] as $node) {
                    foreach ($node['cpeMatch'] ?? [] as $match) {
                        $parts = explode(':', (string) ($match['criteria'] ?? ''));
                        if (($match['vulnerable'] ?? false) && count($parts) > 4) {
                            $facts->vendor ??= str_replace('_', ' ', $parts[3]);
                            $facts->product ??= str_replace('_', ' ', $parts[4]);
                            break 3;
                        }
                    }
                }
            }
        }
        if ($facts->summary === null) {
            foreach ($cve['descriptions'] ?? [] as $d) {
                if (($d['lang'] ?? '') === 'en') {
                    $facts->summary = mb_substr(trim((string) $d['value']), 0, 1500);
                    break;
                }
            }
        }
    }
}
