<?php

declare(strict_types=1);

namespace RiskStudio\Collector\Source;

use RiskStudio\Collector\Facts;
use RiskStudio\Collector\Http;

/** CISA Known Exploited Vulnerabilities catalogue (JSON). */
final class CisaKev implements Source
{
    public const CODE = 'CISA_KEV';

    public function fetch(Http $http, string $url, array $cursor, \DateTimeImmutable $since): array
    {
        return $this->parse($http->json($url), $cursor, $since);
    }

    /**
     * @param array<mixed> $data
     * @param array<string, mixed> $cursor
     * @return array{intel: list<Facts>, leaks: list<\RiskStudio\Collector\LeakFacts>, cursor: array<string, mixed>}
     */
    public function parse(array $data, array $cursor, \DateTimeImmutable $since): array
    {
        // dateAdded is a day: re-read the last day every time, upserts are idempotent.
        $from = (string) ($cursor['date_added'] ?? $since->format('Y-m-d'));
        $latest = $from;
        $items = [];

        foreach ($data['vulnerabilities'] ?? [] as $v) {
            $added = (string) ($v['dateAdded'] ?? '');
            $cve = (string) ($v['cveID'] ?? '');
            if ($added < $from || !preg_match('/^CVE-\d{4}-\d{4,}$/', $cve)) {
                continue;
            }
            $latest = max($latest, $added);
            $items[] = new Facts(
                externalId: $cve,
                type: 'exploitation',
                title: trim((string) ($v['vulnerabilityName'] ?? $cve)),
                summary: isset($v['shortDescription']) ? trim((string) $v['shortDescription']) : null,
                url: 'https://nvd.nist.gov/vuln/detail/' . $cve,
                publishedAt: Dates::utc($added),
                cves: [$cve],
                cwes: array_values(array_filter((array) ($v['cwes'] ?? []), static fn ($c) => is_string($c) && preg_match('/^CWE-\d+$/', $c))),
                kev: true,
                kevDueDate: Dates::date($v['dueDate'] ?? null),
                ransomwareUse: ($v['knownRansomwareCampaignUse'] ?? '') === 'Known',
                vendor: isset($v['vendorProject']) ? trim((string) $v['vendorProject']) : null,
                product: isset($v['product']) ? trim((string) $v['product']) : null,
                sources: [self::CODE],
            );
        }

        return ['intel' => $items, 'leaks' => [], 'cursor' => ['date_added' => $latest]];
    }
}
