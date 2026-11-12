<?php

declare(strict_types=1);

namespace RiskStudio\Collector\Source;

use RiskStudio\Collector\Facts;
use RiskStudio\Collector\Http;

/** ENISA European Vulnerability Database: exploited or critical lists (JSON). */
final class Euvd implements Source
{
    public function __construct(private readonly string $code, private readonly bool $exploited)
    {
    }

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
        $from = (string) ($cursor['updated'] ?? $since->format('Y-m-d H:i:s'));
        $latest = $from;
        $items = [];

        foreach (array_is_list($data) ? $data : ($data['items'] ?? []) as $v) {
            $id = (string) ($v['id'] ?? '');
            $updated = Dates::utc($v['dateUpdated'] ?? null) ?? Dates::utc($v['datePublished'] ?? null);
            if (!preg_match('/^EUVD-\d{4}-\d+$/', $id) || $updated === null || $updated < $from) {
                continue;
            }
            $latest = max($latest, $updated);
            $cves = array_values(array_filter(
                array_map('trim', preg_split('/\s+/', (string) ($v['aliases'] ?? '')) ?: []),
                static fn (string $a): bool => (bool) preg_match('/^CVE-\d{4}-\d{4,}$/', $a),
            ));
            $vendor = $v['enisaIdVendor'][0]['vendor']['name'] ?? null;
            $product = $v['enisaIdProduct'][0]['product']['name'] ?? null;
            $description = trim(preg_replace('/\s+/', ' ', html_entity_decode((string) ($v['description'] ?? ''))) ?? '');
            $score = isset($v['baseScore']) && is_numeric($v['baseScore']) && (float) $v['baseScore'] > 0 ? (float) $v['baseScore'] : null;

            $items[] = new Facts(
                externalId: $cves[0] ?? $id,
                type: $this->exploited ? 'exploitation' : 'vulnerability',
                title: self::title($vendor, $product, $cves[0] ?? $id, $description),
                summary: $description === '' ? null : mb_substr($description, 0, 1500),
                url: 'https://euvd.enisa.europa.eu/vulnerability/' . $id,
                publishedAt: Dates::utc($v['exploitedSince'] ?? null) ?? Dates::utc($v['datePublished'] ?? null),
                cves: $cves,
                cvss: $score,
                cvssVector: isset($v['baseScoreVector']) ? (string) $v['baseScoreVector'] : null,
                // EUVD's `epss` field has an undocumented scale: EPSS is taken
                // from FIRST, its publisher, by the enrichment step instead.
                kev: $this->exploited,
                vendor: is_string($vendor) ? $vendor : null,
                product: is_string($product) ? $product : null,
                sources: [$this->code],
            );
        }

        return ['intel' => $items, 'leaks' => [], 'cursor' => ['updated' => $latest]];
    }

    /** EUVD has no title: "Vendor Product: first sentence" keeps lists readable. */
    private static function title(mixed $vendor, mixed $product, string $id, string $description): string
    {
        $subject = trim((is_string($vendor) ? $vendor : '') . ' ' . (is_string($product) ? $product : ''));
        $sentence = preg_split('/(?<=\.)\s/', $description)[0] ?? '';
        $sentence = mb_strlen($sentence) > 140 ? mb_substr($sentence, 0, 137) . '...' : $sentence;

        return trim(($subject !== '' ? "{$subject} : " : "{$id} : ") . ($sentence !== '' ? $sentence : $id));
    }
}
