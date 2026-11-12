<?php

declare(strict_types=1);

namespace RiskStudio\Collector\Source;

use RiskStudio\Collector\Facts;
use RiskStudio\Collector\Http;

/**
 * CERT-FR feed (RSS) plus the JSON version of each new document, which lists
 * CVEs, affected products (with a SCADA flag) and risk categories.
 * Kept: alerts (exploitation), advisories, CTI reports. Skipped: news.
 */
final class CertFr implements Source
{
    public const CODE = 'CERT_FR';
    /** JSON details fetched per run, at most: keeps runs short on shared hosting. */
    public const DETAILS_PER_RUN = 15;

    private const KINDS = [
        'alerte' => ['type' => 'exploitation', 'severity' => 'critical', 'rule' => 'certfr.alerte'],
        'avis' => ['type' => 'advisory', 'severity' => null, 'rule' => 'certfr.avis'],
        'cti' => ['type' => 'campaign', 'severity' => null, 'rule' => 'certfr.cti'],
    ];

    public function fetch(Http $http, string $url, array $cursor, \DateTimeImmutable $since): array
    {
        $response = $http->get($url);
        if ($response['status'] !== 200) {
            throw new \RuntimeException("HTTP {$response['status']} on {$url}");
        }

        return $this->parse($response['body'], $cursor, $since, function (string $link) use ($http): ?array {
            try {
                return $http->json(rtrim($link, '/') . '/json/');
            } catch (\Throwable) {
                return null;
            }
        });
    }

    /**
     * @param array<string, mixed> $cursor
     * @param callable(string): ?array<mixed> $details
     * @return array{intel: list<Facts>, leaks: list<\RiskStudio\Collector\LeakFacts>, cursor: array<string, mixed>}
     */
    public function parse(string $xml, array $cursor, \DateTimeImmutable $since, callable $details): array
    {
        $previous = libxml_use_internal_errors(true);
        // LIBXML_NONET: never fetch anything referenced by the document (XXE).
        $feed = simplexml_load_string($xml, \SimpleXMLElement::class, LIBXML_NONET | LIBXML_NOCDATA);
        libxml_use_internal_errors($previous);
        if ($feed === false) {
            throw new \RuntimeException('Invalid CERT-FR RSS');
        }

        $from = (string) ($cursor['pub_date'] ?? $since->format('Y-m-d H:i:s'));
        $done = array_flip((array) ($cursor['done'] ?? []));
        $latest = $from;
        $items = [];
        $fetched = 0;
        $pending = false;

        foreach ($feed->channel->item ?? [] as $entry) {
            $link = trim((string) $entry->link);
            if (!preg_match('#/(alerte|avis|cti)/(CERTFR-\d{4}-[A-Z]{3}-\d+)/?$#', $link, $m)) {
                continue;
            }
            [$kind, $reference] = [$m[1], $m[2]];
            $published = Dates::utc((string) $entry->pubDate);
            if ($published === null || $published < $from || isset($done[$reference])) {
                continue;
            }
            if ($fetched >= self::DETAILS_PER_RUN) {
                $pending = true; // the next run picks up the rest
                continue;
            }
            $fetched++;
            $json = $details($link) ?? [];
            $latest = max($latest, $published);
            $done[$reference] = true;
            $items[] = $this->facts($kind, $reference, $link, $entry, $published, $json);
        }

        // While documents remain, keep the cursor where it was and remember
        // what was already imported; once caught up, move the cursor forward.
        $cursor = $pending
            ? ['pub_date' => $from, 'done' => array_keys($done)]
            : ['pub_date' => $latest, 'done' => []];

        return ['intel' => $items, 'leaks' => [], 'cursor' => $cursor];
    }

    /** @param array<mixed> $json */
    private function facts(string $kind, string $reference, string $link, \SimpleXMLElement $entry, string $published, array $json): Facts
    {
        $cves = [];
        foreach ((array) ($json['cves'] ?? []) as $c) {
            $name = is_array($c) ? (string) ($c['name'] ?? '') : '';
            if (preg_match('/^CVE-\d{4}-\d{4,}$/', $name)) {
                $cves[] = $name;
            }
        }
        $vendor = $product = null;
        $scada = false;
        foreach ((array) ($json['affected_systems'] ?? []) as $system) {
            $vendor ??= $system['product']['vendor']['name'] ?? null;
            $product ??= $system['product']['name'] ?? null;
            $scada = $scada || (bool) ($system['product']['vendor']['scada'] ?? false) || (bool) ($system['product']['scada'] ?? false);
        }
        $keywords = [];
        foreach ((array) ($json['risks'] ?? []) as $risk) {
            if (is_array($risk) && isset($risk['description'])) {
                $keywords[] = mb_strtolower((string) $risk['description']);
            }
        }
        $meta = self::KINDS[$kind];

        return new Facts(
            externalId: $reference,
            type: $meta['type'],
            title: trim((string) ($json['title'] ?? $entry->title)),
            summary: trim(strip_tags((string) ($json['summary'] ?? $entry->description))) ?: null,
            url: $link,
            publishedAt: $published,
            cves: array_values(array_unique($cves)),
            vendor: is_string($vendor) ? $vendor : null,
            product: is_string($product) ? $product : null,
            otFlag: $scada,
            severityHint: $meta['severity'],
            keywords: array_values(array_unique([...$keywords, $meta['rule']])),
            sources: [self::CODE],
        );
    }
}
