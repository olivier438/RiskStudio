<?php

declare(strict_types=1);

namespace RiskStudio\Collector\Source;

use RiskStudio\Collector\Facts;
use RiskStudio\Collector\Http;

/**
 * Centre for Cybersecurity Belgium, advisories feed (RSS). Every entry is a
 * "Warning: ..." of the national authority, of two kinds:
 *
 *   - a vulnerability to patch ("Critical authentication bypass in X, Patch
 *     Immediately!"): type advisory, shown with the vulnerabilities;
 *   - an incident or campaign ("Multiple Belgian organisations compromised
 *     through SMS sign-in"): type incident, shown with the threats.
 *
 * The feed carries titles only (no CVE, no summary): the kind is read from
 * the publisher's own wording, the severity from its call to action.
 */
final class Ccb implements Source
{
    public const CODE = 'CCB';

    /** Title words of a vulnerability advisory. Anything else is an incident. */
    private const ADVISORY_WORDS = '/\b(vulnerabilit(y|ies)|patch|zero-day|0-day|cve-\d{4}|security (update|release)|update now)\b/i';
    private const CRITICAL_WORDS = '/\b(critical|zero-day|0-day|actively exploited|immediate|immediately)\b/i';

    public function fetch(Http $http, string $url, array $cursor, \DateTimeImmutable $since): array
    {
        $response = $http->get($url);
        if ($response['status'] !== 200) {
            throw new \RuntimeException("HTTP {$response['status']} on {$url}");
        }

        return $this->parse($response['body'], $cursor, $since);
    }

    /**
     * @param array<string, mixed> $cursor
     * @return array{intel: list<Facts>, leaks: list<\RiskStudio\Collector\LeakFacts>, cursor: array<string, mixed>}
     */
    public function parse(string $xml, array $cursor, \DateTimeImmutable $since): array
    {
        $feed = Rss::load($xml, 'CCB');
        $from = (string) ($cursor['pub_date'] ?? $since->format('Y-m-d H:i:s'));
        $latest = $from;
        $items = [];
        foreach ($feed->channel->item as $entry) {
            $link = trim((string) $entry->link);
            $published = Dates::utc((string) $entry->pubDate);
            $title = Rss::text((string) $entry->title, 500);
            if ($published === null || $published < $from || $title === '' || !str_starts_with($link, 'https://ccb.belgium.be/')) {
                continue;
            }
            $latest = max($latest, $published);
            $advisory = preg_match(self::ADVISORY_WORDS, $title) === 1;
            $items[] = new Facts(
                externalId: mb_substr(basename(parse_url($link, PHP_URL_PATH) ?: $link), 0, 191),
                type: $advisory ? 'advisory' : 'incident',
                title: (string) preg_replace('/^warning:\s*/i', '', $title),
                url: $link,
                publishedAt: $published,
                cves: self::cves($title),
                severityHint: preg_match(self::CRITICAL_WORDS, $title) === 1 ? 'critical' : 'high',
                keywords: [$advisory ? 'ccb.advisory' : 'ccb.incident'],
                sources: [self::CODE],
                countries: $advisory ? [] : ['BE'],
            );
        }

        return ['intel' => $items, 'leaks' => [], 'cursor' => ['pub_date' => $latest]];
    }

    /** @return list<string> */
    private static function cves(string $text): array
    {
        preg_match_all('/\bCVE-\d{4}-\d{4,}\b/i', $text, $m);

        return array_values(array_unique(array_map('strtoupper', $m[0])));
    }
}
