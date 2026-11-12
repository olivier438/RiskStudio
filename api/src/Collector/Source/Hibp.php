<?php

declare(strict_types=1);

namespace RiskStudio\Collector\Source;

use RiskStudio\Collector\Http;
use RiskStudio\Collector\LeakFacts;

/**
 * Have I Been Pwned: list of breaches verified by Troy Hunt (public endpoint,
 * no key). Fabricated, spam-list, retired and sensitive breaches are skipped.
 */
final class Hibp implements Source
{
    public function fetch(Http $http, string $url, array $cursor, \DateTimeImmutable $since): array
    {
        return $this->parse($http->json($url), $cursor, $since);
    }

    /**
     * @param array<mixed> $data
     * @param array<string, mixed> $cursor
     * @return array{intel: list<\RiskStudio\Collector\Facts>, leaks: list<LeakFacts>, cursor: array<string, mixed>}
     */
    public function parse(array $data, array $cursor, \DateTimeImmutable $since): array
    {
        $from = (string) ($cursor['added'] ?? $since->format('Y-m-d H:i:s'));
        $latest = $from;
        $leaks = [];

        foreach ($data as $b) {
            $added = Dates::utc($b['AddedDate'] ?? null);
            $name = (string) ($b['Name'] ?? '');
            if ($added === null || $added < $from || !preg_match('/^[A-Za-z0-9_.-]{1,100}$/', $name)) {
                continue;
            }
            $latest = max($latest, $added);
            if (!($b['IsVerified'] ?? false) || ($b['IsFabricated'] ?? false) || ($b['IsSpamList'] ?? false)
                || ($b['IsRetired'] ?? false) || ($b['IsSensitive'] ?? false)) {
                continue;
            }
            $leaks[] = new LeakFacts(
                externalId: $name,
                type: 'breach',
                organisation: trim((string) ($b['Title'] ?? $name)),
                records: isset($b['PwnCount']) ? (int) $b['PwnCount'] : null,
                dataClasses: array_values(array_filter((array) ($b['DataClasses'] ?? []), 'is_string')),
                disclosedAt: $added,
                url: 'https://haveibeenpwned.com/PwnedWebsites#' . rawurlencode($name),
                domain: isset($b['Domain']) && $b['Domain'] !== '' ? (string) $b['Domain'] : null,
            );
        }

        return ['intel' => [], 'leaks' => $leaks, 'cursor' => ['added' => $latest]];
    }
}
