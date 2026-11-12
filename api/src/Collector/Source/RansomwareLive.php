<?php

declare(strict_types=1);

namespace RiskStudio\Collector\Source;

use RiskStudio\Collector\Http;
use RiskStudio\Collector\LeakFacts;

/**
 * ransomware.live recent victims: claims published by ransomware groups.
 * Claims are not verified, so the source is not authoritative (items wait for
 * review). Only the countries in COLLECTOR_LEAK_COUNTRIES are kept, and links
 * to .onion leak sites are never stored: the ransomware.live page is used.
 */
final class RansomwareLive implements Source
{
    /** @param list<string> $countries empty = every country */
    public function __construct(private readonly array $countries = [])
    {
    }

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
        $from = (string) ($cursor['discovered'] ?? $since->format('Y-m-d H:i:s'));
        $latest = $from;
        $leaks = [];

        foreach ($data as $v) {
            $discovered = Dates::utc($v['discovered'] ?? null);
            $victim = trim((string) ($v['victim'] ?? ''));
            $group = trim((string) ($v['group'] ?? ''));
            if ($discovered === null || $discovered < $from || $victim === '' || $group === '') {
                continue;
            }
            $latest = max($latest, $discovered);
            $country = strtoupper((string) ($v['country'] ?? ''));
            if (!preg_match('/^[A-Z]{2}$/', $country)) {
                $country = null;
            }
            if ($this->countries !== [] && !in_array($country, $this->countries, true)) {
                continue;
            }
            $url = (string) ($v['url'] ?? '');
            $leaks[] = new LeakFacts(
                externalId: substr(hash('sha256', mb_strtolower($group . '|' . $victim)), 0, 40),
                type: 'ransomware',
                organisation: mb_substr($victim, 0, 255),
                country: $country,
                activity: isset($v['activity']) ? (string) $v['activity'] : null,
                actor: mb_substr($group, 0, 160),
                disclosedAt: Dates::utc($v['attackdate'] ?? null) ?? $discovered,
                url: str_starts_with($url, 'https://www.ransomware.live/') ? $url : null,
                domain: isset($v['domain']) && $v['domain'] !== '' ? (string) $v['domain'] : null,
            );
        }

        return ['intel' => [], 'leaks' => $leaks, 'cursor' => ['discovered' => $latest]];
    }
}
