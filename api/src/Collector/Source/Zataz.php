<?php

declare(strict_types=1);

namespace RiskStudio\Collector\Source;

use RiskStudio\Collector\Facts;
use RiskStudio\Collector\Http;

/**
 * ZATAZ (French press, RSS): incidents, campaigns and claims seen on criminal
 * forums. Only entries filed under an attack category are kept (sanctions,
 * events and opinion pieces are skipped). Press items are never
 * authoritative: they wait for review. Only the title, a short summary and
 * the link are stored, as any feed reader does.
 */
final class Zataz implements Source
{
    public const CODE = 'ZATAZ';

    /** Category words (lower case, substring) of the entries kept. */
    private const ATTACK_CATEGORIES = ['piratage', 'warcyber', 'darknet', 'ransomware', 'rançongiciel', 'phishing',
        'hameçonnage', 'social engineering', 'ingénierie sociale', 'fuite', 'cyberattaque', 'arnaque', 'espionnage'];

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
        $feed = Rss::load($xml, 'ZATAZ');
        $from = (string) ($cursor['pub_date'] ?? $since->format('Y-m-d H:i:s'));
        $latest = $from;
        $items = [];
        foreach ($feed->channel->item as $entry) {
            $link = trim((string) $entry->link);
            $published = Dates::utc((string) $entry->pubDate);
            $title = Rss::text((string) $entry->title, 500);
            if ($published === null || $published < $from || $title === '' || !str_starts_with($link, 'https://www.zataz.com/')) {
                continue;
            }
            $latest = max($latest, $published);
            $categories = array_map(static fn ($c): string => mb_strtolower(Rss::text((string) $c, 80)), iterator_to_array($entry->category, false));
            if (!self::isAttack($categories)) {
                continue;
            }
            $items[] = new Facts(
                externalId: mb_substr(trim(parse_url($link, PHP_URL_PATH) ?: $link, '/'), 0, 191),
                type: 'incident',
                title: $title,
                summary: Rss::text((string) $entry->description, 400) ?: null,
                url: $link,
                publishedAt: $published,
                keywords: $categories,
                sources: [self::CODE],
            );
        }

        return ['intel' => $items, 'leaks' => [], 'cursor' => ['pub_date' => $latest]];
    }

    /** @param list<string> $categories */
    private static function isAttack(array $categories): bool
    {
        foreach ($categories as $category) {
            foreach (self::ATTACK_CATEGORIES as $word) {
                if (str_contains($category, $word)) {
                    return true;
                }
            }
        }

        return false;
    }
}
