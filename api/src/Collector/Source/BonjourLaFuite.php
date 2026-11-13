<?php

declare(strict_types=1);

namespace RiskStudio\Collector\Source;

use RiskStudio\Collector\Http;
use RiskStudio\Collector\LeakFacts;

/**
 * Bonjour la fuite (bonjourlafuite.eu.org): data leaks affecting French
 * organisations, curated day by day. The RSS feed lists the latest entries:
 *
 *   title        status emoji + organisation ("🟢 Macif")
 *                🟢 confirmed, 🟠 claimed (credible), 🔴 claimed (unreliable)
 *   description  <ul><li>exposed data class</li>...</ul>
 *   category     "leak", plus "sensitive" for sensitive data
 *
 * The feed is short (about ten entries): every run reads all of it and the
 * store skips what it already has. The entry date is the leak date, which may
 * be older than its publication, so no date cursor is used.
 */
final class BonjourLaFuite implements Source
{
    public const CODE = 'BONJOUR_LA_FUITE';
    private const SITE = 'https://bonjourlafuite.eu.org/';
    private const STATUS = ['🟢' => 'confirmed', '🟠' => 'claimed', '🔴' => 'untrusted'];

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
     * @return array{intel: list<\RiskStudio\Collector\Facts>, leaks: list<LeakFacts>, cursor: array<string, mixed>}
     */
    public function parse(string $xml, array $cursor, \DateTimeImmutable $since): array
    {
        $previous = libxml_use_internal_errors(true);
        // LIBXML_NONET: never fetch anything referenced by the document (XXE).
        $feed = simplexml_load_string($xml, \SimpleXMLElement::class, LIBXML_NONET | LIBXML_NOCDATA);
        libxml_use_internal_errors($previous);
        if ($feed === false || !isset($feed->channel)) {
            throw new \RuntimeException('Invalid Bonjour la fuite RSS');
        }

        $from = $since->format('Y-m-d H:i:s');
        $latest = (string) ($cursor['latest'] ?? '');
        $leaks = [];
        foreach ($feed->channel->item as $item) {
            $date = Dates::utc((string) $item->pubDate);
            $guid = trim((string) $item->guid);
            [$confidence, $organisation] = self::title((string) $item->title);
            if ($date === null || $date < $from || $guid === '' || $organisation === '') {
                continue;
            }
            $latest = max($latest, $date);
            $categories = array_map(static fn ($c): string => strtolower(trim((string) $c)), iterator_to_array($item->category, false));
            $link = trim((string) $item->link);

            $leaks[] = new LeakFacts(
                externalId: mb_substr(preg_replace('/^bonjour-la-fuite:/', '', $guid), 0, 191),
                type: 'breach',
                organisation: mb_substr($organisation, 0, 255),
                country: 'FR',
                dataClasses: self::dataClasses((string) $item->description),
                disclosedAt: $date,
                url: str_starts_with($link, self::SITE) ? $link : self::SITE,
                confidence: $confidence,
                sensitive: in_array('sensitive', $categories, true),
            );
        }

        return ['intel' => [], 'leaks' => $leaks, 'cursor' => ['latest' => $latest]];
    }

    /** @return array{0: ?string, 1: string} confidence, organisation */
    private static function title(string $title): array
    {
        $title = self::trim($title);
        foreach (self::STATUS as $emoji => $confidence) {
            if (str_starts_with($title, $emoji)) {
                return [$confidence, self::trim(substr($title, strlen($emoji)))];
            }
        }

        return [null, $title];
    }

    /** trim() plus the no-break and zero-width spaces the feed puts after the emoji. */
    private static function trim(string $text): string
    {
        return (string) preg_replace('/^[\s\x{00A0}\x{200B}\x{FE0F}\x{FEFF}]+|[\s\x{00A0}\x{200B}\x{FEFF}]+$/u', '', $text);
    }

    /** "<ul><li>Nom, prénom</li>...</ul>" => ["Nom, prénom", ...] @return list<string> */
    private static function dataClasses(string $html): array
    {
        preg_match_all('#<li[^>]*>(.*?)</li>#is', $html, $m);
        $classes = [];
        foreach ($m[1] as $raw) {
            $text = trim((string) preg_replace('/\s+/u', ' ', html_entity_decode(strip_tags($raw), ENT_QUOTES | ENT_HTML5, 'UTF-8')));
            if ($text !== '') {
                $classes[] = mb_substr($text, 0, 200);
            }
        }

        return array_slice(array_values(array_unique($classes)), 0, 40);
    }
}
