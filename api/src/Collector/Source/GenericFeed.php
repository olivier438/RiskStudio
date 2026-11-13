<?php

declare(strict_types=1);

namespace RiskStudio\Collector\Source;

use RiskStudio\Collector\Facts;
use RiskStudio\Collector\Http;
use RiskStudio\Collector\SourceConfig;

/**
 * Any RSS 2.0 or Atom feed, configured from the administration (no code).
 * Each kept entry becomes an advisory (Vulnérabilités view) or an incident
 * (Menaces view); the rules of db/rules classify it like any other item.
 * Only the title, a short summary, the link, the categories and the CVE
 * numbers found in the text are kept.
 */
final class GenericFeed implements Source
{
    private const ATOM = 'http://www.w3.org/2005/Atom';
    private const DC = 'http://purl.org/dc/elements/1.1/';

    /** Entries found in the last parsed feed, before filters (shown by the preview). */
    public int $seen = 0;

    public function __construct(private readonly string $code, private readonly SourceConfig $config)
    {
    }

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
        $previous = libxml_use_internal_errors(true);
        // LIBXML_NONET: never fetch anything referenced by the document (XXE).
        $doc = simplexml_load_string($xml, \SimpleXMLElement::class, LIBXML_NONET | LIBXML_NOCDATA);
        libxml_use_internal_errors($previous);
        if ($doc === false) {
            throw new \RuntimeException('Not an RSS or Atom feed');
        }

        $entries = match (true) {
            isset($doc->channel) => self::rssEntries($doc),
            $doc->getName() === 'feed' => self::atomEntries($doc),
            default => throw new \RuntimeException('Not an RSS or Atom feed'),
        };

        $from = (string) ($cursor['pub_date'] ?? $since->format('Y-m-d H:i:s'));
        $latest = $from;
        $items = [];
        $this->seen = count($entries);
        foreach ($entries as $e) {
            if ($e['title'] === '' || !str_starts_with($e['link'], 'https://')) {
                continue;
            }
            if ($e['date'] !== null) {
                if ($e['date'] < $from) {
                    continue;
                }
                $latest = max($latest, $e['date']);
            }
            if (!$this->config->keeps($e['title'] . ' ' . $e['summary'] . ' ' . implode(' ', $e['categories']))) {
                continue;
            }
            preg_match_all('/\bCVE-\d{4}-\d{4,}\b/i', $e['title'] . ' ' . $e['summary'], $m);
            $items[] = new Facts(
                externalId: mb_substr($e['id'] !== '' ? $e['id'] : $e['link'], 0, 191),
                type: $this->config->itemType(),
                title: $e['title'],
                summary: $e['summary'] === '' ? null : $e['summary'],
                url: mb_substr($e['link'], 0, 2048),
                publishedAt: $e['date'],
                cves: array_values(array_unique(array_map('strtoupper', $m[0]))),
                keywords: $e['categories'],
                sources: [$this->code],
                countries: $this->config->country === null ? [] : [$this->config->country],
            );
        }

        return ['intel' => $items, 'leaks' => [], 'cursor' => ['pub_date' => $latest]];
    }

    /** @return list<array{id: string, title: string, link: string, date: ?string, summary: string, categories: list<string>}> */
    private static function rssEntries(\SimpleXMLElement $doc): array
    {
        $out = [];
        foreach ($doc->channel->item as $item) {
            $dc = $item->children(self::DC);
            $out[] = self::entry(
                (string) $item->guid,
                (string) $item->title,
                trim((string) $item->link),
                (string) ($item->pubDate ?: $dc->date),
                (string) $item->description,
                array_map('strval', iterator_to_array($item->category, false)),
            );
        }

        return $out;
    }

    /** @return list<array{id: string, title: string, link: string, date: ?string, summary: string, categories: list<string>}> */
    private static function atomEntries(\SimpleXMLElement $doc): array
    {
        $out = [];
        foreach ($doc->children(self::ATOM)->entry as $entry) {
            $link = '';
            foreach ($entry->link as $l) {
                $rel = (string) ($l->attributes()['rel'] ?? 'alternate');
                if ($rel === 'alternate' || $link === '') {
                    $link = trim((string) $l->attributes()['href']);
                }
            }
            $categories = [];
            foreach ($entry->category as $c) {
                $categories[] = (string) ($c->attributes()['label'] ?? $c->attributes()['term'] ?? '');
            }
            $out[] = self::entry(
                (string) $entry->id,
                (string) $entry->title,
                $link,
                (string) ($entry->published ?: $entry->updated),
                (string) ($entry->summary ?: $entry->content),
                $categories,
            );
        }

        return $out;
    }

    /**
     * @param list<string> $categories
     * @return array{id: string, title: string, link: string, date: ?string, summary: string, categories: list<string>}
     */
    private static function entry(string $id, string $title, string $link, string $date, string $summary, array $categories): array
    {
        return [
            'id' => trim($id),
            'title' => Rss::text($title, 500),
            'link' => $link,
            'date' => Dates::utc($date),
            'summary' => Rss::text($summary, 400),
            'categories' => array_values(array_filter(array_map(static fn (string $c): string => mb_strtolower(Rss::text($c, 80)), $categories))),
        ];
    }
}
