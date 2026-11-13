<?php

declare(strict_types=1);

namespace RiskStudio\Collector\Source;

/** Shared RSS helpers: safe loading (no network, no external entities) and text clean-up. */
final class Rss
{
    public static function load(string $xml, string $name): \SimpleXMLElement
    {
        $previous = libxml_use_internal_errors(true);
        // LIBXML_NONET: never fetch anything referenced by the document (XXE).
        $feed = simplexml_load_string($xml, \SimpleXMLElement::class, LIBXML_NONET | LIBXML_NOCDATA);
        libxml_use_internal_errors($previous);
        if ($feed === false || !isset($feed->channel)) {
            throw new \RuntimeException("Invalid {$name} RSS");
        }

        return $feed;
    }

    /** HTML to plain text: tags removed, entities decoded (twice: "&amp;nbsp;"), spaces collapsed, cut. */
    public static function text(string $html, int $max): string
    {
        $text = strip_tags($html);
        for ($i = 0; $i < 2; $i++) {
            $text = html_entity_decode($text, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        }
        $text = trim((string) preg_replace('/[\s\x{00A0}]+/u', ' ', $text));

        return mb_strlen($text) > $max ? rtrim(mb_substr($text, 0, $max - 1)) . '…' : $text;
    }
}
