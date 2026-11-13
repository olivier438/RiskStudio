<?php

declare(strict_types=1);

namespace RiskStudio\Tests\Unit\Collector;

use PHPUnit\Framework\TestCase;
use RiskStudio\Collector\Facts;
use RiskStudio\Collector\Source\GenericFeed;
use RiskStudio\Collector\SourceConfig;
use RiskStudio\Repository\ValidationException;

/** Sources added from the administration: generic RSS and Atom reader, settings. */
final class GenericFeedTest extends TestCase
{
    private static function fixture(string $name): string
    {
        return (string) file_get_contents(dirname(__DIR__, 2) . '/fixtures/collector/' . $name);
    }

    private static function since(): \DateTimeImmutable
    {
        return new \DateTimeImmutable('2099-01-01', new \DateTimeZone('UTC'));
    }

    public function testRssWithFiltersCountryAndCves(): void
    {
        $config = SourceConfig::fromInput(['family' => 'threat', 'country' => 'be', 'exclude' => 'webinaire, sponsorisé']);
        $feed = new GenericFeed('RSS_EXEMPLE', $config);
        $result = $feed->parse(self::fixture('generic_rss.xml'), [], self::since());

        self::assertSame(4, $feed->seen);
        self::assertSame(['Campagne de phishing contre des hôpitaux belges', 'Correctif pour CVE-2099-4242 dans Exemple Router'],
            array_map(fn (Facts $f) => $f->title, $result['intel']), 'excluded words and plain HTTP links are skipped');
        [$phishing, $patch] = $result['intel'];
        self::assertSame('incident', $phishing->type);
        self::assertSame(['BE'], $phishing->countries);
        self::assertSame('https://veille.example.org/?p=1', $phishing->externalId, 'guid first');
        self::assertSame('Des courriels piégés visent le personnel.', $phishing->summary);
        self::assertSame(['menaces'], $phishing->keywords);
        self::assertSame(['RSS_EXEMPLE'], $phishing->sources);
        self::assertSame('2099-01-11 08:00:00', $patch->publishedAt, 'dc:date when there is no pubDate');
        self::assertSame(['CVE-2099-4242'], $patch->cves);
        self::assertSame('https://veille.example.org/cve-2099-4242', $patch->externalId, 'the link without guid');
        self::assertSame('2099-01-12 10:00:00', $result['cursor']['pub_date']);
    }

    public function testIncludeWordsKeepOnlyMatchingEntries(): void
    {
        $feed = new GenericFeed('X', SourceConfig::fromInput(['family' => 'vulnerability', 'include' => ['CVE', 'correctif']]));
        $result = $feed->parse(self::fixture('generic_rss.xml'), [], self::since());

        self::assertCount(1, $result['intel']);
        self::assertSame('advisory', $result['intel'][0]->type);
    }

    public function testAtom(): void
    {
        $result = (new GenericFeed('X', SourceConfig::fromInput(['family' => 'threat'])))->parse(self::fixture('generic_atom.xml'), [], self::since());

        self::assertCount(1, $result['intel'], 'old entries are skipped');
        $f = $result['intel'][0];
        self::assertSame('Ransomware : une commune paralysée', $f->title, 'HTML in titles is flattened');
        self::assertSame('https://cert.example.org/ransomware-commune', $f->url, 'the alternate link');
        self::assertSame('urn:uuid:exemple-1', $f->externalId);
        self::assertSame('2099-01-12 08:00:00', $f->publishedAt);
        self::assertSame(['rançongiciel'], $f->keywords);
    }

    public function testNotAFeed(): void
    {
        $this->expectException(\RuntimeException::class);
        (new GenericFeed('X', SourceConfig::fromInput(['family' => 'threat'])))->parse('<html><body>Hello</body></html>', [], self::since());
    }

    public function testExternalEntitiesAreNeverRead(): void
    {
        $xml = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><rss><channel><item><title>&x; t</title>'
            . '<link>https://a.example.org/1</link><pubDate>Mon, 12 Jan 2099 00:00:00 +0000</pubDate></item></channel></rss>';
        $result = (new GenericFeed('X', SourceConfig::fromInput(['family' => 'threat'])))->parse($xml, [], self::since());

        self::assertStringNotContainsString('root:', json_encode(array_map(fn (Facts $f) => $f->toArray(), $result['intel'])));
    }

    public function testSettingsAreValidated(): void
    {
        try {
            SourceConfig::fromInput(['family' => 'leaks', 'country' => 'Belgique', 'include' => implode(',', array_map(fn ($i) => "mot{$i}", range(1, 40)))]);
            self::fail('invalid settings accepted');
        } catch (ValidationException $e) {
            self::assertSame(['family', 'country', 'include'], array_keys($e->fields));
        }
        $config = SourceConfig::fromArray(SourceConfig::fromInput(['family' => 'threat', 'include' => ' Rançongiciel ,, phishing '])->toArray());
        self::assertSame(['rançongiciel', 'phishing'], $config->include, 'stored lower case, trimmed, empty words dropped');
    }
}
