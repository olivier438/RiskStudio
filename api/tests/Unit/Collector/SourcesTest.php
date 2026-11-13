<?php

declare(strict_types=1);

namespace RiskStudio\Tests\Unit\Collector;

use PHPUnit\Framework\TestCase;
use RiskStudio\Collector\Enricher;
use RiskStudio\Collector\Facts;
use RiskStudio\Collector\Source\BonjourLaFuite;
use RiskStudio\Collector\Source\CertFr;
use RiskStudio\Collector\Source\CisaKev;
use RiskStudio\Collector\Source\Euvd;
use RiskStudio\Collector\Source\Hibp;
use RiskStudio\Collector\Source\RansomwareLive;

/** Source parsers on frozen sample payloads: no network involved. */
final class SourcesTest extends TestCase
{
    private static function fixture(string $name): string
    {
        return (string) file_get_contents(dirname(__DIR__, 2) . '/fixtures/collector/' . $name);
    }

    /** @return array<mixed> */
    private static function json(string $name): array
    {
        return json_decode(self::fixture($name), true);
    }

    private static function since(): \DateTimeImmutable
    {
        return new \DateTimeImmutable('2099-01-01', new \DateTimeZone('UTC'));
    }

    public function testCisaKevKeepsRecentEntriesAndMovesTheCursor(): void
    {
        $result = (new CisaKev())->parse(self::json('kev.json'), [], self::since());

        self::assertSame(['CVE-2099-1001', 'CVE-2099-1002'], array_map(fn (Facts $f) => $f->externalId, $result['intel']));
        self::assertSame(['date_added' => '2099-01-10'], $result['cursor']);

        $vpn = $result['intel'][0];
        self::assertTrue($vpn->kev);
        self::assertTrue($vpn->ransomwareUse);
        self::assertSame('2099-01-31', $vpn->kevDueDate);
        self::assertSame(['CWE-288'], $vpn->cwes);
        self::assertSame(['CWE-798'], $result['intel'][1]->cwes, 'invalid CWE identifiers are dropped');

        // Next run from the cursor: only the last day is read again.
        $again = (new CisaKev())->parse(self::json('kev.json'), $result['cursor'], self::since());
        self::assertSame(['CVE-2099-1001'], array_map(fn (Facts $f) => $f->externalId, $again['intel']));
    }

    public function testEuvdUsesTheCveAsIdentifierAndBuildsATitle(): void
    {
        $result = (new Euvd('EUVD_EXPLOITED', true))->parse(self::json('euvd.json'), [], self::since());

        self::assertCount(1, $result['intel']);
        $f = $result['intel'][0];
        self::assertSame('CVE-2099-1001', $f->externalId);
        self::assertSame(['CVE-2099-1001'], $f->cves);
        self::assertSame(7.5, $f->cvss);
        self::assertNull($f->epss, 'EUVD epss scale is undocumented: FIRST is used instead');
        self::assertTrue($f->kev);
        self::assertSame('2099-01-09 00:00:00', $f->publishedAt);
        self::assertStringStartsWith('Exemple Networks : A vulnerability in the Exemple Portal', $f->title);
    }

    public function testCertFrReadsDetailsAndSkipsNews(): void
    {
        $requested = [];
        $result = (new CertFr())->parse(self::fixture('certfr.xml'), [], self::since(), function (string $link) use (&$requested) {
            $requested[] = $link;

            return str_contains($link, 'AVI-0001') ? self::json('certfr_avis.json') : null;
        });

        self::assertSame(['CERTFR-2099-AVI-0001', 'CERTFR-2099-ALE-0001'], array_map(fn (Facts $f) => $f->externalId, $result['intel']));
        self::assertCount(2, $requested, 'news and old items are not fetched');

        [$avis, $alerte] = $result['intel'];
        self::assertSame(['CVE-2099-2001'], $avis->cves);
        self::assertTrue($avis->otFlag, 'SCADA flag from the JSON details');
        self::assertSame('Exemple Automation', $avis->vendor);
        self::assertContains('exécution de code arbitraire à distance', $avis->keywords);
        self::assertSame('exploitation', $alerte->type);
        self::assertSame('critical', $alerte->severityHint);
        self::assertSame('2099-01-13 10:00:00', $result['cursor']['pub_date']);
    }

    public function testCertFrResumesWhenTheDetailBudgetIsSpent(): void
    {
        $items = '';
        for ($i = 1; $i <= CertFr::DETAILS_PER_RUN + 3; $i++) {
            $items .= sprintf('<item><title>Avis %1$d</title><link>https://www.cert.cyber.gouv.fr/avis/CERTFR-2099-AVI-%1$04d/</link><pubDate>Mon, 12 Jan 2099 10:%2$02d:00 +0000</pubDate></item>', $i, $i);
        }
        $xml = "<rss><channel>{$items}</channel></rss>";
        $none = static fn () => null;

        $first = (new CertFr())->parse($xml, [], self::since(), $none);
        self::assertCount(CertFr::DETAILS_PER_RUN, $first['intel']);
        self::assertCount(CertFr::DETAILS_PER_RUN, $first['cursor']['done']);

        $second = (new CertFr())->parse($xml, $first['cursor'], self::since(), $none);
        self::assertCount(3, $second['intel'], 'the rest is picked up by the next run');
        self::assertSame([], $second['cursor']['done']);
    }

    public function testCertFrRejectsExternalEntities(): void
    {
        $xml = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><rss><channel><item><title>&x;</title>'
            . '<link>https://www.cert.cyber.gouv.fr/avis/CERTFR-2099-AVI-0009/</link><pubDate>Mon, 12 Jan 2099 10:00:00 +0000</pubDate></item></channel></rss>';
        $result = (new CertFr())->parse($xml, [], self::since(), static fn () => null);

        self::assertStringNotContainsString('root:', $result['intel'][0]->title ?? '');
    }

    public function testHibpKeepsOnlyVerifiedNonSensitiveBreaches(): void
    {
        $result = (new Hibp())->parse(self::json('hibp.json'), [], self::since());

        self::assertCount(1, $result['leaks']);
        $leak = $result['leaks'][0];
        self::assertSame('Exemple Shop', $leak->organisation);
        self::assertSame(38000, $leak->records);
        self::assertSame(['Email addresses', 'Passwords'], $leak->dataClasses);
        self::assertSame('2099-01-12 05:00:00', $result['cursor']['added'], 'skipped breaches still move the cursor');
    }

    public function testRansomwareLiveFiltersCountriesAndNeverStoresOnionLinks(): void
    {
        $result = (new RansomwareLive(['BE', 'FR']))->parse(self::json('ransomware.json'), [], self::since());

        self::assertSame(['Clinique Exemple', 'Usine Exemple'], array_map(fn ($l) => $l->organisation, $result['leaks']));
        self::assertSame('https://www.ransomware.live/id/abc', $result['leaks'][0]->url);
        self::assertNull($result['leaks'][1]->url, '.onion and non ransomware.live links are dropped');
        foreach ($result['leaks'] as $leak) {
            self::assertStringNotContainsString('.onion', json_encode($leak->toArray()));
        }
        self::assertSame('ExempleLocker', $result['leaks'][0]->actor);
    }

    public function testBonjourLaFuiteReadsStatusDataClassesAndSensitiveFlag(): void
    {
        $result = (new BonjourLaFuite())->parse(self::fixture('bonjourlafuite.xml'), [], self::since());

        self::assertSame(['Exemple Mutuelle', 'Exemple Boutique', 'Exemple Club'], array_map(fn ($l) => $l->organisation, $result['leaks']), 'entries older than the window are skipped');
        [$mutuelle, $boutique, $club] = $result['leaks'];
        self::assertSame('Exemple Mutuelle-2099-01-12', $mutuelle->externalId);
        self::assertSame(['confirmed', 'claimed', 'untrusted'], [$mutuelle->confidence, $boutique->confidence, $club->confidence]);
        self::assertSame(['Nom, prénom', 'Adresse email', 'IBAN', 'Numéro de sécurité sociale'], $mutuelle->dataClasses);
        self::assertSame("Historique d'achats", $boutique->dataClasses[2], 'HTML entities are decoded');
        self::assertTrue($mutuelle->sensitive);
        self::assertFalse($boutique->sensitive);
        self::assertSame('FR', $mutuelle->country);
        self::assertSame('2099-01-12 00:00:00', $mutuelle->disclosedAt);
        self::assertSame('https://bonjourlafuite.eu.org/', $boutique->url, 'links outside the site are never stored');
        self::assertSame('2099-01-12 00:00:00', $result['cursor']['latest']);
    }

    public function testBonjourLaFuiteRejectsExternalEntities(): void
    {
        $xml = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><rss><channel><item><title>🟢 &x;</title>'
            . '<guid>a</guid><pubDate>Mon, 12 Jan 2099 00:00:00 +0000</pubDate></item></channel></rss>';
        $result = (new BonjourLaFuite())->parse($xml, [], self::since());

        self::assertStringNotContainsString('root:', json_encode(array_map(fn ($l) => $l->toArray(), $result['leaks'])));
    }

    public function testNvdPrefersThePrimaryScoreAndReadsCweAndCpe(): void
    {
        $facts = new Facts('CERTFR-2099-AVI-0001', 'advisory', 'Test', cves: ['CVE-2099-2001']);
        Enricher::applyNvd($facts, self::json('nvd_cve.json'));

        self::assertSame(9.8, $facts->cvss);
        self::assertSame(['CWE-327'], $facts->cwes);
        self::assertSame('exemple soft', $facts->vendor);
        self::assertSame('build runner', $facts->product);
        self::assertSame('A test vulnerability.', $facts->summary);
    }

    public function testFactsMergeIsMonotonic(): void
    {
        $a = new Facts('CVE-2099-1', 'vulnerability', 'A', cves: ['CVE-2099-1'], cvss: 7.5, sources: ['EUVD_CRITICAL']);
        $b = new Facts('CVE-2099-1', 'exploitation', 'B', cves: ['CVE-2099-1'], kev: true, kevDueDate: '2099-02-01', sources: ['CISA_KEV']);
        $a->merge($b);

        self::assertTrue($a->kev);
        self::assertSame(7.5, $a->cvss);
        self::assertSame(['EUVD_CRITICAL', 'CISA_KEV'], $a->sources);
        self::assertEquals($a, Facts::fromArray(json_decode(json_encode($a->toArray()), true)), 'JSON round trip');
    }
}
