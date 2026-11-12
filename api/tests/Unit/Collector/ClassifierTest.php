<?php

declare(strict_types=1);

namespace RiskStudio\Tests\Unit\Collector;

use PHPUnit\Framework\TestCase;
use RiskStudio\Collector\Classifier;
use RiskStudio\Collector\Facts;
use RiskStudio\Collector\LeakFacts;
use RiskStudio\Collector\Rules;

/** Classification on the real rule files of db/rules. */
final class ClassifierTest extends TestCase
{
    private static Classifier $classifier;
    private static Rules $rules;

    public static function setUpBeforeClass(): void
    {
        self::$rules = Rules::load(dirname(__DIR__, 4) . '/db/rules');
        self::$classifier = new Classifier(self::$rules);
    }

    public function testScoreFormula(): void
    {
        $c = self::$classifier->classify(new Facts(
            'CVE-2099-1', 'exploitation', 'Test', cves: ['CVE-2099-1'], cvss: 9.8, epssPercentile: 0.995,
            kev: true, ransomwareUse: true, sources: ['CISA_KEV'],
        ));

        // 9.8 x 6 = 58.8, + 25 exploited, + 15 EPSS, + 5 ransomware = 103.8, capped.
        self::assertSame(100, $c['score']);
        self::assertSame('critical', $c['severity']);
        self::assertSame(['base' => 58.8, 'exploited' => 25, 'epss' => 15, 'ransomware' => 5], $c['trace']['score']);
        self::assertContains('kev.listed', $c['trace']['rules']);
        self::assertContains('epss.top1pct', $c['trace']['rules']);
        self::assertSame(['R-OPS-01', 'R-IT-29'], array_column($c['risks'], 'code'));
    }

    public function testWithoutCvssKevMeansHigh(): void
    {
        $c = self::$classifier->classify(new Facts('CVE-2099-2', 'exploitation', 'Test', kev: true));

        self::assertSame('high', $c['severity']);
        self::assertSame(42 + 25, $c['score']);
        self::assertContains('kev.no_cvss->high', $c['trace']['rules']);
    }

    public function testCweGivesCategoryAndRiskLink(): void
    {
        $c = self::$classifier->classify(new Facts('CVE-2099-3', 'vulnerability', 'Test', cwes: ['CWE-798'], cvss: 6.5));

        self::assertSame(['IAM'], $c['categories']);
        self::assertSame('medium', $c['severity']);
        self::assertSame(['R-IAM-05'], array_column($c['risks'], 'code'));
        self::assertSame('cwe.CWE-798', $c['risks'][0]['rule']);
    }

    public function testVendorRulesUseWholeWords(): void
    {
        $abb = self::$classifier->classify(new Facts('X', 'vulnerability', 'T', vendor: 'ABB', product: 'Ability'));
        $abbott = self::$classifier->classify(new Facts('Y', 'vulnerability', 'T', vendor: 'Abbott', product: 'FreeStyle'));

        self::assertSame('BOTH', $abb['environment']);
        self::assertContains('OT', $abb['categories']);
        self::assertContains('ENERGY', $abb['sectors']);
        self::assertSame('IT', $abbott['environment']);
    }

    public function testScadaFlagForcesOtAndLinksOtRisks(): void
    {
        $c = self::$classifier->classify(new Facts(
            'CERTFR-2099-AVI-1', 'advisory', 'Vulnérabilité dans Exemple PLC', vendor: 'Exemple', product: 'Exemple PLC',
            otFlag: true, keywords: ['déni de service à distance'],
        ));

        self::assertSame('OT', $c['environment']);
        self::assertContains('INFRA', $c['categories']);
        self::assertContains('certfr.scada->OT', $c['trace']['rules']);
        self::assertSame(['R-OT-04', 'R-OT-10'], array_column($c['risks'], 'code'));
    }

    public function testSeverityHintCanOnlyRaise(): void
    {
        $alert = self::$classifier->classify(new Facts('A', 'exploitation', 'T', cvss: 5.0, severityHint: 'critical'));
        self::assertSame('critical', $alert['severity']);

        $low = self::$classifier->classify(new Facts('B', 'advisory', 'T', cvss: 9.1, severityHint: 'medium'));
        self::assertSame('critical', $low['severity']);
    }

    public function testClassificationIsDeterministic(): void
    {
        $facts = new Facts('CVE-2099-9', 'exploitation', 'Jenkins RCE', cwes: ['CWE-502'], cvss: 8.8, kev: true,
            vendor: 'Jenkins', product: 'Jenkins', epssPercentile: 0.93);

        self::assertSame(self::$classifier->classify($facts), self::$classifier->classify(clone $facts));
        self::assertContains('R-IT-24', array_column(self::$classifier->classify($facts)['risks'], 'code'));
        self::assertMatchesRegularExpression('/^[0-9a-f]{12}$/', self::$rules->version);
    }

    public function testLeakSectorFromRansomwareActivity(): void
    {
        $c = self::$classifier->classifyLeak(new LeakFacts('x', 'ransomware', 'Org', activity: 'Healthcare'), 'RANSOMWARE_LIVE');

        self::assertSame('HEALTH', $c['sector']);
        self::assertContains('activity.healthcare->HEALTH', $c['trace']['rules']);
    }
}
