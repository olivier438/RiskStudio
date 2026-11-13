<?php

declare(strict_types=1);

namespace RiskStudio\Tests\Unit\Collector;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RiskStudio\Collector\Probe;

/** Admin diagnostic: format detection and address checks (no network). */
final class ProbeTest extends TestCase
{
    public function testFormatDetection(): void
    {
        self::assertSame('json', Probe::format("\xEF\xBB\xBF [1]"));
        self::assertSame('rss', Probe::format('<?xml version="1.0"?><rss version="2.0">'));
        self::assertSame('atom', Probe::format('<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom">'));
        self::assertSame('html', Probe::format('<!DOCTYPE html><html>'));
        self::assertSame('xml', Probe::format('<?xml version="1.0"?><root/>'));
        self::assertNull(Probe::format(''));
    }

    /** @return list<array{string}> */
    public static function forbidden(): array
    {
        return [
            ['http://example.org/feed'],
            ['https://127.0.0.1/'],
            ['https://10.0.0.8/admin'],
            ['https://192.168.1.1/'],
            ['https://169.254.169.254/latest/meta-data/'],
            ['https://[::1]/'],
            ['https://localhost/'],
            ['https://user:secret@example.org/'],
            ['https://example.org:8443/'],
            ['file:///etc/passwd'],
        ];
    }

    #[DataProvider('forbidden')]
    public function testPrivateOrUnusualAddressesAreRefused(string $url): void
    {
        $report = (new Probe())->url($url);

        self::assertSame('refused', $report['verdict'], $url);
        self::assertSame([], $report['requests'], 'nothing is requested');
    }

    public function testUnknownSourceHasNoParser(): void
    {
        self::assertSame('no_parser', (new Probe())->source('CCB', 'https://ccb.belgium.be/advisories')['verdict']);
    }
}
