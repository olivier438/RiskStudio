<?php

declare(strict_types=1);

namespace RiskStudio\Tests\Integration;

use PHPUnit\Framework\TestCase;
use RiskStudio\Config;
use RiskStudio\Database;
use RiskStudio\Http\Request;
use RiskStudio\Http\Response;
use RiskStudio\Kernel;

/** Access rules of the collector web trigger (no network: the run itself is not started). */
final class CronTest extends TestCase
{
    private const KEY = 'phpunit-cron-key-0123456789abcdefgh';

    protected function tearDown(): void
    {
        putenv('CRON_KEY');
    }

    private function call(array $headers = [], array $query = []): Response
    {
        $config = Config::fromFile(dirname(__DIR__, 2) . '/.env');

        return (new Kernel($config, new Database($config)))->handle(new Request('GET', '/v1/cron/collect', $query, $headers));
    }

    public function testDisabledWithoutKey(): void
    {
        putenv('CRON_KEY');
        self::assertSame(404, $this->call(['authorization' => 'Basic ' . base64_encode('cron:' . self::KEY)])->status);
        putenv('CRON_KEY=short');
        self::assertSame(404, $this->call([], ['key' => 'short'])->status);
    }

    public function testWrongKeyIsRefusedBothWays(): void
    {
        putenv('CRON_KEY=' . self::KEY);
        $basic = $this->call(['authorization' => 'Basic ' . base64_encode('cron:wrong')]);
        self::assertSame(401, $basic->status);
        self::assertStringContainsString('Basic', $basic->headers['WWW-Authenticate']);
        self::assertSame(401, $this->call([], ['key' => 'wrong'])->status);
        self::assertSame(401, $this->call()->status);
    }
}
