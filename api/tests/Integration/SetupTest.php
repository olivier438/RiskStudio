<?php

declare(strict_types=1);

namespace RiskStudio\Tests\Integration;

use PDO;
use PHPUnit\Framework\TestCase;
use RiskStudio\Config;
use RiskStudio\Database;
use RiskStudio\Http\Request;
use RiskStudio\Http\Response;
use RiskStudio\Kernel;
use RiskStudio\Security\Totp;

/** Web installer for FTP-only hosting. */
final class SetupTest extends TestCase
{
    private const TOKEN = 'phpunit-setup-token-0123456789abcdef';

    private static ?PDO $pdo = null;

    public static function setUpBeforeClass(): void
    {
        try {
            $config = Config::fromFile(dirname(__DIR__, 2) . '/.env');
            self::$pdo = (new Database($config))->connection(Database::WRITE);
        } catch (\Throwable) {
            self::$pdo = null;
        }
    }

    protected function setUp(): void
    {
        if (self::$pdo === null) {
            self::markTestSkipped('Local database not available (run scripts/dev-db.sh).');
        }
    }

    protected function tearDown(): void
    {
        putenv('SETUP_TOKEN');
    }

    private function call(string $method, string $path, ?string $token, ?array $body = null): Response
    {
        $config = Config::fromFile(dirname(__DIR__, 2) . '/.env');
        $headers = ($token !== null ? ['x-setup-token' => $token] : []) + ($body !== null ? ['content-type' => 'application/json'] : []);

        return (new Kernel($config, new Database($config)))
            ->handle(new Request($method, $path, [], $headers, $body === null ? '' : json_encode($body)));
    }

    public function testDisabledWithoutTokenInEnv(): void
    {
        putenv('SETUP_TOKEN');
        self::assertSame(404, $this->call('GET', '/v1/setup/status', self::TOKEN)->status);

        putenv('SETUP_TOKEN=too-short');
        self::assertSame(404, $this->call('GET', '/v1/setup/status', 'too-short')->status, 'weak tokens disable setup');
    }

    public function testWrongTokenIsRefused(): void
    {
        putenv('SETUP_TOKEN=' . self::TOKEN);
        self::assertSame(403, $this->call('GET', '/v1/setup/status', 'nope')->status);
        self::assertSame(403, $this->call('POST', '/v1/setup/install', null, [])->status);
    }

    public function testInstallIsIdempotentAndStatusReportsIt(): void
    {
        putenv('SETUP_TOKEN=' . self::TOKEN);

        $install = $this->call('POST', '/v1/setup/install', self::TOKEN, []);
        self::assertSame(200, $install->status, $install->body);
        self::assertSame([], json_decode($install->body, true)['migrations_applied'], 'already installed: nothing to apply');

        $status = json_decode($this->call('GET', '/v1/setup/status', self::TOKEN)->body, true);
        self::assertTrue($status['installed']);
        self::assertSame([], $status['migrations_pending']);
        self::assertGreaterThanOrEqual(167, $status['risks']);
    }

    public function testSchemaOwnerTypedInTheFormIsUsedAndNeverEchoed(): void
    {
        putenv('SETUP_TOKEN=' . self::TOKEN);
        $config = Config::fromFile(dirname(__DIR__, 2) . '/.env');

        $refused = $this->call('POST', '/v1/setup/install', self::TOKEN, ['db_admin_user' => 'nobody', 'db_admin_password' => 'wrong']);
        self::assertSame(400, $refused->status);
        self::assertStringNotContainsString('nobody', $refused->body, 'driver message (user, host) never echoed');
        self::assertStringNotContainsString('SQLSTATE', $refused->body);

        $ok = $this->call('POST', '/v1/setup/install', self::TOKEN, [
            'db_admin_user' => $config->get('DB_ADMIN_USER'),
            'db_admin_password' => $config->get('DB_ADMIN_PASSWORD'),
        ]);
        self::assertSame(200, $ok->status, $ok->body);
    }

    public function testOnlyTheFirstAdministratorCanBeCreated(): void
    {
        putenv('SETUP_TOKEN=' . self::TOKEN);
        $existing = (int) self::$pdo->query('SELECT COUNT(*) FROM admins')->fetchColumn();
        $body = ['email' => 'setup-test@example.org', 'name' => 'Setup', 'password' => 'a long enough passphrase'];

        if ($existing > 0) {
            self::assertSame(409, $this->call('POST', '/v1/setup/admin', self::TOKEN, $body)->status);

            return;
        }
        try {
            self::assertSame(422, $this->call('POST', '/v1/setup/admin', self::TOKEN, ['password' => 'short'] + $body)->status);
            $r = $this->call('POST', '/v1/setup/admin', self::TOKEN, $body);
            self::assertSame(200, $r->status, $r->body);
            $data = json_decode($r->body, true);
            self::assertMatchesRegularExpression('/^[A-Z2-7]{32}$/', $data['totp_secret']);
            self::assertSame(Totp::uri($data['totp_secret'], 'setup-test@example.org'), $data['totp_uri']);
            self::assertSame('no-store', $r->headers['Cache-Control']);
            self::assertSame(409, $this->call('POST', '/v1/setup/admin', self::TOKEN, ['email' => 'second@example.org'] + $body)->status);
        } finally {
            self::$pdo->exec("DELETE FROM admins WHERE email = 'setup-test@example.org'");
        }
    }
}
