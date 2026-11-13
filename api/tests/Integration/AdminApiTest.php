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
use RiskStudio\Security\AdminAuth;
use RiskStudio\Security\Totp;

/** Administration, login security and public proposals, end to end through the kernel. */
final class AdminApiTest extends TestCase
{
    private const EMAIL = 'test-admin@example.org';
    private const PASSWORD = 'a long enough test passphrase';

    private static ?Kernel $kernel = null;
    private static ?PDO $pdo = null;
    private static string $secret;
    private static int $lastStep;

    public static function setUpBeforeClass(): void
    {
        $config = Config::fromFile(dirname(__DIR__, 2) . '/.env');
        try {
            $db = new Database($config);
            self::$pdo = $db->connection(Database::WRITE);
            self::$kernel = new Kernel($config, $db);
        } catch (\Throwable) {
            self::$kernel = null;
        }
    }

    protected function setUp(): void
    {
        if (self::$kernel === null) {
            self::markTestSkipped('Local database not available (run scripts/dev-db.sh).');
        }
        self::cleanup();
        self::$secret = Totp::generateSecret();
        self::$lastStep = 0;
        self::$pdo->prepare('INSERT INTO admins (email, display_name, password_hash, totp_secret) VALUES (?, ?, ?, ?)')
            ->execute([self::EMAIL, 'Test Admin', AdminAuth::hashPassword(self::PASSWORD), self::$secret]);
    }

    protected function tearDown(): void
    {
        if (self::$kernel !== null) {
            self::cleanup();
        }
    }

    public function testProbeNeedsCsrfRefusesPrivateAddressesAndIsAudited(): void
    {
        $s = $this->login();
        $h = ['cookie' => $s['cookie'], 'x-csrf-token' => $s['csrf']];
        self::assertSame(403, $this->call('POST', '/v1/admin/probe', ['url' => 'https://127.0.0.1/'], ['cookie' => $s['cookie']])->status);
        self::assertSame(404, $this->call('POST', '/v1/admin/sources/NOPE/probe', [], $h)->status);

        $r = $this->call('POST', '/v1/admin/probe', ['url' => 'https://127.0.0.1/'], $h);
        self::assertSame(200, $r->status, $r->body);
        self::assertSame('no-store', $r->headers['Cache-Control']);
        self::assertSame('refused', self::json($r)['data']['verdict']);
        $audit = self::$pdo->query("SELECT details FROM audit_log WHERE action = 'url.probe' ORDER BY id DESC LIMIT 1")->fetchColumn();
        self::assertStringContainsString('"verdict":"refused"', (string) $audit);
    }

    public function testCustomSourceLifecycle(): void
    {
        $s = $this->login();
        $h = ['cookie' => $s['cookie'], 'x-csrf-token' => $s['csrf']];
        // An IP literal: no DNS lookup, tests never use the network.
        $body = ['name' => 'Veille Exemple', 'url' => 'https://93.184.215.14/feed.xml', 'family' => 'threat', 'country' => 'BE',
            'include' => 'phishing, ransomware', 'poll_minutes' => 60];
        try {
            self::assertSame(403, $this->call('POST', '/v1/admin/sources', $body, ['cookie' => $s['cookie']])->status, 'CSRF');
            $private = $this->call('POST', '/v1/admin/sources', ['url' => 'https://10.0.0.8/feed'] + $body, $h);
            self::assertSame(422, $private->status);
            self::assertArrayHasKey('url', self::json($private)['error']['fields']);
            self::assertSame(422, $this->call('POST', '/v1/admin/sources', ['family' => 'nope', 'poll_minutes' => 5] + $body, $h)->status);

            $created = $this->call('POST', '/v1/admin/sources', $body, $h);
            self::assertSame(200, $created->status, $created->body);
            self::assertSame('RSS_VEILLE_EXEMPLE', self::json($created)['code']);
            self::assertSame('RSS_VEILLE_EXEMPLE_2', self::json($this->call('POST', '/v1/admin/sources', $body, $h))['code'], 'codes stay unique');
            $row = self::$pdo->query("SELECT custom, enabled, authoritative, config FROM sources WHERE code = 'RSS_VEILLE_EXEMPLE'")->fetch();
            self::assertSame(['custom' => 1, 'enabled' => 1, 'authoritative' => 0], array_map('intval', array_slice($row, 0, 3)), 'pending review by default');
            self::assertSame(['family' => 'threat', 'country' => 'BE', 'include' => ['phishing', 'ransomware'], 'exclude' => []], json_decode($row['config'], true));

            $edited = $this->call('PUT', '/v1/admin/sources/RSS_VEILLE_EXEMPLE', ['name' => 'Veille renommée', 'family' => 'vulnerability'] + $body, $h);
            self::assertSame(200, $edited->status, $edited->body);
            self::assertSame('Veille renommée', self::$pdo->query("SELECT name FROM sources WHERE code = 'RSS_VEILLE_EXEMPLE'")->fetchColumn());
            self::assertSame(404, $this->call('PUT', '/v1/admin/sources/CISA_KEV', $body, $h)->status, 'built-in sources are not editable');
            self::assertSame(404, $this->call('POST', '/v1/admin/sources/CISA_KEV/delete', [], $h)->status, 'nor deletable');

            $preview = $this->call('POST', '/v1/admin/sources/preview', ['url' => 'https://127.0.0.1/feed'] + $body, $h);
            self::assertSame(200, $preview->status, $preview->body);
            self::assertFalse(self::json($preview)['data']['ok'], 'private addresses are never fetched');

            self::assertSame(200, $this->call('POST', '/v1/admin/sources/RSS_VEILLE_EXEMPLE/delete', [], $h)->status);
            self::assertFalse(self::$pdo->query("SELECT 1 FROM sources WHERE code = 'RSS_VEILLE_EXEMPLE'")->fetchColumn());
            $audit = self::$pdo->query("SELECT GROUP_CONCAT(action) FROM audit_log WHERE entity_id = 'RSS_VEILLE_EXEMPLE'")->fetchColumn();
            self::assertStringContainsString('source.create', (string) $audit);
            self::assertStringContainsString('source.delete', (string) $audit);
        } finally {
            self::$pdo->exec("DELETE FROM sources WHERE code LIKE 'RSS\\_VEILLE\\_EXEMPLE%'");
        }
    }

    public function testEditorialAlertsLifecycle(): void
    {
        $s = $this->login();
        $h = ['cookie' => $s['cookie'], 'x-csrf-token' => $s['csrf']];
        $body = ['kind' => 'outage', 'level' => 'critical', 'title' => 'phpunit Panne mondiale Exemple 365',
            'summary' => 'Messagerie indisponible.', 'url' => 'https://status.example.org/', 'ends_at' => gmdate('Y-m-d\\TH:i:s\\Z', time() + 3600)];
        $public = fn (): array => array_column(self::json($this->call('GET', '/v1/alerts'))['data'], 'title');
        try {
            self::assertSame(403, $this->call('POST', '/v1/admin/alerts', $body, ['cookie' => $s['cookie']])->status, 'CSRF');
            $bad = $this->call('POST', '/v1/admin/alerts', ['kind' => 'x', 'level' => 'x', 'title' => 'a', 'url' => 'http://x'] + $body, $h);
            self::assertSame(422, $bad->status);
            self::assertSame(['kind', 'level', 'title', 'url'], array_keys(self::json($bad)['error']['fields']));
            self::assertSame(422, $this->call('POST', '/v1/admin/alerts', ['ends_at' => '2000-01-01T00:00:00Z'] + $body, $h)->status, 'end before start');

            $created = $this->call('POST', '/v1/admin/alerts', $body, $h);
            self::assertSame(200, $created->status, $created->body);
            $id = self::json($created)['id'];
            self::assertContains($body['title'], $public());
            $stats = self::json($this->call('GET', '/v1/stats'))['alerts'];
            self::assertGreaterThanOrEqual(1, $stats['active']);
            self::assertGreaterThanOrEqual(1, $stats['critical']);

            $future = $this->call('POST', '/v1/admin/alerts', ['title' => 'phpunit Futur', 'starts_at' => gmdate('Y-m-d\\TH:i:s\\Z', time() + 86400), 'ends_at' => ''] + $body, $h);
            self::assertSame(200, $future->status, $future->body);
            self::assertNotContains('phpunit Futur', $public(), 'not before its start');

            $edited = $this->call('PUT', "/v1/admin/alerts/{$id}", ['level' => 'warning', 'title' => 'phpunit Panne résolue en partie'] + $body, $h);
            self::assertSame(200, $edited->status, $edited->body);
            self::assertContains('phpunit Panne résolue en partie', $public());

            self::assertSame(200, $this->call('POST', "/v1/admin/alerts/{$id}/close", [], $h)->status);
            self::assertNotContains('phpunit Panne résolue en partie', $public(), 'closed alerts leave the page');
            $history = self::json($this->call('GET', '/v1/admin/alerts', null, ['cookie' => $s['cookie']]))['data'];
            $closed = array_values(array_filter($history, fn ($a) => $a['id'] === $id))[0];
            self::assertSame(['archived', false], [$closed['status'], $closed['active']], 'kept in the history');
            self::assertSame(404, $this->call('POST', '/v1/admin/alerts/999999999/close', [], $h)->status);
        } finally {
            self::$pdo->exec("DELETE FROM alerts WHERE title LIKE 'phpunit %'");
        }
    }

    private static function cleanup(): void
    {
        self::$pdo->exec("DELETE FROM risks WHERE origin = 'community' AND code LIKE 'R-COM-%'
                          AND proposal_id IN (SELECT id FROM proposals WHERE submitter_name = 'phpunit')");
        self::$pdo->exec("DELETE FROM proposals WHERE submitter_name = 'phpunit' OR payload LIKE '%phpunit%'");
        self::$pdo->prepare('DELETE FROM admins WHERE email = ?')->execute([self::EMAIL]);
        self::$pdo->exec('DELETE FROM rate_limits');
    }

    /**
     * A fresh, never used TOTP code, computed at call time (a 30 s boundary
     * may pass during a test) and always newer than the previous one (replay).
     */
    private static function code(): string
    {
        self::$lastStep = max(self::$lastStep + 1, intdiv(time(), 30) - 1);

        return Totp::code(self::$secret, self::$lastStep);
    }

    private function call(string $method, string $path, ?array $body = null, array $headers = [], string $ip = '203.0.113.10'): Response
    {
        $headers = array_change_key_case($headers) + ($body !== null ? ['content-type' => 'application/json'] : []);

        return self::$kernel->handle(new Request($method, $path, [], $headers, $body === null ? '' : json_encode($body), [], $ip));
    }

    /** @return array{cookie: string, csrf: string} */
    private function login(): array
    {
        $r = $this->call('POST', '/v1/admin/login', ['email' => self::EMAIL, 'password' => self::PASSWORD, 'code' => self::code()]);
        self::assertSame(200, $r->status, $r->body);
        preg_match('/^(rs_admin|__Host-rs_admin)=([0-9a-f]{64});/', $r->headers['Set-Cookie'], $m);

        return ['cookie' => "{$m[1]}={$m[2]}", 'csrf' => json_decode($r->body, true)['csrf']];
    }

    private static function json(Response $r): array
    {
        return json_decode($r->body, true) ?? [];
    }

    public function testLoginNeedsPasswordAndTotp(): void
    {
        $wrongPassword = $this->call('POST', '/v1/admin/login', ['email' => self::EMAIL, 'password' => 'nope', 'code' => self::code()]);
        $wrongCode = $this->call('POST', '/v1/admin/login', ['email' => self::EMAIL, 'password' => self::PASSWORD, 'code' => '000000']);
        $unknown = $this->call('POST', '/v1/admin/login', ['email' => 'nobody@example.org', 'password' => self::PASSWORD, 'code' => '123456']);

        foreach ([$wrongPassword, $wrongCode, $unknown] as $r) {
            self::assertSame(401, $r->status);
            self::assertSame('Identifiants ou code invalides.', self::json($r)['error']['message'], 'same message: no account enumeration');
        }

        $ok = $this->call('POST', '/v1/admin/login', ['email' => self::EMAIL, 'password' => self::PASSWORD, 'code' => self::code()]);
        self::assertSame(200, $ok->status);
        foreach (['HttpOnly', 'SameSite=Strict', 'Path=/'] as $flag) {
            self::assertStringContainsString($flag, $ok->headers['Set-Cookie']);
        }
        preg_match('/^([^=]+=[0-9a-f]{64});/', $ok->headers['Set-Cookie'], $m);
        self::assertSame(200, $this->call('GET', '/v1/admin/me', null, ['cookie' => $m[1]])->status);
        self::assertSame(0, (int) self::$pdo->query("SELECT COUNT(*) FROM admin_sessions WHERE token_hash = '" . substr($m[1], -64) . "'")->fetchColumn(),
            'only the hash of the token is stored');
    }

    public function testTotpCodeCannotBeReplayed(): void
    {
        $code = self::code();
        $first = $this->call('POST', '/v1/admin/login', ['email' => self::EMAIL, 'password' => self::PASSWORD, 'code' => $code]);
        $replay = $this->call('POST', '/v1/admin/login', ['email' => self::EMAIL, 'password' => self::PASSWORD, 'code' => $code]);

        self::assertSame(200, $first->status);
        self::assertSame(401, $replay->status);
    }

    public function testLoginIsThrottled(): void
    {
        for ($i = 0; $i < 5; $i++) {
            $this->call('POST', '/v1/admin/login', ['email' => self::EMAIL, 'password' => 'wrong', 'code' => '000000']);
        }
        $blocked = $this->call('POST', '/v1/admin/login', ['email' => self::EMAIL, 'password' => self::PASSWORD, 'code' => self::code()]);

        self::assertSame(429, $blocked->status, 'even the right credentials wait once the account is throttled');
        $buckets = self::$pdo->query('SELECT bucket FROM rate_limits')->fetchAll(PDO::FETCH_COLUMN);
        foreach ($buckets as $bucket) {
            self::assertStringNotContainsString('example.org', $bucket);
            self::assertStringNotContainsString('203.0.113', $bucket);
        }
    }

    public function testEndpointsNeedASessionAndMutationsNeedCsrf(): void
    {
        self::assertSame(401, $this->call('GET', '/v1/admin/queue')->status);

        $s = $this->login();
        self::assertSame(200, $this->call('GET', '/v1/admin/queue', null, ['cookie' => $s['cookie']])->status);
        $noCsrf = $this->call('POST', '/v1/admin/sources/HIBP', ['enabled' => true], ['cookie' => $s['cookie']]);
        self::assertSame(403, $noCsrf->status);
        $ok = $this->call('POST', '/v1/admin/sources/HIBP', ['enabled' => true], ['cookie' => $s['cookie'], 'x-csrf-token' => $s['csrf']]);
        self::assertSame(200, $ok->status, $ok->body);
        self::assertSame('no-store', $ok->headers['Cache-Control']);
    }

    public function testIdleSessionExpiresAndLogoutCloses(): void
    {
        $s = $this->login();
        self::$pdo->exec('UPDATE admin_sessions SET last_seen_at = UTC_TIMESTAMP() - INTERVAL ' . (AdminAuth::IDLE_MINUTES + 1) . ' MINUTE');
        self::assertSame(401, $this->call('GET', '/v1/admin/me', null, ['cookie' => $s['cookie']])->status);

        $s = $this->login();
        self::assertSame(200, $this->call('POST', '/v1/admin/logout', [], ['cookie' => $s['cookie'], 'x-csrf-token' => $s['csrf']])->status);
        self::assertSame(401, $this->call('GET', '/v1/admin/me', null, ['cookie' => $s['cookie']])->status);
    }

    public function testPublicProposalLifecycle(): void
    {
        $proposal = [
            'kind' => 'risk',
            'submitter_name' => 'phpunit',
            'payload' => [
                'title' => 'Imprimantes multifonctions exposées sur Internet',
                'category' => 'INFRA',
                'threat' => 'Accès non autorisé',
                'scenario' => 'Une imprimante exposée sans mot de passe révèle les documents numérisés.',
                'measures' => 'Retirer l\'exposition Internet et changer les mots de passe par défaut.',
                'impact' => 3,
                'cia' => 'C',
                'environment' => 'IT',
                'sectors' => ['LOCAL_GOV'],
                'status' => 'published',
            ],
        ];

        $invalid = $this->call('POST', '/v1/proposals', ['kind' => 'risk', 'payload' => ['title' => 'x']]);
        self::assertSame(422, $invalid->status);
        self::assertArrayHasKey('category', self::json($invalid)['error']['fields']);

        $bot = $this->call('POST', '/v1/proposals', $proposal + ['website' => 'http://spam.example']);
        self::assertSame(202, $bot->status);

        $r = $this->call('POST', '/v1/proposals', $proposal);
        self::assertSame(202, $r->status, $r->body);
        $stored = self::$pdo->query("SELECT * FROM proposals WHERE submitter_name = 'phpunit'")->fetchAll();
        self::assertCount(1, $stored, 'honeypot submission was dropped');
        self::assertSame('pending', $stored[0]['status'], 'a payload "status" never reaches the column');
        self::assertNotNull($stored[0]['client_fingerprint']);
        self::assertStringNotContainsString('203.0.113', $stored[0]['client_fingerprint']);

        // Approve: becomes a published community risk.
        $s = $this->login();
        $h = ['cookie' => $s['cookie'], 'x-csrf-token' => $s['csrf']];
        $approve = $this->call('POST', "/v1/admin/proposals/{$stored[0]['id']}/decision", ['decision' => 'approve', 'note' => 'OK'], $h);
        self::assertSame(200, $approve->status, $approve->body);
        $code = self::json($approve)['risk_code'];
        self::assertMatchesRegularExpression('/^R-COM-\d{2,}$/', $code);

        $public = json_decode(self::$kernel->handle(new Request('GET', "/v1/risks/{$code}"))->body, true);
        self::assertSame('community', $public['data']['origin']);
        self::assertSame(['LOCAL_GOV'], $public['data']['sectors']);

        // Community risks are editable, catalogue risks are not.
        $edit = $this->call('PUT', "/v1/admin/risks/{$code}", ['impact' => 4] + $proposal['payload'], $h);
        self::assertSame(200, $edit->status, $edit->body);
        self::assertSame(4, self::json($edit)['data']['impact']);
        self::assertSame(409, $this->call('PUT', '/v1/admin/risks/R-GOV-01', $proposal['payload'], $h)->status);

        // Audited.
        $actions = array_column(self::json($this->call('GET', '/v1/admin/audit', null, $h))['data'], 'action');
        self::assertContains('proposal.approve', $actions);
        self::assertContains('risk.update', $actions);
    }

    public function testFallbackModeStillForcesPendingStatus(): void
    {
        putenv('DB_PUBLIC_WRITES=write');
        try {
            $config = Config::fromFile(dirname(__DIR__, 2) . '/.env');
            $kernel = new Kernel($config, new Database($config));
            $body = ['kind' => 'correction', 'submitter_name' => 'phpunit', 'status' => 'approved',
                'payload' => ['risk_code' => 'R-GOV-01', 'message' => 'phpunit: mode de repli.', 'status' => 'approved']];
            $r = $kernel->handle(new Request('POST', '/v1/proposals', [], ['content-type' => 'application/json'], json_encode($body), [], '192.0.2.50'));
            self::assertSame(202, $r->status, $r->body);
            self::assertSame(['pending'], self::$pdo->query("SELECT status FROM proposals WHERE payload LIKE '%mode de repli%'")->fetchAll(PDO::FETCH_COLUMN));
        } finally {
            putenv('DB_PUBLIC_WRITES');
        }
    }

    public function testProposalsAreRateLimitedPerClient(): void
    {
        $proposal = ['kind' => 'correction', 'submitter_name' => 'phpunit', 'payload' => ['risk_code' => 'R-GOV-01', 'message' => 'phpunit: une correction utile.']];
        for ($i = 0; $i < 5; $i++) {
            self::assertSame(202, $this->call('POST', '/v1/proposals', $proposal, [], '198.51.100.7')->status);
        }
        self::assertSame(429, $this->call('POST', '/v1/proposals', $proposal, [], '198.51.100.7')->status);
        self::assertSame(202, $this->call('POST', '/v1/proposals', $proposal, [], '198.51.100.8')->status, 'other clients are not affected');
    }

    public function testFeedDecisionPublishesAndAudits(): void
    {
        self::$pdo->exec("INSERT INTO sources (code, name, kind, url, authoritative) VALUES ('TST_ADM', 'Test', 'json_api', 'https://example.org', 0)");
        $source = (int) self::$pdo->lastInsertId();
        self::$pdo->exec("INSERT INTO intel_items (source_id, external_id, item_type, title, status) VALUES ({$source}, 'TST-ADM-1', 'vulnerability', 'phpunit pending', 'pending')");
        $id = (int) self::$pdo->lastInsertId();

        try {
            $s = $this->login();
            $h = ['cookie' => $s['cookie'], 'x-csrf-token' => $s['csrf']];
            $queue = self::json($this->call('GET', '/v1/admin/queue', null, $h));
            self::assertContains($id, array_column($queue['intel'], 'id'));

            self::assertSame(400, $this->call('POST', "/v1/admin/intel/{$id}/decision", ['decision' => 'delete'], $h)->status);
            self::assertSame(200, $this->call('POST', "/v1/admin/intel/{$id}/decision", ['decision' => 'publish'], $h)->status);
            $row = self::$pdo->query("SELECT status, published_at FROM intel_items WHERE id = {$id}")->fetch();
            self::assertSame('published', $row['status']);
            self::assertNotNull($row['published_at']);
        } finally {
            self::$pdo->exec("DELETE FROM intel_items WHERE id = {$id}");
            self::$pdo->exec("DELETE FROM sources WHERE code = 'TST_ADM'");
        }
    }
}
