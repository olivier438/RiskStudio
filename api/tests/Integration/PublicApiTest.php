<?php

declare(strict_types=1);

namespace RiskStudio\Tests\Integration;

use PHPUnit\Framework\TestCase;
use RiskStudio\Config;
use RiskStudio\Database;
use RiskStudio\Http\Request;
use RiskStudio\Kernel;

/**
 * Runs against the local database built by scripts/dev-db.sh.
 * Skipped when that database is not reachable.
 */
final class PublicApiTest extends TestCase
{
    private static ?Kernel $kernel = null;
    private static ?Database $db = null;

    public static function setUpBeforeClass(): void
    {
        $config = Config::fromFile(dirname(__DIR__, 2) . '/.env');
        try {
            self::$db = new Database($config);
            self::$db->connection(Database::READ)->query('SELECT 1');
            self::$kernel = new Kernel($config, self::$db);
        } catch (\Throwable) {
            self::$kernel = null;
        }
    }

    protected function setUp(): void
    {
        if (self::$kernel === null) {
            self::markTestSkipped('Local database not available (run scripts/dev-db.sh).');
        }
    }

    /** @return array<string, mixed> */
    private function get(string $path, array $query = []): array
    {
        $response = self::$kernel->handle(new Request('GET', $path, $query));

        return ['status' => $response->status, 'json' => json_decode($response->body, true)];
    }

    public function testHealth(): void
    {
        $r = $this->get('/v1/health');

        self::assertSame(200, $r['status']);
        self::assertSame('ok', $r['json']['database']);
    }

    public function testReferenceData(): void
    {
        $r = $this->get('/v1/reference');
        $frameworks = array_column($r['json']['frameworks'], 'controls_count', 'code');

        self::assertSame(200, $r['status']);
        self::assertCount(15, $r['json']['categories']);
        self::assertSame(127, $frameworks['ISO27001_2022'], '93 Annex A controls + 4 themes + 30 clauses');
        self::assertContains('Sécurité physique', array_column($r['json']['categories'], 'name_fr'));
    }

    public function testControlsEndpoint(): void
    {
        $r = $this->get('/v1/frameworks/nis2/controls');

        self::assertSame(200, $r['status']);
        self::assertContains('Art.21.2.j', array_column($r['json']['controls'], 'ref'));
        self::assertSame(404, $this->get('/v1/frameworks/UNKNOWN/controls')['status']);
    }

    public function testRisksEndpointReturnsOnlyPublishedRows(): void
    {
        $write = self::$db->connection(Database::WRITE);
        $write->exec("DELETE FROM risks WHERE code IN ('T-TEST-01','T-TEST-02')");
        $write->exec(
            "INSERT INTO risks (code, title, category_id, threat, scenario, measures, impact, cia_confidentiality, status)
             SELECT 'T-TEST-01', 'Test publié', id, 'Test', 'Scénario', 'Mesure', 5, 1, 'published' FROM categories WHERE code = 'GOV'
             UNION ALL
             SELECT 'T-TEST-02', 'Test brouillon', id, 'Test', 'Scénario', 'Mesure', 5, 1, 'draft' FROM categories WHERE code = 'GOV'"
        );

        try {
            $codes = array_column($this->get('/v1/risks', ['q' => 'T-TEST', 'per_page' => '200'])['json']['data'], 'code');
            self::assertContains('T-TEST-01', $codes);
            self::assertNotContains('T-TEST-02', $codes);
            self::assertSame(404, $this->get('/v1/risks/T-TEST-02')['status']);
            self::assertSame('Test publié', $this->get('/v1/risks/T-TEST-01')['json']['data']['title']);
        } finally {
            $write->exec("DELETE FROM risks WHERE code IN ('T-TEST-01','T-TEST-02')");
        }
    }

    public function testReadUserCannotTouchPrivateTables(): void
    {
        $read = self::$db->connection(Database::READ);

        foreach (['SELECT * FROM risks', 'SELECT * FROM admins', 'SELECT * FROM proposals', "UPDATE categories SET name_fr = 'x'"] as $sql) {
            try {
                $read->query($sql);
                self::fail("rs_read should not be allowed to run: {$sql}");
            } catch (\PDOException $e) {
                self::assertStringContainsString('denied', $e->getMessage());
            }
        }
    }

    public function testReadUserCannotForceProposalStatus(): void
    {
        $read = self::$db->connection(Database::READ);

        $this->expectException(\PDOException::class);
        $read->exec("INSERT INTO proposals (kind, payload, status) VALUES ('risk', '{}', 'approved')");
    }

    public function testUnknownEndpointIs404Json(): void
    {
        $r = $this->get('/v1/nope');

        self::assertSame(404, $r['status']);
        self::assertSame('not_found', $r['json']['error']['code']);
    }
}
