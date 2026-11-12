<?php

declare(strict_types=1);

namespace RiskStudio\Tests\Integration;

use PDO;
use PHPUnit\Framework\TestCase;
use RiskStudio\Config;
use RiskStudio\Database;
use RiskStudio\Http\Request;
use RiskStudio\Kernel;

/** Threat intelligence, leaks and stats endpoints, on test-owned rows. */
final class FeedApiTest extends TestCase
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

            return;
        }
        self::cleanup();
        $w = self::$db->connection(Database::WRITE);
        $w->exec("INSERT INTO sources (code, name, kind, url, authoritative) VALUES ('TEST_SRC', 'Test source', 'json_api', 'https://example.org', 1)");
        $source = (int) $w->lastInsertId();
        $insert = $w->prepare(
            "INSERT INTO intel_items (source_id, external_id, item_type, title, summary, kev, severity, environment, status, published_at, rule_trace)
             VALUES (?, ?, 'vulnerability', ?, 'Résumé de test', ?, ?, ?, ?, UTC_TIMESTAMP() - INTERVAL ? HOUR, ?)"
        );
        $insert->execute([$source, 'CVE-2098-0001', 'Test critique publié', 1, 'critical', 'OT', 'published', 1, '{"rules":["kev.listed"]}']);
        $insert->execute([$source, 'CVE-2098-0002', 'Test moyen publié', 0, 'medium', 'IT', 'published', 48, null]);
        $insert->execute([$source, 'CVE-2098-0003', 'Test en attente', 1, 'critical', 'IT', 'pending', 1, null]);
        $w->exec("INSERT INTO intel_cves (item_id, cve_id) SELECT id, external_id FROM intel_items WHERE external_id LIKE 'CVE-2098-%'");
        $w->exec(
            "INSERT INTO intel_risks (item_id, risk_id, rule)
             SELECT i.id, r.id, 'test.rule' FROM intel_items i JOIN risks r ON r.code = 'R-OPS-01'
             WHERE i.external_id = 'CVE-2098-0001'"
        );
        $w->prepare(
            "INSERT INTO leaks (source_id, external_id, leak_type, organisation, country, records_count, data_classes, status, published_at)
             VALUES (?, 'TEST-LEAK-1', 'breach', 'Organisation Test', 'BE', 1000, '[\"E-mails\"]', 'published', UTC_TIMESTAMP()),
                    (?, 'TEST-LEAK-2', 'breach', 'Organisation Cachée', 'BE', 10, NULL, 'pending', UTC_TIMESTAMP())"
        )->execute([$source, $source]);
    }

    public static function tearDownAfterClass(): void
    {
        if (self::$kernel !== null) {
            self::cleanup();
        }
    }

    private static function cleanup(): void
    {
        $w = self::$db->connection(Database::WRITE);
        $w->exec("DELETE i FROM intel_items i JOIN sources s ON s.id = i.source_id WHERE s.code = 'TEST_SRC'");
        $w->exec("DELETE l FROM leaks l JOIN sources s ON s.id = l.source_id WHERE s.code = 'TEST_SRC'");
        $w->exec("DELETE FROM sources WHERE code = 'TEST_SRC'");
    }

    protected function setUp(): void
    {
        if (self::$kernel === null) {
            self::markTestSkipped('Local database not available (run scripts/dev-db.sh).');
        }
    }

    /** @return array{status: int, json: mixed} */
    private function get(string $path, array $query = []): array
    {
        $response = self::$kernel->handle(new Request('GET', $path, $query));

        return ['status' => $response->status, 'json' => json_decode($response->body, true)];
    }

    /** @return list<string> */
    private function intelIds(array $query): array
    {
        $r = $this->get('/v1/intel', $query + ['source' => 'TEST_SRC', 'per_page' => '200']);
        self::assertSame(200, $r['status'], json_encode($r['json']));

        return array_column($r['json']['data'], 'external_id');
    }

    public function testOnlyPublishedItemsAreVisible(): void
    {
        self::assertSame(['CVE-2098-0001', 'CVE-2098-0002'], $this->intelIds([]));
        self::assertSame(['Organisation Test'], array_column(
            $this->get('/v1/leaks', ['source' => 'TEST_SRC'])['json']['data'],
            'organisation',
        ));
    }

    public function testIntelPayload(): void
    {
        $item = $this->get('/v1/intel', ['source' => 'TEST_SRC', 'q' => 'CVE-2098-0001'])['json']['data'][0];

        self::assertTrue($item['critical']);
        self::assertSame(['CVE-2098-0001'], $item['cves']);
        self::assertSame('R-OPS-01', $item['risks'][0]['code']);
        self::assertSame(['rules' => ['kev.listed']], $item['rule_trace']);
        self::assertMatchesRegularExpression('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/', $item['published_at']);

        $id = $item['id'];
        self::assertSame(200, $this->get("/v1/intel/{$id}")['status']);
    }

    public function testPendingItemIsNotReachableById(): void
    {
        $id = self::$db->connection(Database::WRITE)
            ->query("SELECT id FROM intel_items WHERE external_id = 'CVE-2098-0003'")->fetchColumn();

        self::assertSame(404, $this->get("/v1/intel/{$id}")['status']);
        self::assertSame(404, $this->get('/v1/intel/abc')['status']);
    }

    public function testIntelFilters(): void
    {
        self::assertSame(['CVE-2098-0001'], $this->intelIds(['severity_min' => 'high']));
        self::assertSame(['CVE-2098-0001'], $this->intelIds(['kev' => '1']));
        self::assertSame(['CVE-2098-0001'], $this->intelIds(['env' => 'OT']));
        self::assertSame(['CVE-2098-0001'], $this->intelIds(['since' => gmdate('Y-m-d\TH:i:s\Z', time() - 6 * 3600)]));
        self::assertSame(400, $this->get('/v1/intel', ['severity_min' => 'huge'])['status']);
        self::assertSame(400, $this->get('/v1/intel', ['since' => 'yesterday'])['status']);
    }

    public function testStatsCountsRecentCriticalItems(): void
    {
        $stats = $this->get('/v1/stats')['json'];

        self::assertGreaterThanOrEqual(1, $stats['intel']['critical_recent']);
        self::assertGreaterThanOrEqual(2, $stats['intel']['total']);
        self::assertSame(167, $stats['risks']['total']);
        self::assertNotNull($stats['last_update']);
    }

    public function testReadUserCannotReadRawFeedTables(): void
    {
        $read = self::$db->connection(Database::READ);
        foreach (['intel_items', 'leaks', 'intel_risks', 'sources'] as $table) {
            try {
                $read->query("SELECT * FROM {$table} LIMIT 1")->fetchAll(PDO::FETCH_ASSOC);
                self::fail("rs_read should not read {$table}");
            } catch (\PDOException $e) {
                self::assertStringContainsString('denied', $e->getMessage());
            }
        }
    }
}
