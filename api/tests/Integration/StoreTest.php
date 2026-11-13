<?php

declare(strict_types=1);

namespace RiskStudio\Tests\Integration;

use PDO;
use PHPUnit\Framework\TestCase;
use RiskStudio\Collector\Classifier;
use RiskStudio\Collector\Facts;
use RiskStudio\Collector\LeakFacts;
use RiskStudio\Collector\Rules;
use RiskStudio\Collector\Store;
use RiskStudio\Config;
use RiskStudio\Database;

/** Collector storage rules, on test-owned sources (codes reuse the merge list). */
final class StoreTest extends TestCase
{
    private static ?PDO $pdo = null;
    private static Store $store;
    /** @var array<string, array{id: int, code: string, authoritative: int}> */
    private static array $sources = [];

    public static function setUpBeforeClass(): void
    {
        try {
            self::$pdo = (new Database(Config::fromFile(dirname(__DIR__, 2) . '/.env')))->connection(Database::WRITE);
        } catch (\Throwable) {
            self::$pdo = null;

            return;
        }
        // The test sources play the role of vulnerability feeds, so CVE merging applies.
        self::$store = new Store(self::$pdo, new Classifier(Rules::load(dirname(__DIR__, 3) . '/db/rules')), ['TST_KEV', 'TST_PENDING']);
    }

    protected function setUp(): void
    {
        if (self::$pdo === null) {
            self::markTestSkipped('Local database not available (run scripts/dev-db.sh).');
        }
        self::cleanup();
        foreach (['TST_KEV' => 1, 'TST_PENDING' => 0, 'TST_LEAKS' => 0] as $code => $auth) {
            self::$pdo->prepare("INSERT INTO sources (code, name, kind, url, authoritative) VALUES (?, ?, 'json_api', 'https://example.org', ?)")
                ->execute([$code, $code, $auth]);
            self::$sources[$code] = ['id' => (int) self::$pdo->lastInsertId(), 'code' => $code, 'authoritative' => $auth];
        }
    }

    protected function tearDown(): void
    {
        if (self::$pdo !== null) {
            self::cleanup();
        }
    }

    private static function cleanup(): void
    {
        self::$pdo->exec("DELETE i FROM intel_items i JOIN sources s ON s.id = i.source_id WHERE s.code LIKE 'TST\\_%'");
        self::$pdo->exec("DELETE l FROM leaks l JOIN sources s ON s.id = l.source_id WHERE s.code LIKE 'TST\\_%'");
        self::$pdo->exec("DELETE FROM sources WHERE code LIKE 'TST\\_%'");
    }

    private function item(string $externalId): array
    {
        $stmt = self::$pdo->prepare('SELECT * FROM intel_items WHERE external_id = ?');
        $stmt->execute([$externalId]);

        return $stmt->fetch() ?: [];
    }

    private static function facts(string $source, bool $kev = false, ?float $cvss = null): Facts
    {
        return new Facts('CVE-2099-7777', $kev ? 'exploitation' : 'vulnerability', 'Exemple VPN bypass',
            cves: ['CVE-2099-7777'], cwes: ['CWE-288'], cvss: $cvss, kev: $kev, vendor: 'Exemple', product: 'Gate VPN',
            sources: [$source]);
    }

    public function testAuthoritativeSourcePublishesAndOthersWait(): void
    {
        self::assertSame('new', self::$store->saveIntel(self::$sources['TST_KEV'], self::facts('TST_KEV', true)));
        $item = $this->item('CVE-2099-7777');
        self::assertSame('published', $item['status']);
        self::assertNotNull($item['published_at']);
        self::assertSame('high', $item['severity']);

        $other = new Facts('TST-0001', 'vulnerability', 'Unconfirmed', sources: ['TST_PENDING']);
        self::$store->saveIntel(self::$sources['TST_PENDING'], $other);
        self::assertSame('pending', $this->item('TST-0001')['status']);
        self::assertNull($this->item('TST-0001')['published_at']);
    }

    public function testSecondRunIsUnchangedAndUpdatesOnlyOnNewFacts(): void
    {
        self::$store->saveIntel(self::$sources['TST_KEV'], self::facts('TST_KEV', true));
        self::assertSame('unchanged', self::$store->saveIntel(self::$sources['TST_KEV'], self::facts('TST_KEV', true)));
        self::assertSame('updated', self::$store->saveIntel(self::$sources['TST_KEV'], self::facts('TST_KEV', true, 9.8)));

        $item = $this->item('CVE-2099-7777');
        self::assertSame('9.8', (string) $item['cvss_score']);
        self::assertSame('critical', $item['severity']);
    }

    public function testChildrenAreWritten(): void
    {
        self::$store->saveIntel(self::$sources['TST_KEV'], self::facts('TST_KEV', true));
        $id = (int) $this->item('CVE-2099-7777')['id'];

        $q = fn (string $sql) => self::$pdo->query(str_replace('?', (string) $id, $sql))->fetchAll(PDO::FETCH_COLUMN);
        self::assertSame(['CVE-2099-7777'], $q('SELECT cve_id FROM intel_cves WHERE item_id = ?'));
        self::assertSame(['IAM'], $q('SELECT c.code FROM intel_categories ic JOIN categories c ON c.id = ic.category_id WHERE item_id = ?'));
        self::assertContains('R-OPS-01', $q('SELECT r.code FROM intel_risks ir JOIN risks r ON r.id = ir.risk_id WHERE item_id = ?'));
        self::assertContains('R-ACC-01', $q('SELECT r.code FROM intel_risks ir JOIN risks r ON r.id = ir.risk_id WHERE item_id = ?'), 'product rule "vpn"');
        self::assertSame(['Gate VPN'], $q('SELECT p.name FROM intel_products ip JOIN products p ON p.id = ip.product_id WHERE item_id = ?'));
        $trace = json_decode((string) $this->item('CVE-2099-7777')['rule_trace'], true);
        self::assertContains('source.tst_kev', $trace['rules']);
    }

    public function testPendingItemIsPublishedWhenAnAuthorityConfirmsIt(): void
    {
        $pending = new Facts('TST-0002', 'vulnerability', 'Wait', sources: ['TST_PENDING']);
        self::$store->saveIntel(self::$sources['TST_PENDING'], $pending);
        self::assertSame('pending', $this->item('TST-0002')['status']);

        // Same external id seen again through the same pending source: stays pending.
        self::$store->saveIntel(self::$sources['TST_PENDING'], $pending);
        self::assertSame('pending', $this->item('TST-0002')['status']);
    }

    public function testSameCveFromTwoFeedsIsMergedAndConfirmationPublishes(): void
    {
        self::$store->saveIntel(self::$sources['TST_PENDING'], self::facts('TST_PENDING', false, 7.5));
        self::assertSame('pending', $this->item('CVE-2099-7777')['status']);

        self::assertSame('updated', self::$store->saveIntel(self::$sources['TST_KEV'], self::facts('TST_KEV', true)));
        $item = $this->item('CVE-2099-7777');
        self::assertSame('published', $item['status'], 'confirmed by an authoritative source');
        self::assertSame('1', (string) $item['kev']);
        self::assertSame('7.5', (string) $item['cvss_score'], 'facts merged, nothing lost');
        self::assertSame(1, (int) self::$pdo->query("SELECT COUNT(*) FROM intel_items WHERE external_id = 'CVE-2099-7777'")->fetchColumn());
        self::assertSame(2, (int) self::$pdo->query("SELECT COUNT(*) FROM intel_item_sources WHERE item_id = {$item['id']}")->fetchColumn());
    }

    public function testRejectedItemIsNeverRepublished(): void
    {
        self::$store->saveIntel(self::$sources['TST_KEV'], self::facts('TST_KEV', true));
        self::$pdo->exec("UPDATE intel_items SET status = 'rejected' WHERE external_id = 'CVE-2099-7777'");

        self::$store->saveIntel(self::$sources['TST_KEV'], self::facts('TST_KEV', true, 9.8));
        self::assertSame('rejected', $this->item('CVE-2099-7777')['status']);
    }

    public function testReclassifyReplaysFacts(): void
    {
        self::$store->saveIntel(self::$sources['TST_KEV'], self::facts('TST_KEV', true));
        self::$pdo->exec("UPDATE intel_items SET score = 1, severity = 'low' WHERE external_id = 'CVE-2099-7777'");

        self::assertGreaterThan(0, self::$store->reclassify());
        $item = $this->item('CVE-2099-7777');
        self::assertSame('high', $item['severity']);
        self::assertGreaterThan(60, (int) $item['score']);
    }

    public function testLeaksFollowTheSourcePolicy(): void
    {
        $leak = new LeakFacts('tst-leak-1', 'ransomware', 'Clinique Exemple', country: 'BE', activity: 'Healthcare', actor: 'ExempleLocker');

        self::assertSame('new', self::$store->saveLeak(self::$sources['TST_LEAKS'], $leak));
        self::assertSame('unchanged', self::$store->saveLeak(self::$sources['TST_LEAKS'], $leak));
        $row = self::$pdo->query("SELECT l.status, s.code FROM leaks l LEFT JOIN sectors s ON s.id = l.sector_id WHERE external_id = 'tst-leak-1'")->fetch();
        self::assertSame(['status' => 'pending', 'code' => 'HEALTH'], $row);
    }

    public function testClaimsWaitAndArePublishedOnceConfirmed(): void
    {
        $source = ['code' => 'TST_KEV'] + self::$sources['TST_KEV'];
        $claim = new LeakFacts('tst-claim-1', 'breach', 'Exemple Boutique', country: 'FR', dataClasses: ['IBAN'], confidence: 'claimed');
        $confirmed = new LeakFacts('tst-claim-2', 'breach', 'Exemple Banque', dataClasses: ['Adresse email'], confidence: 'confirmed');
        $status = fn (string $id) => self::$pdo->query("SELECT status, severity, confidence FROM leaks WHERE external_id = '{$id}'")->fetch();

        self::assertSame('new', self::$store->saveLeak($source, $claim));
        self::assertSame('new', self::$store->saveLeak($source, $confirmed));
        self::assertSame(['status' => 'pending', 'severity' => 'critical', 'confidence' => 'claimed'], $status('tst-claim-1'), 'an authority does not publish a claim');
        self::assertSame(['status' => 'published', 'severity' => 'medium', 'confidence' => 'confirmed'], $status('tst-claim-2'));

        $claim->confidence = 'confirmed';
        self::assertSame('updated', self::$store->saveLeak($source, $claim));
        self::assertSame('published', $status('tst-claim-1')['status']);
    }

    public function testStaleClassificationsAreReplayed(): void
    {
        $leak = new LeakFacts('tst-stale-1', 'breach', 'Exemple', dataClasses: ['Passwords']);
        self::$store->saveLeak(self::$sources['TST_LEAKS'], $leak);
        self::$pdo->exec("UPDATE leaks SET severity = NULL, rule_trace = '{\"rules\":[],\"rules_version\":\"old\"}' WHERE external_id = 'tst-stale-1'");

        self::assertGreaterThanOrEqual(1, self::$store->reclassifyStale(500));
        self::assertSame('high', self::$pdo->query("SELECT severity FROM leaks WHERE external_id = 'tst-stale-1'")->fetchColumn());
        self::assertSame('unchanged', self::$store->saveLeak(self::$sources['TST_LEAKS'], $leak));
    }

    public function testEveryRiskReferencedByTheRulesExists(): void
    {
        $codes = array_unique(array_column(Rules::load(dirname(__DIR__, 3) . '/db/rules')->riskLinks, 'risk'));
        $in = implode(',', array_fill(0, count($codes), '?'));
        $stmt = self::$pdo->prepare("SELECT code FROM risks WHERE status = 'published' AND code IN ({$in})");
        $stmt->execute(array_values($codes));

        self::assertEqualsCanonicalizing(array_values($codes), $stmt->fetchAll(PDO::FETCH_COLUMN));
    }
}
