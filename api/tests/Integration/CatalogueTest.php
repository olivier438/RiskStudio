<?php

declare(strict_types=1);

namespace RiskStudio\Tests\Integration;

use PHPUnit\Framework\TestCase;
use RiskStudio\Catalogue\CatalogueImporter;
use RiskStudio\Catalogue\ImportException;
use RiskStudio\Config;
use RiskStudio\Database;
use RiskStudio\Http\Request;
use RiskStudio\Kernel;

/**
 * Checks the imported catalogue (db/catalogue) through the public API.
 * Requires the local database built by scripts/dev-db.sh.
 */
final class CatalogueTest extends TestCase
{
    private static ?Kernel $kernel = null;
    private static ?Database $db = null;
    private static string $catalogueDir;

    public static function setUpBeforeClass(): void
    {
        $config = Config::fromFile(dirname(__DIR__, 2) . '/.env');
        self::$catalogueDir = dirname(__DIR__, 3) . '/db/catalogue';
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

    /** @return array{status: int, json: mixed} */
    private function get(string $path, array $query = []): array
    {
        $response = self::$kernel->handle(new Request('GET', $path, $query));

        return ['status' => $response->status, 'json' => json_decode($response->body, true)];
    }

    /** @return list<string> */
    private function codes(array $query): array
    {
        $r = $this->get('/v1/risks', $query + ['per_page' => '200']);
        self::assertSame(200, $r['status'], json_encode($r['json']));

        return array_column($r['json']['data'], 'code');
    }

    public function testWholeCatalogueIsPublished(): void
    {
        $r = $this->get('/v1/risks', ['per_page' => '1']);

        self::assertSame(167, $r['json']['meta']['total']);
    }

    public function testBackupRiskUsesTheIso2022BackupControl(): void
    {
        $risk = $this->get('/v1/risks/R-OPS-02')['json']['data'];
        $refs = [];
        foreach ($risk['controls'] as $c) {
            $refs[$c['framework'] . ' ' . $c['ref']] = $c['source'];
        }

        // A.8.13 is "backup" in 2022. v4 pointed to A.8.14 (redundancy).
        self::assertSame('editorial', $refs['ISO27001_2022 A.8.13'] ?? null);
        self::assertArrayNotHasKey('ISO27001_2022 A.8.14', $refs);
        self::assertSame('crosswalk', $refs['NIS2 Art.21.2.c'] ?? null);
        self::assertSame('crosswalk', $refs['CYFUN_2023 PR.IP-4'] ?? null);
        self::assertSame('crosswalk', $refs['NIST_CSF_2 PR.DS'] ?? null);
        self::assertSame('BCM', $risk['category']['code']);
        self::assertSame(['confidentiality' => false, 'integrity' => false, 'availability' => true], $risk['cia']);
    }

    public function testNoIso2013ReferenceSurvives(): void
    {
        $count = self::$db->connection(Database::WRITE)->query(
            "SELECT COUNT(*) FROM risk_controls rc JOIN framework_controls c ON c.id = rc.control_id
             JOIN frameworks f ON f.id = c.framework_id
             WHERE f.code = 'ISO27001_2022' AND (c.ref LIKE 'A.9.%' OR c.ref LIKE 'A.1_.%')"
        )->fetchColumn();

        self::assertSame(0, (int) $count);
    }

    public function testFrameworkFilterDistinguishesEditorialFromCrosswalk(): void
    {
        self::assertGreaterThan(100, count($this->codes(['framework' => 'CYFUN_2023'])));
        self::assertSame([], $this->codes(['framework' => 'CYFUN_2023', 'mapping' => 'editorial']));
        self::assertContains('R-IT-24', $this->codes(['framework' => 'CRA', 'mapping' => 'editorial']));
    }

    public function testControlFilterIncludesChildren(): void
    {
        $backup = $this->codes(['framework' => 'ISO27001_2022', 'control' => 'A.8.13']);
        self::assertContains('R-OPS-02', $backup);
        self::assertContains('R-IT-29', $backup);

        $technological = $this->codes(['framework' => 'ISO27001_2022', 'control' => 'A.8']);
        self::assertContains('R-OPS-02', $technological);
        self::assertGreaterThan(count($backup), count($technological));

        self::assertSame(400, $this->get('/v1/risks', ['control' => 'A.8.13'])['status']);
    }

    public function testSectorFilterKeepsCrossSectorRisks(): void
    {
        $health = $this->codes(['sector' => 'HEALTH']);

        self::assertContains('R-HOS-01', $health, 'health-specific risk');
        self::assertContains('R-ACC-01', $health, 'cross-sector risk');
        self::assertNotContains('R-DEV-01', $health, 'finance-only risk');
    }

    public function testCyfunLevelsAreExposed(): void
    {
        $controls = array_column($this->get('/v1/frameworks/CYFUN_2023/controls')['json']['controls'], null, 'ref');

        self::assertSame('BASIC', $controls['PR.AC-1']['assurance_level']);
        self::assertSame('BASIC', $controls['PR.AC-1']['key_measure_level']);
        self::assertSame('ESSENTIAL', $controls['DE.AE-4']['assurance_level']);
        self::assertSame('PR.AC', $controls['PR.AC-1']['parent_ref']);
        self::assertSame('PR', $controls['PR.AC']['parent_ref']);
    }

    public function testImportIsIdempotent(): void
    {
        $importer = new CatalogueImporter(self::$db->connection(Database::WRITE), self::$catalogueDir);

        $stats = $importer->import(dryRun: true);

        self::assertSame(167, $stats['risks']);
        self::assertSame(0, $stats['archived']);
    }

    public function testImportRejectsInvalidRowsWithoutWriting(): void
    {
        $dir = sys_get_temp_dir() . '/rs-catalogue-' . bin2hex(random_bytes(4));
        mkdir($dir);
        symlink(self::$catalogueDir . '/controls', $dir . '/controls');
        symlink(self::$catalogueDir . '/crosswalk', $dir . '/crosswalk');
        file_put_contents($dir . '/risks.csv', implode("\n", [
            'code;title;category;threat;scenario;measures;impact;likelihood;cia;environment;sectors;iso27001;nis2;dora;cra',
            'R-GOV-01;Titre;NOPE;Menace;Scénario;Mesures;9;;DIC;IT;MARS;A.9.2;;;',
        ]) . "\n");

        try {
            (new CatalogueImporter(self::$db->connection(Database::WRITE), $dir))->import();
            self::fail('Invalid catalogue should be rejected.');
        } catch (ImportException $e) {
            $all = implode("\n", $e->errors);
            foreach (['unknown category NOPE', 'unknown sector MARS', 'impact must be 1 to 5', 'cia must be', 'unknown ISO27001_2022 reference A.9.2'] as $expected) {
                self::assertStringContainsString($expected, $all);
            }
        } finally {
            unlink($dir . '/risks.csv');
            unlink($dir . '/controls');
            unlink($dir . '/crosswalk');
            rmdir($dir);
        }

        // Nothing was written: the real catalogue is intact.
        self::assertSame(167, $this->get('/v1/risks', ['per_page' => '1'])['json']['meta']['total']);
        self::assertSame('Absence d\'Information Security Policy', $this->get('/v1/risks/R-GOV-01')['json']['data']['title']);
    }
}
