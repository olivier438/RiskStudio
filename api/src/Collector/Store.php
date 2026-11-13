<?php

declare(strict_types=1);

namespace RiskStudio\Collector;

use PDO;

/**
 * Writes classified facts to the database (rs_write user).
 *
 * - The same CVE reported by several vulnerability feeds becomes one item:
 *   facts are merged, every source is recorded in intel_item_sources.
 * - Publication: authoritative sources publish directly, the others create
 *   pending items. An existing item never loses its editorial status, except
 *   that a pending item is published when an authoritative source confirms it.
 * - An unchanged item is not rewritten, so `updated_at` means "really changed".
 */
final class Store
{
    /** Feeds keyed by CVE, whose items are merged together. */
    public const VULNERABILITY_FEEDS = ['CISA_KEV', 'EUVD_EXPLOITED', 'EUVD_CRITICAL'];

    /** @param list<string> $vulnerabilityFeeds */
    public function __construct(
        private readonly PDO $pdo,
        private readonly Classifier $classifier,
        private readonly array $vulnerabilityFeeds = self::VULNERABILITY_FEEDS,
    ) {
    }

    /** @param array{id: int|string, code: string, authoritative: int|string|bool} $source */
    public function saveIntel(array $source, Facts $facts): string
    {
        $existing = $this->findIntel($source, $facts);
        $authoritative = (bool) $source['authoritative'];

        if ($existing !== null) {
            $merged = Facts::fromArray(json_decode((string) $existing['facts'], true) ?: $facts->toArray());
            $before = json_encode($merged->toArray());
            $merged->merge($facts);
            $publish = $authoritative && $existing['status'] === 'pending';
            $this->link((int) $existing['id'], $source, $facts->externalId);
            if (json_encode($merged->toArray()) === $before && !$publish) {
                return 'unchanged';
            }
            $this->writeIntel((int) $existing['id'], $merged, $publish ? 'published' : null);

            return 'updated';
        }

        $id = $this->writeIntel(null, $facts, $authoritative ? 'published' : 'pending', (int) $source['id']);
        $this->link($id, $source, $facts->externalId);

        return 'new';
    }

    /**
     * Publication of leaks: an authoritative source publishes what it reports
     * as confirmed (or without a confidence level); claims wait for review. A
     * pending leak is published when the authoritative source later confirms it.
     *
     * @param array{id: int|string, code: string, authoritative: int|string|bool} $source
     */
    public function saveLeak(array $source, LeakFacts $leak): string
    {
        $stmt = $this->pdo->prepare('SELECT id, facts, status, rule_trace FROM leaks WHERE source_id = ? AND external_id = ?');
        $stmt->execute([$source['id'], $leak->externalId]);
        $row = $stmt->fetch();
        $json = json_encode($leak->toArray(), JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE);
        $publishable = (bool) $source['authoritative'] && in_array($leak->confidence, [null, 'confirmed'], true);
        if ($row !== false && $row['facts'] === $json && self::traceVersion($row['rule_trace']) === $this->classifier->rulesVersion()) {
            return 'unchanged';
        }

        if ($row !== false) {
            $this->writeLeak((int) $row['id'], $leak, $source['code'], $publishable && $row['status'] === 'pending');

            return 'updated';
        }

        $c = $this->classifier->classifyLeak($leak, $source['code']);
        $this->pdo->prepare(
            'INSERT INTO leaks (leak_type, organisation, country, sector_id, actor, records_count, data_classes, severity, confidence,
                                disclosed_at, url, rule_trace, facts, source_id, external_id, status, published_at)
             VALUES (?, ?, ?, (SELECT id FROM sectors WHERE code = ?), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '
             . ($publishable ? 'UTC_TIMESTAMP()' : 'NULL') . ')'
        )->execute([...self::leakValues($leak, $c), $source['id'], mb_substr($leak->externalId, 0, 191), $publishable ? 'published' : 'pending']);

        return 'new';
    }

    /**
     * Re-applies the current rules to items classified with older rules, a
     * batch at a time: an edited rule file reaches every item over the next
     * runs, without any command line (FTP-only hosting).
     *
     * @return int items reclassified
     */
    public function reclassifyStale(int $limit = 50): int
    {
        $version = $this->classifier->rulesVersion();
        $stale = "facts IS NOT NULL AND (rule_trace IS NULL
                  OR COALESCE(JSON_UNQUOTE(JSON_EXTRACT(rule_trace, '$.rules_version')), '') <> ?)";
        $count = 0;

        $stmt = $this->pdo->prepare("SELECT l.id, l.facts, s.code FROM leaks l JOIN sources s ON s.id = l.source_id WHERE {$stale} ORDER BY l.id DESC LIMIT {$limit}");
        $stmt->execute([$version]);
        foreach ($stmt->fetchAll() as $row) {
            $this->writeLeak((int) $row['id'], LeakFacts::fromArray(json_decode((string) $row['facts'], true)), (string) $row['code'], false);
            $count++;
        }

        $stmt = $this->pdo->prepare("SELECT id, facts FROM intel_items WHERE {$stale} ORDER BY id DESC LIMIT " . max(0, $limit - $count));
        $stmt->execute([$version]);
        foreach ($stmt->fetchAll() as $row) {
            $this->writeIntel((int) $row['id'], Facts::fromArray(json_decode((string) $row['facts'], true)), null);
            $count++;
        }

        return $count;
    }

    private function writeLeak(int $id, LeakFacts $leak, string $sourceCode, bool $publish): void
    {
        $c = $this->classifier->classifyLeak($leak, $sourceCode);
        $this->pdo->prepare(
            'UPDATE leaks SET leak_type = ?, organisation = ?, country = ?,
                    sector_id = (SELECT id FROM sectors WHERE code = ?), actor = ?, records_count = ?,
                    data_classes = ?, severity = ?, confidence = ?, disclosed_at = ?, url = ?, rule_trace = ?, facts = ?'
            . ($publish ? ", status = 'published', published_at = UTC_TIMESTAMP()" : '') . ' WHERE id = ?'
        )->execute([...self::leakValues($leak, $c), $id]);
    }

    /** @param array{sector: ?string, severity: ?string, trace: array<string, mixed>} $c @return list<mixed> */
    private static function leakValues(LeakFacts $leak, array $c): array
    {
        return [
            $leak->type, mb_substr($leak->organisation, 0, 255), $leak->country, $c['sector'],
            $leak->actor === null ? null : mb_substr($leak->actor, 0, 160), $leak->records,
            json_encode($leak->dataClasses, JSON_UNESCAPED_UNICODE), $c['severity'],
            in_array($leak->confidence, LeakFacts::CONFIDENCES, true) ? $leak->confidence : null,
            $leak->disclosedAt, $leak->url === null ? null : mb_substr($leak->url, 0, 2048),
            json_encode($c['trace'], JSON_UNESCAPED_UNICODE), json_encode($leak->toArray(), JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE),
        ];
    }

    private static function traceVersion(mixed $trace): ?string
    {
        $data = is_string($trace) ? json_decode($trace, true) : null;

        return is_array($data) && is_string($data['rules_version'] ?? null) ? $data['rules_version'] : null;
    }

    /** Re-applies the current rules to every stored item. @return int items updated */
    public function reclassify(): int
    {
        $count = 0;
        $rows = $this->pdo->query('SELECT id, facts FROM intel_items WHERE facts IS NOT NULL ORDER BY id');
        foreach ($rows->fetchAll() as $row) {
            $this->writeIntel((int) $row['id'], Facts::fromArray(json_decode((string) $row['facts'], true)), null);
            $count++;
        }
        $rows = $this->pdo->query('SELECT l.id, l.facts, s.code FROM leaks l JOIN sources s ON s.id = l.source_id WHERE l.facts IS NOT NULL ORDER BY l.id');
        foreach ($rows->fetchAll() as $row) {
            $this->writeLeak((int) $row['id'], LeakFacts::fromArray(json_decode((string) $row['facts'], true)), (string) $row['code'], false);
            $count++;
        }

        return $count;
    }

    /**
     * Items still waiting for CVSS (NVD budget was spent), newest first.
     * @return list<array{id: int, facts: Facts}>
     */
    public function awaitingEnrichment(int $limit): array
    {
        $stmt = $this->pdo->prepare(
            "SELECT id, facts FROM intel_items
             WHERE cvss_score IS NULL AND facts IS NOT NULL AND status <> 'rejected'
               AND created_at >= UTC_TIMESTAMP() - INTERVAL 30 DAY
               AND EXISTS (SELECT 1 FROM intel_cves c WHERE c.item_id = intel_items.id)
             ORDER BY id DESC LIMIT {$limit}"
        );
        $stmt->execute();

        return array_map(
            static fn (array $r): array => ['id' => (int) $r['id'], 'facts' => Facts::fromArray(json_decode((string) $r['facts'], true))],
            $stmt->fetchAll(),
        );
    }

    public function updateFacts(int $id, Facts $facts): void
    {
        $this->writeIntel($id, $facts, null);
    }

    // -------------------------------------------------------------------------

    /** @param array{id: int|string, code: string} $source @return array<string, mixed>|null */
    private function findIntel(array $source, Facts $facts): ?array
    {
        $stmt = $this->pdo->prepare(
            'SELECT i.id, i.status, i.facts FROM intel_item_sources s JOIN intel_items i ON i.id = s.item_id
             WHERE s.source_id = ? AND s.external_id = ? LIMIT 1'
        );
        $stmt->execute([$source['id'], $facts->externalId]);
        $row = $stmt->fetch();
        if ($row !== false) {
            return $row;
        }
        if ($facts->cves === [] || !in_array($source['code'], $this->vulnerabilityFeeds, true)) {
            return null;
        }
        $in = implode(',', array_fill(0, count($facts->cves), '?'));
        $feeds = implode(',', array_fill(0, count($this->vulnerabilityFeeds), '?'));
        $stmt = $this->pdo->prepare(
            "SELECT i.id, i.status, i.facts FROM intel_cves c
             JOIN intel_items i ON i.id = c.item_id
             JOIN sources src ON src.id = i.source_id
             WHERE c.cve_id IN ({$in}) AND src.code IN ({$feeds})
             ORDER BY i.id LIMIT 1"
        );
        $stmt->execute([...$facts->cves, ...$this->vulnerabilityFeeds]);
        $row = $stmt->fetch();

        return $row === false ? null : $row;
    }

    /** @param array{id: int|string} $source */
    private function link(int $itemId, array $source, string $externalId): void
    {
        $this->pdo->prepare('INSERT IGNORE INTO intel_item_sources (item_id, source_id, external_id) VALUES (?, ?, ?)')
            ->execute([$itemId, $source['id'], mb_substr($externalId, 0, 191)]);
    }

    /** Inserts (id null) or updates an item and rebuilds its links. Returns the id. */
    private function writeIntel(?int $id, Facts $f, ?string $status, ?int $sourceId = null): int
    {
        $c = $this->classifier->classify($f);
        $values = [
            $f->type, mb_substr($f->title, 0, 500), $f->summary, $f->url === null ? null : mb_substr($f->url, 0, 2048),
            $f->publishedAt, $f->cvss, $f->cvssVector === null ? null : mb_substr($f->cvssVector, 0, 255), $f->epss, $f->epssPercentile, (int) $f->kev, $f->kevDueDate,
            $c['severity'], $c['score'], $c['environment'],
            json_encode($c['trace'], JSON_UNESCAPED_UNICODE), json_encode($f->toArray(), JSON_UNESCAPED_UNICODE),
        ];
        $columns = 'item_type = ?, title = ?, summary = ?, url = ?, source_published_at = ?, cvss_score = ?, cvss_vector = ?,
                    epss_score = ?, epss_percentile = ?, kev = ?, kev_due_date = ?, severity = ?, score = ?, environment = ?,
                    rule_trace = ?, facts = ?';

        if ($id === null) {
            $this->pdo->prepare(
                "INSERT INTO intel_items SET {$columns}, source_id = ?, external_id = ?, status = ?, published_at = "
                . ($status === 'published' ? 'UTC_TIMESTAMP()' : 'NULL')
            )->execute([...$values, $sourceId, mb_substr($f->externalId, 0, 191), $status]);
            $id = (int) $this->pdo->lastInsertId();
        } else {
            $publish = $status === 'published' ? ", status = 'published', published_at = UTC_TIMESTAMP()" : '';
            $this->pdo->prepare("UPDATE intel_items SET {$columns}{$publish} WHERE id = ?")->execute([...$values, $id]);
        }

        $this->replace('intel_cves', $id, 'cve_id', $f->cves);
        $this->replace('intel_cwes', $id, 'cwe_id', $f->cwes);
        $this->pdo->prepare('DELETE FROM intel_categories WHERE item_id = ?')->execute([$id]);
        foreach ($c['categories'] as $code) {
            $this->pdo->prepare('INSERT IGNORE INTO intel_categories (item_id, category_id) SELECT ?, id FROM categories WHERE code = ?')
                ->execute([$id, $code]);
        }
        $this->pdo->prepare('DELETE FROM intel_sectors WHERE item_id = ?')->execute([$id]);
        foreach ($c['sectors'] as $code) {
            $this->pdo->prepare('INSERT IGNORE INTO intel_sectors (item_id, sector_id) SELECT ?, id FROM sectors WHERE code = ?')
                ->execute([$id, $code]);
        }
        $this->replace('intel_countries', $id, 'country', $c['countries']);
        $this->pdo->prepare('DELETE FROM intel_risks WHERE item_id = ?')->execute([$id]);
        foreach ($c['risks'] as $risk) {
            $this->pdo->prepare('INSERT IGNORE INTO intel_risks (item_id, risk_id, rule) SELECT ?, id, ? FROM risks WHERE code = ?')
                ->execute([$id, mb_substr($risk['rule'], 0, 64), $risk['code']]);
        }
        $this->pdo->prepare('DELETE FROM intel_products WHERE item_id = ?')->execute([$id]);
        if ($f->vendor !== null && $f->product !== null) {
            $productId = $this->product($f->vendor, $f->product, $c['environment']);
            $this->pdo->prepare('INSERT IGNORE INTO intel_products (item_id, product_id) VALUES (?, ?)')->execute([$id, $productId]);
        }

        return $id;
    }

    /** @param list<string> $values */
    private function replace(string $table, int $id, string $column, array $values): void
    {
        $this->pdo->prepare("DELETE FROM {$table} WHERE item_id = ?")->execute([$id]);
        foreach (array_unique($values) as $value) {
            $this->pdo->prepare("INSERT IGNORE INTO {$table} (item_id, {$column}) VALUES (?, ?)")->execute([$id, $value]);
        }
    }

    /** Vendors and products are keyed by a CPE-style slug ("palo_alto_networks"). */
    private function product(string $vendor, string $product, string $environment): int
    {
        $slug = static fn (string $s): string => mb_substr(trim((string) preg_replace('/[^a-z0-9]+/', '_', mb_strtolower($s)), '_'), 0, 120);
        $this->pdo->prepare('INSERT INTO vendors (name, cpe_vendor) VALUES (?, ?) ON DUPLICATE KEY UPDATE id = LAST_INSERT_ID(id)')
            ->execute([mb_substr($vendor, 0, 120), $slug($vendor)]);
        $vendorId = (int) $this->pdo->lastInsertId();
        $this->pdo->prepare(
            'INSERT INTO products (vendor_id, name, cpe_product, environment) VALUES (?, ?, ?, ?)
             ON DUPLICATE KEY UPDATE id = LAST_INSERT_ID(id), environment = VALUES(environment)'
        )->execute([$vendorId, mb_substr($product, 0, 160), $slug($product), $environment]);

        return (int) $this->pdo->lastInsertId();
    }
}
