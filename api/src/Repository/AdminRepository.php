<?php

declare(strict_types=1);

namespace RiskStudio\Repository;

use PDO;
use RiskStudio\Http\HttpException;

/**
 * Back-office data access (rs_write). Every decision is audited by the
 * controller. Catalogue risks are read-only here: their source of truth is
 * db/catalogue/risks.csv. Community risks (approved proposals) are editable.
 */
final class AdminRepository
{
    public const DECISIONS = ['publish' => 'published', 'reject' => 'rejected', 'archive' => 'archived'];

    public function __construct(private readonly PDO $pdo)
    {
    }

    // ------------------------------------------------------------- queues

    /** @return array<string, int> */
    public function queueCounts(): array
    {
        $q = fn (string $sql): int => (int) $this->pdo->query($sql)->fetchColumn();

        return [
            'intel' => $q("SELECT COUNT(*) FROM intel_items WHERE status = 'pending'"),
            'leaks' => $q("SELECT COUNT(*) FROM leaks WHERE status = 'pending'"),
            'proposals' => $q("SELECT COUNT(*) FROM proposals WHERE status = 'pending'"),
        ];
    }

    /** @return list<array<string, mixed>> */
    public function pendingIntel(int $limit = 100): array
    {
        $rows = $this->pdo->query(
            "SELECT i.id, s.name AS source, i.external_id, i.item_type AS type, i.title, i.summary, i.url,
                    i.cvss_score, i.epss_percentile, i.kev, i.severity, i.score, i.environment, i.rule_trace,
                    i.source_published_at, i.created_at
             FROM intel_items i JOIN sources s ON s.id = i.source_id
             WHERE i.status = 'pending' ORDER BY i.score DESC, i.id DESC LIMIT {$limit}"
        )->fetchAll();

        return array_map(static fn (array $r): array => [
            'id' => (int) $r['id'],
            'source' => $r['source'],
            'external_id' => $r['external_id'],
            'type' => $r['type'],
            'title' => $r['title'],
            'summary' => $r['summary'],
            'url' => $r['url'],
            'cvss' => $r['cvss_score'] === null ? null : (float) $r['cvss_score'],
            'epss_percentile' => $r['epss_percentile'] === null ? null : (float) $r['epss_percentile'],
            'kev' => (bool) $r['kev'],
            'severity' => $r['severity'],
            'score' => $r['score'] === null ? null : (int) $r['score'],
            'environment' => $r['environment'],
            'rules' => json_decode((string) $r['rule_trace'], true)['rules'] ?? [],
            'source_published_at' => Dates::iso($r['source_published_at']),
            'created_at' => Dates::iso($r['created_at']),
        ], $rows);
    }

    /** @return list<array<string, mixed>> */
    public function pendingLeaks(int $limit = 100): array
    {
        $rows = $this->pdo->query(
            "SELECT l.id, s.name AS source, l.leak_type AS type, l.organisation, l.country, sec.code AS sector, l.actor,
                    l.records_count, l.data_classes, l.url, l.disclosed_at, l.created_at
             FROM leaks l JOIN sources s ON s.id = l.source_id LEFT JOIN sectors sec ON sec.id = l.sector_id
             WHERE l.status = 'pending' ORDER BY COALESCE(l.disclosed_at, l.created_at) DESC LIMIT {$limit}"
        )->fetchAll();

        return array_map(static fn (array $r): array => [
            'id' => (int) $r['id'],
            'source' => $r['source'],
            'type' => $r['type'],
            'organisation' => $r['organisation'],
            'country' => $r['country'],
            'sector' => $r['sector'],
            'actor' => $r['actor'],
            'records_count' => $r['records_count'] === null ? null : (int) $r['records_count'],
            'data_classes' => json_decode((string) ($r['data_classes'] ?? '[]'), true) ?: [],
            'url' => $r['url'],
            'disclosed_at' => Dates::iso($r['disclosed_at']),
            'created_at' => Dates::iso($r['created_at']),
        ], $rows);
    }

    /** @return list<array<string, mixed>> */
    public function proposals(string $status = 'pending', int $limit = 100): array
    {
        $stmt = $this->pdo->prepare(
            "SELECT p.*, a.display_name AS reviewer FROM proposals p LEFT JOIN admins a ON a.id = p.reviewed_by
             WHERE p.status = ? ORDER BY p.created_at DESC LIMIT {$limit}"
        );
        $stmt->execute([$status]);

        return array_map(static fn (array $r): array => [
            'id' => (int) $r['id'],
            'kind' => $r['kind'],
            'payload' => json_decode((string) $r['payload'], true),
            'submitter_name' => $r['submitter_name'],
            'submitter_email' => $r['submitter_email'],
            'status' => $r['status'],
            'admin_note' => $r['admin_note'],
            'reviewer' => $r['reviewer'],
            'reviewed_at' => Dates::iso($r['reviewed_at']),
            'created_at' => Dates::iso($r['created_at']),
        ], $stmt->fetchAll());
    }

    // ------------------------------------------------------------- decisions

    /** Publishes, rejects or archives a feed item. Returns the previous status. */
    public function decideFeed(string $table, int $id, string $decision): string
    {
        if (!in_array($table, ['intel_items', 'leaks'], true) || !isset(self::DECISIONS[$decision])) {
            throw HttpException::badRequest('decision must be publish, reject or archive.');
        }
        $stmt = $this->pdo->prepare("SELECT status FROM {$table} WHERE id = ?");
        $stmt->execute([$id]);
        $previous = $stmt->fetchColumn();
        if ($previous === false) {
            throw HttpException::notFound('Unknown item.');
        }
        $this->pdo->prepare(
            "UPDATE {$table} SET status = ?, published_at = IF(? = 'published', COALESCE(published_at, UTC_TIMESTAMP()), published_at)
             WHERE id = ?"
        )->execute([self::DECISIONS[$decision], self::DECISIONS[$decision], $id]);

        return (string) $previous;
    }

    /** @return array{proposal: array<string, mixed>, risk_code: ?string} */
    public function decideProposal(int $id, string $decision, int $adminId, ?string $note): array
    {
        if (!in_array($decision, ['approve', 'reject'], true)) {
            throw HttpException::badRequest('decision must be approve or reject.');
        }
        $this->pdo->beginTransaction();
        try {
            $stmt = $this->pdo->prepare("SELECT * FROM proposals WHERE id = ? AND status = 'pending' FOR UPDATE");
            $stmt->execute([$id]);
            $proposal = $stmt->fetch();
            if ($proposal === false) {
                throw HttpException::notFound('Unknown or already reviewed proposal.');
            }
            $riskCode = null;
            if ($decision === 'approve' && $proposal['kind'] === 'risk') {
                $riskCode = $this->createCommunityRisk((int) $proposal['id'], json_decode((string) $proposal['payload'], true) ?: []);
            }
            $this->pdo->prepare(
                'UPDATE proposals SET status = ?, admin_note = ?, reviewed_by = ?, reviewed_at = UTC_TIMESTAMP() WHERE id = ?'
            )->execute([$decision === 'approve' ? 'approved' : 'rejected', $note === null ? null : mb_substr($note, 0, 1000), $adminId, $id]);
            $this->pdo->commit();
        } catch (\Throwable $e) {
            $this->pdo->rollBack();
            throw $e;
        }

        return ['proposal' => ['id' => $id, 'kind' => $proposal['kind']], 'risk_code' => $riskCode];
    }

    /** @param array<string, mixed> $payload */
    private function createCommunityRisk(int $proposalId, array $payload): string
    {
        $data = RiskInput::validate($payload, $this->pdo);
        $next = (int) $this->pdo->query(
            "SELECT COALESCE(MAX(CAST(SUBSTRING(code, 7) AS UNSIGNED)), 0) + 1 FROM risks WHERE code LIKE 'R-COM-%'"
        )->fetchColumn();
        $code = sprintf('R-COM-%02d', $next);
        $this->pdo->prepare(
            "INSERT INTO risks (code, title, category_id, threat, scenario, measures, impact, cia_confidentiality,
                                cia_integrity, cia_availability, environment, origin, proposal_id, status, published_at)
             VALUES (?, ?, (SELECT id FROM categories WHERE code = ?), ?, ?, ?, ?, ?, ?, ?, ?, 'community', ?, 'published', UTC_TIMESTAMP())"
        )->execute([
            $code, $data['title'], $data['category'], $data['threat'], $data['scenario'], $data['measures'], $data['impact'],
            (int) $data['cia']['C'], (int) $data['cia']['I'], (int) $data['cia']['A'], $data['environment'], $proposalId,
        ]);
        $this->setSectors((int) $this->pdo->lastInsertId(), $data['sectors']);

        return $code;
    }

    // ------------------------------------------------------------- risks

    /** @return list<array<string, mixed>> */
    public function risks(?string $origin = null): array
    {
        $sql = 'SELECT r.code, r.title, c.code AS category, r.impact, r.environment, r.origin, r.status, r.updated_at
                FROM risks r JOIN categories c ON c.id = r.category_id';
        $stmt = $this->pdo->prepare($sql . ($origin !== null ? ' WHERE r.origin = ?' : '') . ' ORDER BY r.origin DESC, r.code');
        $stmt->execute($origin !== null ? [$origin] : []);

        return array_map(static fn (array $r): array => ['impact' => (int) $r['impact'], 'updated_at' => Dates::iso($r['updated_at'])] + $r, $stmt->fetchAll());
    }

    /** @return array<string, mixed> */
    public function communityRisk(string $code): array
    {
        $stmt = $this->pdo->prepare(
            "SELECT r.*, c.code AS category FROM risks r JOIN categories c ON c.id = r.category_id WHERE r.code = ?"
        );
        $stmt->execute([$code]);
        $r = $stmt->fetch();
        if ($r === false) {
            throw HttpException::notFound('Unknown risk.');
        }
        if ($r['origin'] !== 'community') {
            throw new HttpException(409, 'catalogue_risk', 'Les risques du catalogue se modifient dans db/catalogue/risks.csv.');
        }
        $sectors = $this->pdo->prepare('SELECT s.code FROM risk_sectors rs JOIN sectors s ON s.id = rs.sector_id WHERE rs.risk_id = ?');
        $sectors->execute([$r['id']]);

        return [
            'code' => $r['code'], 'title' => $r['title'], 'category' => $r['category'], 'threat' => $r['threat'],
            'scenario' => $r['scenario'], 'measures' => $r['measures'], 'impact' => (int) $r['impact'],
            'cia' => ($r['cia_confidentiality'] ? 'C' : '') . ($r['cia_integrity'] ? 'I' : '') . ($r['cia_availability'] ? 'A' : ''),
            'environment' => $r['environment'], 'sectors' => $sectors->fetchAll(PDO::FETCH_COLUMN), 'status' => $r['status'],
        ];
    }

    /** @param array<string, mixed> $payload */
    public function updateCommunityRisk(string $code, array $payload): void
    {
        $current = $this->communityRisk($code);
        $data = RiskInput::validate($payload, $this->pdo);
        $status = $payload['status'] ?? $current['status'];
        if (!in_array($status, ['published', 'archived'], true)) {
            throw HttpException::badRequest('status must be published or archived.');
        }
        $this->pdo->prepare(
            'UPDATE risks SET title = ?, category_id = (SELECT id FROM categories WHERE code = ?), threat = ?, scenario = ?,
                    measures = ?, impact = ?, cia_confidentiality = ?, cia_integrity = ?, cia_availability = ?,
                    environment = ?, status = ? WHERE code = ?'
        )->execute([
            $data['title'], $data['category'], $data['threat'], $data['scenario'], $data['measures'], $data['impact'],
            (int) $data['cia']['C'], (int) $data['cia']['I'], (int) $data['cia']['A'], $data['environment'], $status, $code,
        ]);
        $id = (int) $this->pdo->query('SELECT id FROM risks WHERE code = ' . $this->pdo->quote($code))->fetchColumn();
        $this->setSectors($id, $data['sectors']);
    }

    /** @param list<string> $sectors */
    private function setSectors(int $riskId, array $sectors): void
    {
        $this->pdo->prepare('DELETE FROM risk_sectors WHERE risk_id = ?')->execute([$riskId]);
        foreach ($sectors as $code) {
            $this->pdo->prepare('INSERT IGNORE INTO risk_sectors (risk_id, sector_id) SELECT ?, id FROM sectors WHERE code = ?')
                ->execute([$riskId, $code]);
        }
    }

    // ------------------------------------------------------------- sources and health

    /** @return list<array<string, mixed>> */
    public function sources(): array
    {
        $rows = $this->pdo->query(
            "SELECT s.id, s.code, s.name, s.kind, s.url, s.authoritative, s.enabled, s.poll_minutes, s.last_run_at, s.last_success_at,
                    (SELECT r.status FROM collector_runs r WHERE r.source_id = s.id ORDER BY r.id DESC LIMIT 1) AS last_status,
                    (SELECT r.error FROM collector_runs r WHERE r.source_id = s.id ORDER BY r.id DESC LIMIT 1) AS last_error,
                    (SELECT COALESCE(SUM(r.items_new), 0) FROM collector_runs r WHERE r.source_id = s.id
                       AND r.started_at >= UTC_TIMESTAMP() - INTERVAL 1 DAY) AS new_24h,
                    (SELECT COUNT(*) FROM collector_runs r WHERE r.source_id = s.id AND r.status = 'failed'
                       AND r.started_at >= UTC_TIMESTAMP() - INTERVAL 1 DAY) AS failures_24h
             FROM sources s WHERE s.code NOT LIKE 'DEV\\_%' AND s.code NOT LIKE 'TST\\_%' AND s.code NOT LIKE 'TEST\\_%'
             ORDER BY s.name"
        )->fetchAll();

        return array_map(static fn (array $r): array => [
            'code' => $r['code'], 'name' => $r['name'], 'kind' => $r['kind'], 'url' => $r['url'],
            'authoritative' => (bool) $r['authoritative'], 'enabled' => (bool) $r['enabled'],
            'poll_minutes' => (int) $r['poll_minutes'],
            'last_run_at' => Dates::iso($r['last_run_at']), 'last_success_at' => Dates::iso($r['last_success_at']),
            'last_status' => $r['last_status'], 'last_error' => $r['last_error'],
            'new_24h' => (int) $r['new_24h'], 'failures_24h' => (int) $r['failures_24h'],
        ], $rows);
    }

    /** @param array<string, mixed> $changes @return array<string, mixed> previous values */
    public function updateSource(string $code, array $changes): array
    {
        $stmt = $this->pdo->prepare('SELECT enabled, authoritative FROM sources WHERE code = ?');
        $stmt->execute([$code]);
        $previous = $stmt->fetch();
        if ($previous === false) {
            throw HttpException::notFound('Unknown source.');
        }
        foreach (['enabled', 'authoritative'] as $field) {
            if (array_key_exists($field, $changes)) {
                if (!is_bool($changes[$field])) {
                    throw HttpException::badRequest("{$field} must be a boolean.");
                }
                $this->pdo->prepare("UPDATE sources SET {$field} = ? WHERE code = ?")->execute([(int) $changes[$field], $code]);
            }
        }

        return ['enabled' => (bool) $previous['enabled'], 'authoritative' => (bool) $previous['authoritative']];
    }

    /** @return array<string, mixed> */
    public function statistics(): array
    {
        $byStatus = fn (string $table): array => array_map('intval', $this->pdo
            ->query("SELECT status, COUNT(*) FROM {$table} GROUP BY status")->fetchAll(PDO::FETCH_KEY_PAIR));

        return [
            'risks' => $byStatus('risks'),
            'risks_by_origin' => array_map('intval', $this->pdo->query("SELECT origin, COUNT(*) FROM risks WHERE status = 'published' GROUP BY origin")->fetchAll(PDO::FETCH_KEY_PAIR)),
            'intel' => $byStatus('intel_items'),
            'leaks' => $byStatus('leaks'),
            'proposals' => $byStatus('proposals'),
            'intel_by_severity' => array_map('intval', $this->pdo->query(
                "SELECT COALESCE(severity, 'unknown'), COUNT(*) FROM intel_items WHERE status = 'published' GROUP BY severity"
            )->fetchAll(PDO::FETCH_KEY_PAIR)),
            'top_linked_risks' => $this->pdo->query(
                "SELECT r.code, r.title, COUNT(*) AS items FROM intel_risks ir
                 JOIN intel_items i ON i.id = ir.item_id AND i.status = 'published'
                 JOIN risks r ON r.id = ir.risk_id GROUP BY r.id ORDER BY items DESC LIMIT 10"
            )->fetchAll(),
            'runs_7d' => $this->pdo->query(
                "SELECT DATE(started_at) AS day, COUNT(*) AS runs, SUM(status = 'failed') AS failed, SUM(items_new) AS items_new
                 FROM collector_runs WHERE started_at >= UTC_DATE() - INTERVAL 6 DAY GROUP BY DATE(started_at) ORDER BY day"
            )->fetchAll(),
        ];
    }

    /** @return list<array<string, mixed>> */
    public function audit(int $limit = 100): array
    {
        $rows = $this->pdo->query(
            "SELECT l.id, l.actor_type, a.display_name AS actor, l.action, l.entity, l.entity_id, l.details, l.created_at
             FROM audit_log l LEFT JOIN admins a ON a.id = l.actor_id AND l.actor_type = 'admin'
             ORDER BY l.id DESC LIMIT {$limit}"
        )->fetchAll();

        return array_map(static fn (array $r): array => [
            'id' => (int) $r['id'], 'actor_type' => $r['actor_type'], 'actor' => $r['actor'], 'action' => $r['action'],
            'entity' => $r['entity'], 'entity_id' => $r['entity_id'],
            'details' => json_decode((string) $r['details'], true), 'created_at' => Dates::iso($r['created_at']),
        ], $rows);
    }
}
