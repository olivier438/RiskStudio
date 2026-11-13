<?php

declare(strict_types=1);

namespace RiskStudio\Repository;

use PDO;
use RiskStudio\Http\HttpException;

/**
 * Editorial alerts: what matters right now (a global outage, a mass
 * campaign), written by the administrator. The public side reads the
 * v_public_alerts view only (active alerts); the admin side writes the table.
 */
final class AlertRepository
{
    public const KINDS = ['outage', 'attack', 'vulnerability', 'other'];
    public const LEVELS = ['info', 'warning', 'critical'];

    public function __construct(private readonly PDO $pdo)
    {
    }

    /** Active alerts, most serious first. @return list<array<string, mixed>> */
    public function active(): array
    {
        $rows = $this->pdo->query(
            "SELECT * FROM v_public_alerts ORDER BY FIELD(level, 'critical', 'warning', 'info'), starts_at DESC, id DESC LIMIT 20"
        )->fetchAll();

        return array_map(self::hydrate(...), $rows);
    }

    /** Latest alerts, active or not, for the administration. @return list<array<string, mixed>> */
    public function recent(int $limit = 100): array
    {
        $rows = $this->pdo->query(
            "SELECT a.*, (a.status = 'published' AND a.starts_at <= UTC_TIMESTAMP()
                          AND (a.ends_at IS NULL OR a.ends_at > UTC_TIMESTAMP())) AS active
             FROM alerts a ORDER BY a.starts_at DESC, a.id DESC LIMIT {$limit}"
        )->fetchAll();

        return array_map(static fn (array $r): array => self::hydrate($r) + [
            'status' => $r['status'],
            'active' => (bool) $r['active'],
            'created_at' => Dates::iso($r['created_at']),
        ], $rows);
    }

    /** @param array<string, mixed> $a validated input */
    public function create(array $a, int $adminId): int
    {
        $this->pdo->prepare(
            'INSERT INTO alerts (kind, level, title, summary, url, starts_at, ends_at, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
        )->execute([$a['kind'], $a['level'], $a['title'], $a['summary'], $a['url'], $a['starts_at'], $a['ends_at'], $adminId]);

        return (int) $this->pdo->lastInsertId();
    }

    /** @param array<string, mixed> $a validated input @return array<string, mixed> previous values */
    public function update(int $id, array $a): array
    {
        $previous = $this->find($id);
        $this->pdo->prepare(
            "UPDATE alerts SET kind = ?, level = ?, title = ?, summary = ?, url = ?, starts_at = ?, ends_at = ?, status = 'published' WHERE id = ?"
        )->execute([$a['kind'], $a['level'], $a['title'], $a['summary'], $a['url'], $a['starts_at'], $a['ends_at'], $id]);

        return $previous;
    }

    /** Ends an alert now: it leaves the public page, stays in the history. @return array<string, mixed> */
    public function close(int $id): array
    {
        $previous = $this->find($id);
        $this->pdo->prepare("UPDATE alerts SET status = 'archived', ends_at = LEAST(COALESCE(ends_at, UTC_TIMESTAMP()), UTC_TIMESTAMP()) WHERE id = ?")
            ->execute([$id]);

        return $previous;
    }

    /**
     * @param array<string, mixed> $body
     * @return array{kind: string, level: string, title: string, summary: ?string, url: ?string, starts_at: string, ends_at: ?string}
     * @throws ValidationException
     */
    public static function input(array $body): array
    {
        $errors = [];
        $string = static fn (string $key): string => trim(is_string($body[$key] ?? null) ? $body[$key] : '');
        $kind = $string('kind');
        if (!in_array($kind, self::KINDS, true)) {
            $errors['kind'] = 'Type : panne, attaque, vulnérabilité ou autre.';
        }
        $level = $string('level');
        if (!in_array($level, self::LEVELS, true)) {
            $errors['level'] = 'Niveau : info, attention ou critique.';
        }
        $title = $string('title');
        if (mb_strlen($title) < 3 || mb_strlen($title) > 200) {
            $errors['title'] = 'Titre de 3 à 200 caractères.';
        }
        $summary = $string('summary');
        if (mb_strlen($summary) > 600) {
            $errors['summary'] = '600 caractères au maximum.';
        }
        $url = $string('url');
        if ($url !== '' && (!str_starts_with($url, 'https://') || strlen($url) > 2048 || filter_var($url, FILTER_VALIDATE_URL) === false)) {
            $errors['url'] = 'Lien HTTPS valide, ou vide.';
        }
        $starts = $ends = null;
        try {
            $starts = $string('starts_at') === '' ? gmdate('Y-m-d H:i:s') : Dates::fromQuery($string('starts_at'), 'starts_at');
        } catch (HttpException) {
            $errors['starts_at'] = 'Date de début invalide.';
        }
        try {
            $ends = $string('ends_at') === '' ? null : Dates::fromQuery($string('ends_at'), 'ends_at');
        } catch (HttpException) {
            $errors['ends_at'] = 'Date de fin invalide.';
        }
        if ($starts !== null && $ends !== null && $ends <= $starts) {
            $errors['ends_at'] = 'La fin doit suivre le début.';
        }
        if ($errors !== []) {
            throw new ValidationException($errors);
        }

        return ['kind' => $kind, 'level' => $level, 'title' => $title, 'summary' => $summary === '' ? null : $summary,
            'url' => $url === '' ? null : $url, 'starts_at' => (string) $starts, 'ends_at' => $ends];
    }

    /** @return array<string, mixed> */
    private function find(int $id): array
    {
        $stmt = $this->pdo->prepare('SELECT kind, level, title, summary, url, starts_at, ends_at, status FROM alerts WHERE id = ?');
        $stmt->execute([$id]);

        return $stmt->fetch() ?: throw HttpException::notFound('Unknown alert.');
    }

    /** @param array<string, mixed> $r @return array<string, mixed> */
    private static function hydrate(array $r): array
    {
        return [
            'id' => (int) $r['id'],
            'kind' => $r['kind'],
            'level' => $r['level'],
            'title' => $r['title'],
            'summary' => $r['summary'],
            'url' => $r['url'],
            'starts_at' => Dates::iso($r['starts_at']),
            'ends_at' => Dates::iso($r['ends_at']),
            'updated_at' => Dates::iso($r['updated_at']),
        ];
    }
}
