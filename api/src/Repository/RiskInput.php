<?php

declare(strict_types=1);

namespace RiskStudio\Repository;

use PDO;
use RiskStudio\Http\HttpException;

/**
 * Validation of a risk written by a person (public proposal, community risk
 * edit). Same rules as the catalogue importer. Messages are in French: they
 * are shown in the proposal form.
 */
final class RiskInput
{
    /**
     * @param array<string, mixed> $p
     * @return array{title: string, category: string, threat: string, scenario: string, measures: string,
     *               impact: int, cia: array{C: bool, I: bool, A: bool}, environment: string, sectors: list<string>}
     */
    public static function validate(array $p, PDO $pdo): array
    {
        $errors = [];
        $text = static function (string $field, int $min, int $max) use ($p, &$errors): string {
            $value = self::clean($p[$field] ?? '');
            if (mb_strlen($value) < $min || mb_strlen($value) > $max) {
                $errors[$field] = "Entre {$min} et {$max} caractères.";
            }

            return $value;
        };

        $data = [
            'title' => $text('title', 5, 255),
            'threat' => $text('threat', 3, 255),
            'scenario' => $text('scenario', 10, 2000),
            'measures' => $text('measures', 5, 2000),
        ];

        $category = is_string($p['category'] ?? null) ? strtoupper($p['category']) : '';
        $stmt = $pdo->prepare('SELECT COUNT(*) FROM categories WHERE code = ?');
        $stmt->execute([$category]);
        if ((int) $stmt->fetchColumn() !== 1) {
            $errors['category'] = 'Catégorie inconnue.';
        }

        $impact = $p['impact'] ?? null;
        if (!is_int($impact) || $impact < 1 || $impact > 5) {
            $errors['impact'] = 'Impact entre 1 et 5.';
        }

        $cia = is_string($p['cia'] ?? null) ? strtoupper($p['cia']) : '';
        if (!preg_match('/^C?I?A?$/', $cia) || $cia === '') {
            $errors['cia'] = 'Au moins un critère : C, I ou A.';
        }

        $environment = $p['environment'] ?? 'IT';
        if (!in_array($environment, ['IT', 'OT', 'BOTH'], true)) {
            $errors['environment'] = 'IT, OT ou BOTH.';
        }

        $sectors = $p['sectors'] ?? [];
        if (!is_array($sectors) || count($sectors) > 10 || array_filter($sectors, static fn ($s) => !is_string($s)) !== []) {
            $errors['sectors'] = 'Liste de secteurs invalide.';
            $sectors = [];
        } elseif ($sectors !== []) {
            $in = implode(',', array_fill(0, count($sectors), '?'));
            $stmt = $pdo->prepare("SELECT COUNT(*) FROM sectors WHERE code IN ({$in})");
            $stmt->execute(array_values($sectors));
            if ((int) $stmt->fetchColumn() !== count(array_unique($sectors))) {
                $errors['sectors'] = 'Secteur inconnu.';
            }
        }

        if ($errors !== []) {
            throw new ValidationException($errors);
        }

        return $data + [
            'category' => $category,
            'impact' => $impact,
            'cia' => ['C' => str_contains($cia, 'C'), 'I' => str_contains($cia, 'I'), 'A' => str_contains($cia, 'A')],
            'environment' => $environment,
            'sectors' => array_values(array_unique($sectors)),
        ];
    }

    /** Trims, collapses spaces, drops control characters. Never HTML: the UI escapes. */
    public static function clean(mixed $value): string
    {
        if (!is_string($value)) {
            return '';
        }
        $value = preg_replace('/[^\P{C}\n]/u', '', $value) ?? '';

        return trim(preg_replace('/[ \t]+/u', ' ', $value) ?? '');
    }
}
