<?php

declare(strict_types=1);

namespace RiskStudio\Collector;

/**
 * Deterministic classification: same facts + same rules = same result.
 * Every decision appends a rule identifier to the trace shown as "Pourquoi ?".
 *
 * Score (0 to 100), documented in db/rules/README.md:
 *   CVSS x 6 (max 60), or a severity-based value when CVSS is unknown
 *   + 25 if known exploited (KEV, EUVD exploited, CERT-FR alert)
 *   + EPSS percentile x 15 (max 15)
 *   + 5 if used in ransomware campaigns
 */
final class Classifier
{
    private const SEVERITY_BASE = ['critical' => 54, 'high' => 42, 'medium' => 30, 'low' => 12];

    public function __construct(private readonly Rules $rules)
    {
    }

    /**
     * @return array{severity: ?string, score: int, environment: string, categories: list<string>,
     *               sectors: list<string>, risks: list<array{code: string, rule: string}>, trace: array<string, mixed>}
     */
    public function classify(Facts $f): array
    {
        $trace = array_map(static fn (string $s): string => 'source.' . strtolower($s), $f->sources);

        // ---- severity
        $severity = null;
        if ($f->cvss !== null) {
            $severity = match (true) {
                $f->cvss >= 9.0 => 'critical',
                $f->cvss >= 7.0 => 'high',
                $f->cvss >= 4.0 => 'medium',
                $f->cvss > 0.0 => 'low',
                default => null,
            };
            $severity !== null && $trace[] = "cvss.{$severity}";
        }
        if ($f->severityHint !== null && ($severity === null || self::rank($f->severityHint) > self::rank($severity))) {
            $severity = $f->severityHint;
            $trace[] = "hint.{$severity}";
        }
        if ($severity === null && $f->kev) {
            $severity = 'high';
            $trace[] = 'kev.no_cvss->high';
        }

        // ---- exploitation signals
        $exploited = $f->kev || $f->type === 'exploitation';
        if ($f->kev) {
            $trace[] = 'kev.listed';
        }
        if ($f->ransomwareUse) {
            $trace[] = 'kev.ransomware';
        }
        if ($f->epssPercentile !== null && $f->epssPercentile >= 0.99) {
            $trace[] = 'epss.top1pct';
        } elseif ($f->epssPercentile !== null && $f->epssPercentile >= 0.90) {
            $trace[] = 'epss.top10pct';
        }

        // ---- score
        $base = $f->cvss !== null ? $f->cvss * 6 : (float) (self::SEVERITY_BASE[$severity ?? 'medium'] ?? 30);
        $parts = [
            'base' => round($base, 1),
            'exploited' => $exploited ? 25 : 0,
            'epss' => $f->epssPercentile !== null ? (int) round($f->epssPercentile * 15) : 0,
            'ransomware' => $f->ransomwareUse ? 5 : 0,
        ];
        $score = (int) min(100, round(array_sum($parts)));

        // ---- categories
        $categories = [];
        foreach ($f->cwes as $cwe) {
            if (isset($this->rules->cweCategories[$cwe])) {
                $categories[] = $this->rules->cweCategories[$cwe];
                $trace[] = "cwe.{$cwe}->{$this->rules->cweCategories[$cwe]}";
            }
        }
        $text = mb_strtolower($f->title . ' ' . ($f->summary ?? '') . ' ' . implode(' ', $f->keywords));
        foreach ($this->rules->keywords as $k) {
            if (str_contains($text, $k['pattern'])) {
                $categories[] = $k['category'];
                $trace[] = 'keyword.' . str_replace(' ', '_', $k['pattern']) . "->{$k['category']}";
            }
        }
        $categories = array_values(array_unique($categories));
        if ($categories === [] && in_array($f->type, ['vulnerability', 'exploitation', 'advisory'], true)) {
            $categories = ['VULN'];
            $trace[] = 'default.category->VULN';
        }

        // ---- environment and sectors
        $environment = 'IT';
        $sectors = [];
        if ($f->otFlag) {
            $environment = 'OT';
            $trace[] = 'certfr.scada->OT';
        }
        $vendor = mb_strtolower($f->vendor ?? '');
        $product = mb_strtolower($f->product ?? '');
        foreach ($this->rules->environment as $e) {
            $haystack = $e['kind'] === 'vendor' ? $vendor : $product;
            if (!Rules::matches($haystack, $e['pattern'])) {
                continue;
            }
            $environment = self::widen($environment, $e['environment'], $f->otFlag);
            $sectors = [...$sectors, ...$e['sectors']];
            $trace[] = "{$e['kind']}." . str_replace(' ', '_', $e['pattern']) . "->{$e['environment']}";
        }
        $sectors = array_values(array_unique($sectors));
        if ($environment !== 'IT' && !in_array('OT', $categories, true)) {
            $categories[] = 'OT';
        }

        // ---- links to catalogue risks
        $risks = [];
        $productText = $f->productText();
        foreach ($this->rules->riskLinks as $link) {
            $hit = match ($link['condition']) {
                'kev' => $f->kev,
                'kev_ransomware' => $f->ransomwareUse,
                'env' => $link['value'] === 'OT' ? $environment !== 'IT' : $environment === $link['value'],
                'cwe' => in_array($link['value'], $f->cwes, true),
                'product' => Rules::matches($productText, mb_strtolower($link['value'])),
                'text' => Rules::matches($text, mb_strtolower($link['value'])),
                default => false,
            };
            if ($hit && !isset($risks[$link['risk']])) {
                $rule = $link['condition'] . ($link['value'] !== '' ? '.' . str_replace(' ', '_', $link['value']) : '');
                $risks[$link['risk']] = ['code' => $link['risk'], 'rule' => $rule];
                $trace[] = "{$rule}->risk.{$link['risk']}";
            }
        }

        return [
            'severity' => $severity,
            'score' => $score,
            'environment' => $environment,
            'categories' => $categories,
            'sectors' => $sectors,
            'risks' => array_values($risks),
            'trace' => ['rules' => array_values(array_unique($trace)), 'score' => $parts, 'rules_version' => $this->rules->version],
        ];
    }

    /**
     * Severity of a leak, from the exposed data classes (db/rules/leak_data.csv):
     * for each class the most specific (longest) matching pattern decides, then
     * the most serious class wins; a class no rule knows counts as low. A source
     * flag "sensitive" raises it to at least high. Without any data class, a
     * ransomware claim is high (exfiltration before encryption is the norm),
     * anything else stays unknown.
     *
     * @return array{sector: ?string, severity: ?string, trace: array<string, mixed>}
     */
    public function classifyLeak(LeakFacts $l, string $sourceCode): array
    {
        $trace = ['source.' . strtolower($sourceCode)];
        $sector = null;
        if ($l->activity !== null && isset($this->rules->ransomwareSectors[mb_strtolower($l->activity)])) {
            $sector = $this->rules->ransomwareSectors[mb_strtolower($l->activity)];
            $trace[] = 'activity.' . str_replace(' ', '_', mb_strtolower($l->activity)) . "->{$sector}";
        }

        $severity = null;
        foreach ($l->dataClasses as $class) {
            $text = Rules::normalise($class);
            $found = null;
            foreach ($this->rules->leakData as $rule) {
                // The most specific (longest) matching pattern decides: "carte de fidélité" beats "numéro de carte".
                if (mb_strlen($rule['pattern']) > mb_strlen($found['pattern'] ?? '') && Rules::matches($text, $rule['pattern'])) {
                    $found = $rule;
                }
            }
            if ($found === null) {
                $severity ??= 'low';
                continue;
            }
            if (self::rank($found['severity']) > self::rank($severity ?? '')) {
                $severity = $found['severity'];
            }
            $trace[] = 'data.' . str_replace(' ', '_', $found['pattern']) . "->{$found['severity']}";
        }
        if ($severity === 'low') {
            $trace[] = 'data.other->low';
        }
        if ($l->sensitive && self::rank($severity ?? '') < self::rank('high')) {
            $severity = 'high';
            $trace[] = 'hint.sensitive->high';
        }
        if ($severity === null && $l->type === 'ransomware') {
            $severity = 'high';
            $trace[] = 'type.ransomware->high';
        }
        if ($l->confidence !== null) {
            $trace[] = "confidence.{$l->confidence}";
        }

        return [
            'sector' => $sector,
            'severity' => $severity,
            'trace' => ['rules' => array_values(array_unique($trace)), 'rules_version' => $this->rules->version],
        ];
    }

    public function rulesVersion(): string
    {
        return $this->rules->version;
    }

    private static function rank(string $severity): int
    {
        return ['low' => 1, 'medium' => 2, 'high' => 3, 'critical' => 4][$severity] ?? 0;
    }

    /** IT + OT evidence gives BOTH; an explicit SCADA flag stays OT. */
    private static function widen(string $current, string $rule, bool $scadaFlag): string
    {
        if ($scadaFlag) {
            return 'OT';
        }
        if ($current === 'IT') {
            return $rule;
        }

        return $current === $rule ? $current : ($rule === 'OT' ? 'OT' : $current);
    }
}
