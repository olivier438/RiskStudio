<?php

declare(strict_types=1);

namespace RiskStudio\Collector;

/**
 * Classification rules, loaded from the CSV files of db/rules. Editing a file
 * and running `collect.php --reclassify` applies the change to every item.
 */
final class Rules
{
    /** @var array<string, string> CWE => category */
    public array $cweCategories = [];
    /** @var list<array{kind: string, pattern: string, environment: string, sectors: list<string>}> */
    public array $environment = [];
    /** @var list<array{pattern: string, category: string}> */
    public array $keywords = [];
    /** @var list<array{condition: string, value: string, risk: string}> */
    public array $riskLinks = [];
    /** @var array<string, string> ransomware.live activity => sector */
    public array $ransomwareSectors = [];
    public string $version = '';

    public static function load(string $dir): self
    {
        $rules = new self();
        $hash = hash_init('sha256');
        foreach (['cwe_categories', 'environment', 'keywords', 'risk_links', 'ransomware_sectors'] as $name) {
            $path = "{$dir}/{$name}.csv";
            if (!is_readable($path)) {
                throw new \RuntimeException("Missing rules file {$path}");
            }
            hash_update($hash, (string) file_get_contents($path));
            foreach (self::rows($path) as $r) {
                match ($name) {
                    'cwe_categories' => $rules->cweCategories[$r['cwe']] = $r['category'],
                    'environment' => $rules->environment[] = [
                        'kind' => $r['kind'],
                        'pattern' => mb_strtolower($r['pattern']),
                        'environment' => $r['environment'],
                        'sectors' => $r['sectors'] === '' ? [] : explode('|', $r['sectors']),
                    ],
                    'keywords' => $rules->keywords[] = ['pattern' => mb_strtolower($r['pattern']), 'category' => $r['category']],
                    'risk_links' => $rules->riskLinks[] = ['condition' => $r['condition'], 'value' => $r['value'], 'risk' => $r['risk_code']],
                    'ransomware_sectors' => $rules->ransomwareSectors[mb_strtolower($r['activity'])] = $r['sector'],
                };
            }
        }
        // Short fingerprint of the rule files, stored in every rule trace.
        $rules->version = substr(hash_final($hash), 0, 12);

        return $rules;
    }

    /** @return list<array<string, string>> */
    private static function rows(string $path): array
    {
        $fh = fopen($path, 'rb');
        $header = fgetcsv($fh, null, ';', '"', '');
        $rows = [];
        while (($row = fgetcsv($fh, null, ';', '"', '')) !== false) {
            if ($row === [null] || str_starts_with((string) $row[0], '#')) {
                continue;
            }
            $rows[] = array_map('trim', array_combine($header, array_pad($row, count($header), '')));
        }
        fclose($fh);

        return $rows;
    }

    /** Word match: "abb" matches "ABB Ltd" but not "Abbott". */
    public static function matches(string $haystack, string $pattern): bool
    {
        return $pattern !== '' && preg_match('/(?<![\p{L}\p{N}])' . preg_quote($pattern, '/') . '(?![\p{L}\p{N}])/u', $haystack) === 1;
    }
}
