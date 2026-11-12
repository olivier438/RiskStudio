<?php

/**
 * CycloneDX 1.5 SBOM of the PHP application, built from composer.json and
 * composer.lock (no Composer plugin needed). Runtime packages get scope
 * "required", development tools scope "excluded" (not shipped).
 *
 *   php scripts/sbom-composer.php api/ > dist/sbom/riskstudio-api.cdx.json
 */

declare(strict_types=1);

$dir = rtrim($argv[1] ?? 'api', '/');
$composer = json_decode((string) file_get_contents("{$dir}/composer.json"), true, flags: JSON_THROW_ON_ERROR);
$lock = json_decode((string) file_get_contents("{$dir}/composer.lock"), true, flags: JSON_THROW_ON_ERROR);
$version = trim((string) shell_exec('git describe --tags --always 2>/dev/null')) ?: 'dev';

$component = static function (array $p, string $scope): array {
    $c = [
        'type' => 'library',
        'bom-ref' => "pkg:composer/{$p['name']}@{$p['version']}",
        'name' => $p['name'],
        'version' => $p['version'],
        'scope' => $scope,
        'purl' => "pkg:composer/{$p['name']}@{$p['version']}",
    ];
    if (!empty($p['license'])) {
        $c['licenses'] = array_map(static fn (string $id): array => ['license' => ['id' => $id]], (array) $p['license']);
    }
    if (isset($p['dist']['shasum']) && $p['dist']['shasum'] !== '') {
        $c['hashes'] = [['alg' => 'SHA-1', 'content' => $p['dist']['shasum']]];
    }

    return $c;
};

$components = [
    ...array_map(static fn (array $p) => $component($p, 'required'), $lock['packages'] ?? []),
    ...array_map(static fn (array $p) => $component($p, 'excluded'), $lock['packages-dev'] ?? []),
];

// Platform requirements (PHP and extensions) are part of what runs in production.
foreach ($composer['require'] ?? [] as $name => $constraint) {
    $components[] = [
        'type' => $name === 'php' ? 'platform' : 'library',
        'bom-ref' => "platform:{$name}",
        'name' => $name,
        'version' => $constraint,
        'scope' => 'required',
    ];
}

$bom = [
    'bomFormat' => 'CycloneDX',
    'specVersion' => '1.5',
    'serialNumber' => 'urn:uuid:' . vsprintf('%s%s-%s-4%s-%s-%s%s%s', str_split(bin2hex(random_bytes(16)), 4)),
    'version' => 1,
    'metadata' => [
        'timestamp' => gmdate('Y-m-d\TH:i:s\Z'),
        'component' => [
            'type' => 'application',
            'bom-ref' => 'riskstudio-api',
            'name' => 'riskstudio-api',
            'version' => $version,
            'licenses' => [['license' => ['id' => 'MIT']]],
        ],
        'supplier' => ['name' => 'One Circle IT Solutions'],
    ],
    'components' => $components,
];

echo json_encode($bom, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR), PHP_EOL;
