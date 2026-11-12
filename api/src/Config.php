<?php

declare(strict_types=1);

namespace RiskStudio;

/**
 * Minimal `.env` reader. No dependency, no variable expansion, no magic.
 * Real environment variables take precedence over the file.
 */
final class Config
{
    /** @param array<string, string> $values */
    private function __construct(private readonly array $values)
    {
    }

    public static function fromFile(string $path): self
    {
        $values = [];
        if (is_readable($path)) {
            $values = self::parse((string) file_get_contents($path));
        }

        return new self($values);
    }

    /** @param array<string, string> $values */
    public static function fromArray(array $values): self
    {
        return new self($values);
    }

    /** @return array<string, string> */
    public static function parse(string $content): array
    {
        $values = [];
        foreach (preg_split('/\R/', $content) ?: [] as $line) {
            $line = trim($line);
            if ($line === '' || str_starts_with($line, '#') || !str_contains($line, '=')) {
                continue;
            }
            [$key, $value] = array_map('trim', explode('=', $line, 2));
            if (!preg_match('/^[A-Z][A-Z0-9_]*$/', $key)) {
                continue;
            }
            $quoted = strlen($value) >= 2
                && ($value[0] === '"' || $value[0] === "'")
                && $value[-1] === $value[0];
            $values[$key] = $quoted ? substr($value, 1, -1) : $value;
        }

        return $values;
    }

    public function get(string $key, ?string $default = null): ?string
    {
        $env = getenv($key);
        if ($env !== false && $env !== '') {
            return $env;
        }

        return $this->values[$key] ?? $default;
    }

    public function require(string $key): string
    {
        $value = $this->get($key);
        if ($value === null || $value === '') {
            throw new \RuntimeException("Missing configuration key: {$key}");
        }

        return $value;
    }

    public function isDev(): bool
    {
        return $this->get('APP_ENV', 'prod') === 'dev';
    }
}
