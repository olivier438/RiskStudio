<?php

declare(strict_types=1);

namespace RiskStudio\Http;

final class Request
{
    /** Request bodies are small JSON documents: anything bigger is refused. */
    public const MAX_BODY = 32 * 1024;

    /**
     * @param array<string, string|array<mixed>> $query
     * @param array<string, string> $headers  lower-cased header names
     * @param array<string, string> $params   route parameters, filled by the router
     */
    public function __construct(
        public readonly string $method,
        public readonly string $path,
        public readonly array $query = [],
        public readonly array $headers = [],
        public readonly string $body = '',
        public readonly array $params = [],
        public readonly string $ip = '',
    ) {
    }

    public static function fromGlobals(string $basePath = ''): self
    {
        $uri = (string) ($_SERVER['REQUEST_URI'] ?? '/');
        $path = (string) (parse_url($uri, PHP_URL_PATH) ?? '/');

        $basePath = rtrim($basePath, '/');
        if ($basePath !== '' && ($path === $basePath || str_starts_with($path, $basePath . '/'))) {
            $path = substr($path, strlen($basePath));
        }

        $headers = [];
        foreach ($_SERVER as $key => $value) {
            if (str_starts_with((string) $key, 'HTTP_')) {
                $name = strtolower(str_replace('_', '-', substr((string) $key, 5)));
                $headers[$name] = (string) $value;
            }
        }
        if (isset($_SERVER['CONTENT_TYPE'])) {
            $headers['content-type'] = (string) $_SERVER['CONTENT_TYPE'];
        }

        return new self(
            strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET')),
            self::normalisePath($path),
            $_GET,
            $headers,
            (string) file_get_contents('php://input', false, null, 0, self::MAX_BODY + 1),
            [],
            (string) ($_SERVER['REMOTE_ADDR'] ?? ''),
        );
    }

    public static function normalisePath(string $path): string
    {
        $path = '/' . trim($path, '/');

        return preg_replace('#/+#', '/', $path) ?? '/';
    }

    /** @param array<string, string> $params */
    public function withParams(array $params): self
    {
        return new self($this->method, $this->path, $this->query, $this->headers, $this->body, $params, $this->ip);
    }

    public function cookie(string $name): ?string
    {
        foreach (explode(';', $this->header('cookie') ?? '') as $pair) {
            [$key, $value] = array_pad(explode('=', trim($pair), 2), 2, '');
            if ($key === $name && $value !== '') {
                return urldecode($value);
            }
        }

        return null;
    }

    /**
     * Decoded JSON object body.
     * @return array<string, mixed>
     */
    public function json(): array
    {
        if (strlen($this->body) > self::MAX_BODY) {
            throw new HttpException(413, 'payload_too_large', 'Request body too large.');
        }
        if (!str_contains($this->header('content-type') ?? '', 'application/json')) {
            throw new HttpException(415, 'unsupported_media_type', 'Expected application/json.');
        }
        $data = json_decode($this->body, true);
        if (!is_array($data) || array_is_list($data) && $data !== []) {
            throw HttpException::badRequest('Invalid JSON object.');
        }

        return $data;
    }

    public function header(string $name): ?string
    {
        return $this->headers[strtolower($name)] ?? null;
    }

    /** Scalar query parameter, trimmed. Arrays are ignored on purpose. */
    public function query(string $key): ?string
    {
        $value = $this->query[$key] ?? null;
        if (!is_string($value)) {
            return null;
        }
        $value = trim($value);

        return $value === '' ? null : $value;
    }

    public function queryInt(string $key, int $default, int $min, int $max): int
    {
        $value = $this->query($key);
        if ($value === null || !preg_match('/^-?\d{1,9}$/', $value)) {
            return $default;
        }

        return max($min, min($max, (int) $value));
    }
}
