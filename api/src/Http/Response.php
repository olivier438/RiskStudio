<?php

declare(strict_types=1);

namespace RiskStudio\Http;

final class Response
{
    /** Security headers sent with every API response. */
    public const SECURITY_HEADERS = [
        'X-Content-Type-Options' => 'nosniff',
        'Referrer-Policy' => 'strict-origin-when-cross-origin',
        'Content-Security-Policy' => "default-src 'none'; frame-ancestors 'none'",
        'Cross-Origin-Resource-Policy' => 'same-origin',
    ];

    /** @param array<string, string> $headers */
    public function __construct(
        public readonly int $status = 200,
        public readonly string $body = '',
        public readonly array $headers = [],
    ) {
    }

    public static function json(mixed $data, int $status = 200, int $maxAge = 0): self
    {
        $body = json_encode(
            $data,
            JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR | JSON_PRESERVE_ZERO_FRACTION,
        );

        return new self($status, $body, [
            'Content-Type' => 'application/json; charset=utf-8',
            'Cache-Control' => $maxAge > 0 ? "public, max-age={$maxAge}" : 'no-cache',
        ]);
    }

    public static function error(int $status, string $code, string $message): self
    {
        return self::json(['error' => ['code' => $code, 'message' => $message]], $status);
    }

    /**
     * Adds a strong ETag and answers 304 when the client already holds it.
     * This keeps the 60-second polling of the front end almost free.
     */
    public function withETag(Request $request): self
    {
        if ($this->status !== 200) {
            return $this;
        }
        $etag = '"' . substr(hash('sha256', $this->body), 0, 32) . '"';
        $headers = $this->headers + ['ETag' => $etag];

        $ifNoneMatch = $request->header('if-none-match');
        if ($ifNoneMatch !== null && in_array($etag, array_map('trim', explode(',', $ifNoneMatch)), true)) {
            unset($headers['Content-Type']);

            return new self(304, '', $headers);
        }

        return new self($this->status, $this->body, $headers);
    }

    public function withHeader(string $name, string $value): self
    {
        return new self($this->status, $this->body, [$name => $value] + $this->headers);
    }

    public function send(): void
    {
        http_response_code($this->status);
        foreach (self::SECURITY_HEADERS + $this->headers as $name => $value) {
            header("{$name}: {$value}");
        }
        if ($this->status !== 304 && $this->status !== 204) {
            echo $this->body;
        }
    }
}
