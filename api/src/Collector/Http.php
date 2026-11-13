<?php

declare(strict_types=1);

namespace RiskStudio\Collector;

/**
 * Minimal HTTP client for the collector: curl when available (shared hosting
 * always has it), strict timeouts, size cap, HTTPS only, identified agent.
 */
class Http
{
    public const USER_AGENT = 'Noroshi-Collector/5.0 (+https://www.noroshi.be)';
    private const MAX_BYTES = 8 * 1024 * 1024;

    public function __construct(private readonly int $timeoutSeconds = 20)
    {
    }

    /**
     * @param array<string, string> $headers
     * @return array{status: int, body: string, content_type: string}
     */
    public function get(string $url, array $headers = []): array
    {
        if (!str_starts_with($url, 'https://')) {
            throw new \InvalidArgumentException("Only HTTPS URLs are fetched: {$url}");
        }
        $lines = ['Accept: application/json, application/xml;q=0.9, */*;q=0.5'];
        foreach ($headers as $name => $value) {
            $lines[] = "{$name}: {$value}";
        }

        $ch = curl_init($url);
        $body = '';
        curl_setopt_array($ch, [
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 3,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_TIMEOUT => $this->timeoutSeconds,
            CURLOPT_USERAGENT => self::USER_AGENT,
            CURLOPT_HTTPHEADER => $lines,
            CURLOPT_ENCODING => '',
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_WRITEFUNCTION => static function ($ch, string $chunk) use (&$body): int {
                $body .= $chunk;

                return strlen($body) > self::MAX_BYTES ? 0 : strlen($chunk);
            },
        ]);
        $ok = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $type = (string) curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
        $error = curl_error($ch);
        curl_close($ch);

        if ($ok === false) {
            throw new \RuntimeException(strlen($body) > self::MAX_BYTES ? "Response too large: {$url}" : "HTTP error on {$url}: {$error}");
        }

        return ['status' => $status, 'body' => $body, 'content_type' => $type];
    }

    /** @param array<string, string> $headers @return array<mixed> */
    public function json(string $url, array $headers = []): array
    {
        $response = $this->get($url, $headers);
        if ($response['status'] !== 200) {
            throw new \RuntimeException("HTTP {$response['status']} on {$url}");
        }
        $data = json_decode($response['body'], true);
        if (!is_array($data)) {
            throw new \RuntimeException("Invalid JSON from {$url}");
        }

        return $data;
    }
}
