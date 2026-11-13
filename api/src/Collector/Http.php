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

    /**
     * @param bool $publicOnly for addresses typed by an administrator (custom
     *   sources): every hop must pass PublicAddress, requests are pinned to the
     *   checked IP and redirects are followed one by one, each checked again.
     */
    public function __construct(private readonly int $timeoutSeconds = 20, private readonly bool $publicOnly = false)
    {
    }

    /**
     * @param array<string, string> $headers
     * @return array{status: int, body: string, content_type: string, location: ?string}
     */
    public function get(string $url, array $headers = []): array
    {
        if (!$this->publicOnly) {
            return $this->request($url, $headers, null);
        }
        for ($hop = 0; $hop <= 3; $hop++) {
            try {
                $address = PublicAddress::check($url);
            } catch (\InvalidArgumentException $e) {
                throw new \RuntimeException($e->getMessage() . " ({$url})");
            }
            $response = $this->request($url, $headers, $address['resolve']);
            if (!in_array($response['status'], [301, 302, 303, 307, 308], true) || $response['location'] === null) {
                return $response;
            }
            $url = self::absolute($url, $response['location']);
        }

        throw new \RuntimeException("Too many redirects: {$url}");
    }

    /** Resolves a Location header against the URL that sent it. */
    private static function absolute(string $base, string $location): string
    {
        if (preg_match('#^https?://#i', $location)) {
            return $location;
        }
        $p = parse_url($base);
        $origin = 'https://' . ($p['host'] ?? '');

        return str_starts_with($location, '/') ? $origin . $location : $origin . rtrim(dirname($p['path'] ?? '/'), '/') . '/' . $location;
    }

    /**
     * @param array<string, string> $headers
     * @return array{status: int, body: string, content_type: string, location: ?string}
     */
    private function request(string $url, array $headers, ?string $resolve): array
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
        $location = null;
        curl_setopt_array($ch, [
            CURLOPT_FOLLOWLOCATION => $resolve === null,
            CURLOPT_MAXREDIRS => 3,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_TIMEOUT => $this->timeoutSeconds,
            CURLOPT_USERAGENT => self::USER_AGENT,
            CURLOPT_HTTPHEADER => $lines,
            CURLOPT_ENCODING => '',
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_HEADERFUNCTION => static function ($ch, string $line) use (&$location): int {
                if (stripos($line, 'location:') === 0) {
                    $location = trim(substr($line, 9));
                }

                return strlen($line);
            },
            CURLOPT_WRITEFUNCTION => static function ($ch, string $chunk) use (&$body): int {
                $body .= $chunk;

                return strlen($body) > self::MAX_BYTES ? 0 : strlen($chunk);
            },
        ]);
        if ($resolve !== null) {
            curl_setopt($ch, CURLOPT_RESOLVE, [$resolve]);
        }
        $ok = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $type = (string) curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
        $error = curl_error($ch);
        curl_close($ch);

        if ($ok === false) {
            throw new \RuntimeException(strlen($body) > self::MAX_BYTES ? "Response too large: {$url}" : "HTTP error on {$url}: {$error}");
        }

        return ['status' => $status, 'body' => $body, 'content_type' => $type, 'location' => $location];
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
