<?php

declare(strict_types=1);

namespace RiskStudio\Collector;

/** HTTP client of the diagnostic: records every request and caps their number. */
final class ProbeHttp extends Http
{
    /** @var list<array{url: string, status: int, content_type: string, bytes: int, ms: int, format: ?string, error: ?string}> */
    public array $log = [];

    public function __construct(int $timeoutSeconds, private readonly int $maxRequests)
    {
        parent::__construct($timeoutSeconds);
    }

    public function get(string $url, array $headers = []): array
    {
        if (count($this->log) >= $this->maxRequests) {
            throw new \RuntimeException('Diagnostic request limit reached');
        }
        $started = microtime(true);
        try {
            $response = parent::get($url, $headers);
        } catch (\Throwable $e) {
            $this->log[] = ['url' => $url, 'status' => 0, 'content_type' => '', 'bytes' => 0,
                'ms' => (int) round((microtime(true) - $started) * 1000), 'format' => null, 'error' => mb_substr($e->getMessage(), 0, 200)];
            throw $e;
        }
        $this->log[] = ['url' => $url, 'status' => $response['status'], 'content_type' => $response['content_type'],
            'bytes' => strlen($response['body']), 'ms' => (int) round((microtime(true) - $started) * 1000),
            'format' => Probe::format($response['body']), 'error' => null];

        return $response;
    }
}
