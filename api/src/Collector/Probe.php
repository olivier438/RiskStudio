<?php

declare(strict_types=1);

namespace RiskStudio\Collector;

/**
 * Admin diagnostic: tests a source, or any HTTPS address, from the production
 * server itself. Some publishers filter hosting providers (ransomware.live
 * answered 404 to the hosting while answering 200 elsewhere): this tells a
 * blocked feed from a broken parser without guessing.
 *
 * A source test runs the real parser on the live answer and stores nothing.
 * An address test only reports metadata (status, type, size, format), never
 * the body, and refuses private or reserved addresses (no SSRF towards the
 * hosting's internal network). Redirects are reported, not followed.
 */
final class Probe
{
    private const TIMEOUT = 15;
    private const MAX_BYTES = 2 * 1024 * 1024;

    /** @return array<string, mixed> */
    public function source(string $code, string $url): array
    {
        $http = new ProbeHttp(self::TIMEOUT, 3);
        $impl = Collector::sourceFor($code);
        $report = ['code' => $code, 'url' => $url, 'ok' => false, 'items' => null, 'sample' => [], 'error' => null];
        if ($impl === null) {
            return $report + ['requests' => [], 'verdict' => 'no_parser', 'message' => 'Aucun lecteur n’existe encore pour cette source : rien à tester.'];
        }
        try {
            $result = $impl->fetch($http, $url, [], new \DateTimeImmutable('-30 days', new \DateTimeZone('UTC')));
            $report['ok'] = true;
            $report['items'] = count($result['intel']) + count($result['leaks']);
            $report['sample'] = array_slice([
                ...array_map(static fn (Facts $f): string => $f->title, $result['intel']),
                ...array_map(static fn (LeakFacts $l): string => $l->organisation, $result['leaks']),
            ], 0, 5);
        } catch (\Throwable $e) {
            $report['error'] = mb_substr($e->getMessage(), 0, 300);
        }
        $first = $http->log[0] ?? null;

        return $report + ['requests' => $http->log] + self::verdict($first, $report['ok'], $report['items'], $report['error'], true);
    }

    /** @return array<string, mixed> */
    public function url(string $url): array
    {
        $parts = parse_url($url);
        if ($parts === false || ($parts['scheme'] ?? '') !== 'https' || empty($parts['host']) || isset($parts['user']) || isset($parts['pass'])
            || (isset($parts['port']) && $parts['port'] !== 443) || strlen($url) > 500) {
            return self::refused($url, 'Adresse refusée : HTTPS uniquement, port 443, sans identifiants, 500 caractères au maximum.');
        }
        $host = strtolower(trim($parts['host'], '[]'));
        $ips = self::resolve($host);
        if ($ips === []) {
            return self::refused($url, "Le nom {$host} ne se résout pas depuis ce serveur.", 'unreachable');
        }
        foreach ($ips as $ip) {
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
                return self::refused($url, 'Adresse refusée : elle mène à un réseau privé ou réservé.');
            }
        }

        $started = microtime(true);
        $body = '';
        $location = null;
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            // Pinned to the checked address: no DNS rebinding between check and request.
            CURLOPT_RESOLVE => [$host . ':443:' . (str_contains($ips[0], ':') ? "[{$ips[0]}]" : $ips[0])],
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_TIMEOUT => self::TIMEOUT,
            CURLOPT_USERAGENT => Http::USER_AGENT,
            CURLOPT_HTTPHEADER => ['Accept: application/json, application/xml;q=0.9, */*;q=0.5'],
            CURLOPT_ENCODING => '',
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_HEADERFUNCTION => static function ($ch, string $line) use (&$location): int {
                if (stripos($line, 'location:') === 0) {
                    $location = mb_substr(trim(substr($line, 9)), 0, 500);
                }

                return strlen($line);
            },
            CURLOPT_WRITEFUNCTION => static function ($ch, string $chunk) use (&$body): int {
                $body .= $chunk;

                return strlen($body) > self::MAX_BYTES ? 0 : strlen($chunk);
            },
        ]);
        $ok = curl_exec($ch);
        $request = [
            'url' => $url,
            'status' => (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE),
            'content_type' => (string) curl_getinfo($ch, CURLINFO_CONTENT_TYPE),
            'bytes' => strlen($body),
            'ms' => (int) round((microtime(true) - $started) * 1000),
            'format' => self::format($body),
            'error' => $ok === false && strlen($body) <= self::MAX_BYTES ? mb_substr(curl_error($ch), 0, 200) : null,
        ];
        curl_close($ch);

        return ['url' => $url, 'ok' => $request['status'] === 200, 'location' => $location, 'requests' => [$request]]
            + self::verdict($request, false, null, $request['error'], false, $location);
    }

    /** Guesses the format from the first bytes: json, rss, atom, xml, html or other. */
    public static function format(string $body): ?string
    {
        if ($body === '') {
            return null;
        }
        $start = strtolower(ltrim(substr($body, 0, 512), "\xEF\xBB\xBF \t\r\n"));

        return match (true) {
            str_starts_with($start, '{'), str_starts_with($start, '[') => 'json',
            str_contains($start, '<rss') => 'rss',
            str_contains($start, '<feed') => 'atom',
            str_starts_with($start, '<!doctype html'), str_contains($start, '<html') => 'html',
            str_starts_with($start, '<?xml') => 'xml',
            default => 'other',
        };
    }

    /**
     * @param array<string, mixed>|null $r first request
     * @return array{verdict: string, message: string}
     */
    private static function verdict(?array $r, bool $parsed, ?int $items, ?string $error, bool $feed, ?string $location = null): array
    {
        $status = (int) ($r['status'] ?? 0);
        if ($parsed) {
            return ['verdict' => 'works', 'message' => sprintf('Fonctionne depuis ce serveur : %d élément%s lu%s sur les 30 derniers jours.',
                $items, $items > 1 ? 's' : '', $items > 1 ? 's' : '')];
        }
        if ($status === 0) {
            return ['verdict' => 'unreachable', 'message' => 'Aucune réponse : délai dépassé, DNS ou connexion refusée.' . ($error ? " Détail : {$error}" : '')];
        }
        if ($status >= 300 && $status < 400) {
            return ['verdict' => 'redirect', 'message' => "Redirection {$status}" . ($location ? " vers {$location}" : '') . ' : tester cette nouvelle adresse.'];
        }
        if (in_array($status, [401, 403, 404, 406, 429, 451, 503], true)) {
            $hint = $status === 404 ? ' (ou l’adresse a changé : vérifier depuis un navigateur)' : '';

            return ['verdict' => 'blocked', 'message' => "Réponse {$status} : le site refuse probablement les requêtes venant de cet hébergeur{$hint}."];
        }
        if ($status === 200 && $feed) {
            return ['verdict' => 'format', 'message' => 'Réponse reçue, mais le contenu n’a pas le format attendu.' . ($error ? " Détail : {$error}" : '')];
        }
        if ($status === 200) {
            return ['verdict' => 'reachable', 'message' => sprintf('Joignable depuis ce serveur : %s, %s octets.', $r['format'] ?? 'vide', number_format((int) $r['bytes'], 0, ',', ' '))];
        }

        return ['verdict' => 'error', 'message' => "Réponse {$status}." . ($error ? " Détail : {$error}" : '')];
    }

    /** @return list<string> */
    private static function resolve(string $host): array
    {
        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            return [$host];
        }
        $ips = gethostbynamel($host) ?: [];
        foreach (@dns_get_record($host, DNS_AAAA) ?: [] as $record) {
            if (isset($record['ipv6'])) {
                $ips[] = $record['ipv6'];
            }
        }

        return array_values(array_unique($ips));
    }

    /** @return array<string, mixed> */
    private static function refused(string $url, string $message, string $verdict = 'refused'): array
    {
        return ['url' => mb_substr($url, 0, 500), 'ok' => false, 'location' => null, 'requests' => [], 'verdict' => $verdict, 'message' => $message];
    }
}
