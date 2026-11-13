<?php

declare(strict_types=1);

namespace RiskStudio\Collector;

/**
 * Checks that an address an administrator typed (custom source, diagnostic)
 * leads to the public Internet: HTTPS, port 443, no credentials, and every
 * resolved IP outside private and reserved ranges. The caller pins the
 * request to the returned IP (CURLOPT_RESOLVE), so DNS cannot change between
 * the check and the request.
 */
final class PublicAddress
{
    /**
     * @return array{host: string, ip: string, resolve: string}
     * @throws \InvalidArgumentException with a message for the administrator
     */
    public static function check(string $url): array
    {
        $parts = parse_url($url);
        if ($parts === false || ($parts['scheme'] ?? '') !== 'https' || empty($parts['host']) || isset($parts['user']) || isset($parts['pass'])
            || (isset($parts['port']) && $parts['port'] !== 443) || strlen($url) > 500) {
            throw new \InvalidArgumentException('Adresse refusée : HTTPS uniquement, port 443, sans identifiants, 500 caractères au maximum.');
        }
        $host = strtolower(trim($parts['host'], '[]'));
        $ips = self::resolve($host);
        if ($ips === []) {
            throw new \InvalidArgumentException("Le nom {$host} ne se résout pas depuis ce serveur.");
        }
        foreach ($ips as $ip) {
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
                throw new \InvalidArgumentException('Adresse refusée : elle mène à un réseau privé ou réservé.');
            }
        }

        return ['host' => $host, 'ip' => $ips[0], 'resolve' => $host . ':443:' . (str_contains($ips[0], ':') ? "[{$ips[0]}]" : $ips[0])];
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
}
