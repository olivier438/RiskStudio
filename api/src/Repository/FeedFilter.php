<?php

declare(strict_types=1);

namespace RiskStudio\Repository;

use RiskStudio\Http\HttpException;
use RiskStudio\Http\Request;

/** Filters shared by the threat intelligence feed and the data leaks feed. */
final class FeedFilter
{
    public const SEVERITIES = ['low', 'medium', 'high', 'critical'];
    public const LEAK_TYPES = ['ransomware', 'breach', 'exposure'];

    public function __construct(
        public readonly ?string $search = null,
        public readonly ?string $environment = null,
        public readonly ?string $severityMin = null,
        public readonly bool $kevOnly = false,
        public readonly ?string $source = null,
        public readonly ?string $category = null,
        public readonly ?string $sector = null,
        public readonly ?string $leakType = null,
        public readonly ?string $country = null,
        public readonly ?string $since = null,
        public readonly int $page = 1,
        public readonly int $perPage = 50,
    ) {
    }

    public static function fromRequest(Request $request): self
    {
        $search = $request->query('q');
        if ($search !== null && mb_strlen($search) > 120) {
            throw HttpException::badRequest('Search text is limited to 120 characters.');
        }

        $environment = $request->query('env');
        if ($environment !== null) {
            $environment = strtoupper($environment);
            if (!in_array($environment, RiskFilter::ENVIRONMENTS, true)) {
                throw HttpException::badRequest('env must be IT or OT.');
            }
        }

        $severity = $request->query('severity_min');
        if ($severity !== null && !in_array($severity, self::SEVERITIES, true)) {
            throw HttpException::badRequest('severity_min must be low, medium, high or critical.');
        }

        $leakType = $request->query('type');
        if ($leakType !== null && !in_array($leakType, self::LEAK_TYPES, true)) {
            throw HttpException::badRequest('type must be ransomware, breach or exposure.');
        }

        $country = $request->query('country');
        if ($country !== null) {
            if (!preg_match('/^[A-Za-z]{2}$/', $country)) {
                throw HttpException::badRequest('country must be an ISO 3166 alpha-2 code.');
            }
            $country = strtoupper($country);
        }

        return new self(
            search: $search,
            environment: $environment,
            severityMin: $severity,
            kevOnly: $request->query('kev') === '1',
            source: self::code($request->query('source'), 'source'),
            category: self::code($request->query('category'), 'category'),
            sector: self::code($request->query('sector'), 'sector'),
            leakType: $leakType,
            country: $country,
            since: Dates::fromQuery($request->query('since'), 'since'),
            page: $request->queryInt('page', 1, 1, 10_000),
            perPage: $request->queryInt('per_page', 50, 1, 200),
        );
    }

    /** @return list<string> severities at or above the minimum */
    public function severities(): array
    {
        $index = array_search($this->severityMin, self::SEVERITIES, true);

        return $index === false ? self::SEVERITIES : array_slice(self::SEVERITIES, (int) $index);
    }

    private static function code(?string $value, string $name): ?string
    {
        if ($value === null) {
            return null;
        }
        if (!preg_match('/^[A-Za-z0-9_]{1,32}$/', $value)) {
            throw HttpException::badRequest("Invalid {$name} code.");
        }

        return strtoupper($value);
    }
}
