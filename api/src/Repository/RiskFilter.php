<?php

declare(strict_types=1);

namespace RiskStudio\Repository;

use RiskStudio\Http\HttpException;
use RiskStudio\Http\Request;

/**
 * Catalogue filter, built to double as an "environment profile".
 * V1: filled from the query string. V2: filled from the user's saved profile.
 */
final class RiskFilter
{
    public const ENVIRONMENTS = ['IT', 'OT'];

    public function __construct(
        public readonly ?string $search = null,
        public readonly ?string $category = null,
        public readonly ?string $sector = null,
        public readonly ?string $environment = null,
        public readonly ?string $framework = null,
        public readonly ?int $impactMin = null,
        public readonly ?string $control = null,
        public readonly bool $editorialOnly = false,
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
            if (!in_array($environment, self::ENVIRONMENTS, true)) {
                throw HttpException::badRequest('env must be IT or OT.');
            }
        }

        $impact = $request->query('impact_min');

        $control = $request->query('control');
        if ($control !== null && !preg_match('/^[A-Za-z0-9.\-]{1,40}$/', $control)) {
            throw HttpException::badRequest('Invalid control reference.');
        }

        if ($control !== null && $request->query('framework') === null) {
            throw HttpException::badRequest('control requires framework.');
        }

        $mapping = $request->query('mapping');
        if ($mapping !== null && $mapping !== 'editorial' && $mapping !== 'all') {
            throw HttpException::badRequest('mapping must be editorial or all.');
        }

        return new self(
            search: $search,
            category: self::code($request->query('category'), 'category'),
            sector: self::code($request->query('sector'), 'sector'),
            environment: $environment,
            framework: self::code($request->query('framework'), 'framework'),
            impactMin: $impact === null ? null : $request->queryInt('impact_min', 1, 1, 5),
            control: $control,
            editorialOnly: $mapping === 'editorial',
            page: $request->queryInt('page', 1, 1, 10_000),
            perPage: $request->queryInt('per_page', 50, 1, 200),
        );
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
