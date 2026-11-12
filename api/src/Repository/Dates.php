<?php

declare(strict_types=1);

namespace RiskStudio\Repository;

use RiskStudio\Http\HttpException;

/** Database timestamps are UTC `Y-m-d H:i:s`; the API speaks ISO 8601 with Z. */
final class Dates
{
    public static function iso(?string $value): ?string
    {
        if ($value === null || $value === '') {
            return null;
        }

        return str_replace(' ', 'T', $value) . (strlen($value) === 10 ? '' : 'Z');
    }

    /** Parses an ISO 8601 query parameter into a UTC database timestamp. */
    public static function fromQuery(?string $value, string $name): ?string
    {
        if ($value === null) {
            return null;
        }
        if (strlen($value) > 40 || !preg_match('/^\d{4}-\d{2}-\d{2}([T ][\d:.]+(Z|[+-]\d{2}:?\d{2})?)?$/', $value)) {
            throw HttpException::badRequest("{$name} must be an ISO 8601 date.");
        }
        try {
            $date = new \DateTimeImmutable($value, new \DateTimeZone('UTC'));
        } catch (\Exception) {
            throw HttpException::badRequest("{$name} must be an ISO 8601 date.");
        }

        return $date->setTimezone(new \DateTimeZone('UTC'))->format('Y-m-d H:i:s');
    }
}
