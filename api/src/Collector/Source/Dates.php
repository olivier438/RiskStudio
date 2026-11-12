<?php

declare(strict_types=1);

namespace RiskStudio\Collector\Source;

/** Parses the date formats used by the sources into UTC `Y-m-d H:i:s`. */
final class Dates
{
    public static function utc(?string $value): ?string
    {
        if ($value === null || trim($value) === '') {
            return null;
        }
        try {
            // EUVD uses "Nov 11, 2026, 4:55:47 AM" (UTC): PHP parses it natively.
            $date = new \DateTimeImmutable(trim($value), new \DateTimeZone('UTC'));
        } catch (\Exception) {
            return null;
        }

        return $date->setTimezone(new \DateTimeZone('UTC'))->format('Y-m-d H:i:s');
    }

    public static function date(?string $value): ?string
    {
        $utc = self::utc($value);

        return $utc === null ? null : substr($utc, 0, 10);
    }
}
