<?php

declare(strict_types=1);

namespace RiskStudio\Repository;

use RiskStudio\Http\HttpException;

/** 422 with one message per invalid field, for forms. */
final class ValidationException extends \RuntimeException
{
    /** @param array<string, string> $fields */
    public function __construct(public readonly array $fields)
    {
        parent::__construct('Validation failed.');
    }

    public function toHttp(): HttpException
    {
        return new HttpException(422, 'validation', 'Certains champs sont invalides.');
    }
}
