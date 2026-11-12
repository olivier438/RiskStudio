<?php

declare(strict_types=1);

namespace RiskStudio\Catalogue;

final class ImportException extends \RuntimeException
{
    /** @param list<string> $errors */
    public function __construct(public readonly array $errors)
    {
        parent::__construct(count($errors) . " catalogue error(s):\n  " . implode("\n  ", array_slice($errors, 0, 50)));
    }
}
