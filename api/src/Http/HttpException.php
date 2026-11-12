<?php

declare(strict_types=1);

namespace RiskStudio\Http;

/** An error whose message is safe to show to the client. */
final class HttpException extends \RuntimeException
{
    public function __construct(
        public readonly int $status,
        public readonly string $errorCode,
        string $message,
    ) {
        parent::__construct($message, $status);
    }

    public static function notFound(string $message = 'Resource not found.'): self
    {
        return new self(404, 'not_found', $message);
    }

    public static function badRequest(string $message): self
    {
        return new self(400, 'bad_request', $message);
    }
}
