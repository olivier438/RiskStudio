<?php

declare(strict_types=1);

namespace RiskStudio\Collector;

/** What a source says about a data leak or a ransomware claim. */
final class LeakFacts
{
    /** @param list<string> $dataClasses */
    public function __construct(
        public string $externalId,
        public string $type,
        public string $organisation,
        public ?string $country = null,
        public ?string $activity = null,
        public ?string $actor = null,
        public ?int $records = null,
        public array $dataClasses = [],
        public ?string $disclosedAt = null,
        public ?string $url = null,
        public ?string $domain = null,
    ) {
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return get_object_vars($this);
    }
}
