<?php

declare(strict_types=1);

namespace RiskStudio\Collector;

/** What a source says about a data leak or a ransomware claim. */
final class LeakFacts
{
    /** Confidence levels a source may state (Bonjour la fuite: 🟢 🟠 🔴). */
    public const CONFIDENCES = ['confirmed', 'claimed', 'untrusted'];

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
        public ?string $confidence = null,
        public bool $sensitive = false,
    ) {
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return get_object_vars($this);
    }

    /** @param array<string, mixed> $data */
    public static function fromArray(array $data): self
    {
        $leak = new self((string) $data['externalId'], (string) $data['type'], (string) $data['organisation']);
        foreach (get_object_vars($leak) as $key => $_) {
            if (array_key_exists($key, $data)) {
                $leak->{$key} = $data[$key];
            }
        }

        return $leak;
    }
}
