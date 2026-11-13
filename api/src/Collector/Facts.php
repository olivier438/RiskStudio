<?php

declare(strict_types=1);

namespace RiskStudio\Collector;

/**
 * What a source says about a vulnerability, advisory or campaign: normalised,
 * never interpreted. Stored as JSON (`intel_items.facts`) so classification
 * can be replayed at any time.
 */
final class Facts
{
    /** @param list<string> $cves @param list<string> $cwes @param list<string> $keywords @param list<string> $sources */
    public function __construct(
        public string $externalId,
        public string $type,
        public string $title,
        public ?string $summary = null,
        public ?string $url = null,
        public ?string $publishedAt = null,
        public array $cves = [],
        public array $cwes = [],
        public ?float $cvss = null,
        public ?string $cvssVector = null,
        public ?float $epss = null,
        public ?float $epssPercentile = null,
        public bool $kev = false,
        public ?string $kevDueDate = null,
        public bool $ransomwareUse = false,
        public ?string $vendor = null,
        public ?string $product = null,
        public bool $otFlag = false,
        public ?string $severityHint = null,
        public array $keywords = [],
        public array $sources = [],
        /** Countries stated by the source (a CCB warning concerns Belgium). @var list<string> */
        public array $countries = [],
    ) {
    }

    /**
     * Combines what another source says about the same vulnerability.
     * Monotonic: known exploitation is never forgotten, scores keep the most
     * informative value, lists are unioned.
     */
    public function merge(self $other): void
    {
        $this->summary ??= $other->summary;
        $this->url ??= $other->url;
        $this->publishedAt = self::earliest($this->publishedAt, $other->publishedAt);
        $this->cves = self::union($this->cves, $other->cves);
        $this->cwes = self::union($this->cwes, $other->cwes);
        if ($other->cvss !== null && ($this->cvss === null || $other->cvss > $this->cvss)) {
            $this->cvss = $other->cvss;
            $this->cvssVector = $other->cvssVector;
        }
        $this->epss = $other->epss ?? $this->epss;
        $this->epssPercentile = $other->epssPercentile ?? $this->epssPercentile;
        $this->kev = $this->kev || $other->kev;
        $this->kevDueDate ??= $other->kevDueDate;
        $this->ransomwareUse = $this->ransomwareUse || $other->ransomwareUse;
        $this->vendor ??= $other->vendor;
        $this->product ??= $other->product;
        $this->otFlag = $this->otFlag || $other->otFlag;
        $this->severityHint ??= $other->severityHint;
        $this->keywords = self::union($this->keywords, $other->keywords);
        $this->sources = self::union($this->sources, $other->sources);
        $this->countries = self::union($this->countries, $other->countries);
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return get_object_vars($this);
    }

    /** @param array<string, mixed> $data */
    public static function fromArray(array $data): self
    {
        $facts = new self((string) $data['externalId'], (string) $data['type'], (string) $data['title']);
        foreach (get_object_vars($facts) as $key => $_) {
            if (array_key_exists($key, $data)) {
                $facts->{$key} = $data[$key];
            }
        }

        return $facts;
    }

    /** "Vendor Product", lower-cased, for keyword rules. */
    public function productText(): string
    {
        return mb_strtolower(trim(($this->vendor ?? '') . ' ' . ($this->product ?? '')));
    }

    /** @param list<string> $a @param list<string> $b @return list<string> */
    private static function union(array $a, array $b): array
    {
        return array_values(array_unique([...$a, ...$b]));
    }

    private static function earliest(?string $a, ?string $b): ?string
    {
        if ($a === null || $b === null) {
            return $a ?? $b;
        }

        return min($a, $b);
    }
}
