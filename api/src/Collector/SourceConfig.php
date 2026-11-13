<?php

declare(strict_types=1);

namespace RiskStudio\Collector;

use RiskStudio\Repository\ValidationException;

/**
 * Settings of a source added from the administration (no code): an RSS or
 * Atom feed, the view it feeds, a default country and keyword filters.
 * Stored as JSON in sources.config.
 */
final class SourceConfig
{
    /** View fed by the source => item type of its entries. */
    public const FAMILIES = ['vulnerability' => 'advisory', 'threat' => 'incident'];
    public const MAX_WORDS = 30;

    /** @param list<string> $include @param list<string> $exclude */
    public function __construct(
        public readonly string $family,
        public readonly ?string $country = null,
        public readonly array $include = [],
        public readonly array $exclude = [],
    ) {
    }

    public function itemType(): string
    {
        return self::FAMILIES[$this->family];
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return ['family' => $this->family, 'country' => $this->country, 'include' => $this->include, 'exclude' => $this->exclude];
    }

    /** @param array<string, mixed> $data stored JSON: trusted, but read defensively */
    public static function fromArray(array $data): self
    {
        $family = isset(self::FAMILIES[$data['family'] ?? '']) ? (string) $data['family'] : 'threat';
        $country = is_string($data['country'] ?? null) && preg_match('/^[A-Z]{2}$/', $data['country']) ? $data['country'] : null;

        return new self($family, $country, self::words($data['include'] ?? []), self::words($data['exclude'] ?? []));
    }

    /**
     * Validates what the administrator typed. Keyword lists are given as one
     * string ("ransomware, phishing") or as a list.
     *
     * @param array<string, mixed> $body
     * @throws ValidationException
     */
    public static function fromInput(array $body): self
    {
        $errors = [];
        $family = is_string($body['family'] ?? null) ? $body['family'] : '';
        if (!isset(self::FAMILIES[$family])) {
            $errors['family'] = 'Choisir la vue : vulnérabilités ou menaces.';
        }
        $country = strtoupper(trim(is_string($body['country'] ?? null) ? $body['country'] : ''));
        if ($country !== '' && !preg_match('/^[A-Z]{2}$/', $country)) {
            $errors['country'] = 'Code pays à deux lettres (BE, FR...) ou vide.';
        }
        $lists = [];
        foreach (['include', 'exclude'] as $field) {
            $raw = $body[$field] ?? [];
            $items = is_string($raw) ? explode(',', $raw) : (is_array($raw) ? $raw : []);
            $words = self::words($items);
            if (count($words) > self::MAX_WORDS || array_filter($words, static fn (string $w): bool => mb_strlen($w) > 60) !== []) {
                $errors[$field] = self::MAX_WORDS . ' mots-clés au maximum, de 60 caractères chacun.';
            }
            $lists[$field] = $words;
        }
        if ($errors !== []) {
            throw new ValidationException($errors);
        }

        return new self($family, $country === '' ? null : $country, $lists['include'], $lists['exclude']);
    }

    /** Keeps an entry when it contains one of the include words (if any) and none of the exclude words. */
    public function keeps(string $text): bool
    {
        $text = Rules::normalise($text);
        foreach ($this->exclude as $word) {
            if (Rules::matches($text, $word)) {
                return false;
            }
        }
        if ($this->include === []) {
            return true;
        }
        foreach ($this->include as $word) {
            if (Rules::matches($text, $word)) {
                return true;
            }
        }

        return false;
    }

    /** @param array<mixed> $items @return list<string> */
    private static function words(array $items): array
    {
        $words = [];
        foreach ($items as $item) {
            if (is_string($item) && ($w = Rules::normalise(preg_replace('/\s+/u', ' ', $item) ?? '')) !== '') {
                $words[] = $w;
            }
        }

        return array_values(array_unique($words));
    }
}
