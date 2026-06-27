<?php

declare(strict_types=1);

namespace Sellinnate\Warden\ValueObjects;

/**
 * Normalized output of any ModerationDriver. Categories are keyed by the
 * internal Llama-Guard-style taxonomy (S1..S13); scores are 0..1.
 */
final readonly class ModerationVerdict
{
    /**
     * @param  array<string, float>  $categories  internal-category => score
     */
    public function __construct(
        public bool $flagged,
        public array $categories = [],
        public string $driver = 'null',
    ) {}

    public static function safe(string $driver = 'null'): self
    {
        return new self(false, [], $driver);
    }

    /**
     * Highest score across all categories.
     */
    public function maxScore(): float
    {
        return $this->categories === [] ? 0.0 : max($this->categories);
    }

    /**
     * Categories whose score meets or exceeds the threshold.
     *
     * @return array<string, float>
     */
    public function above(float $threshold): array
    {
        return array_filter($this->categories, static fn (float $s): bool => $s >= $threshold);
    }
}
