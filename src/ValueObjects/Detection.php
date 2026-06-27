<?php

declare(strict_types=1);

namespace Sellinnate\Warden\ValueObjects;

use Illuminate\Contracts\Support\Arrayable;
use JsonSerializable;

/**
 * A single typed finding within a piece of text, modelled on Presidio's
 * RecognizerResult. Offsets are expressed as **byte** positions into the text
 * the detector ran against (see ScanContext for which view that is).
 *
 * @implements Arrayable<string, mixed>
 */
final readonly class Detection implements Arrayable, JsonSerializable
{
    /**
     * @param  string  $type  Stable detection type, e.g. 'IT_FISCAL_CODE', 'PROMPT_INJECTION', 'SECRET_AWS'.
     * @param  int  $start  Inclusive byte offset where the match begins.
     * @param  int  $end  Exclusive byte offset where the match ends.
     * @param  float  $score  Confidence in the 0..1 range.
     * @param  string  $scanner  Name of the scanner that produced this detection.
     * @param  array<string, mixed>  $context  Redacted evidence (pattern hit, snippet, signals).
     */
    public function __construct(
        public string $type,
        public int $start,
        public int $end,
        public float $score,
        public string $scanner,
        public array $context = [],
    ) {
        if ($start < 0 || $end < $start) {
            throw new \InvalidArgumentException("Invalid detection span [{$start}, {$end}].");
        }

        if ($score < 0.0 || $score > 1.0) {
            throw new \InvalidArgumentException("Detection score {$score} out of range [0, 1].");
        }
    }

    public function length(): int
    {
        return $this->end - $this->start;
    }

    /**
     * Does this detection's span overlap the other's at all?
     */
    public function overlaps(self $other): bool
    {
        return $this->start < $other->end && $other->start < $this->end;
    }

    /**
     * Does this detection fully contain the other's span?
     */
    public function contains(self $other): bool
    {
        return $this->start <= $other->start && $this->end >= $other->end;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'type' => $this->type,
            'start' => $this->start,
            'end' => $this->end,
            'score' => $this->score,
            'scanner' => $this->scanner,
            'context' => $this->context,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }
}
