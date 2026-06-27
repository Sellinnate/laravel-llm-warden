<?php

declare(strict_types=1);

namespace Sellinnate\Warden\ValueObjects;

use Illuminate\Contracts\Support\Arrayable;
use JsonSerializable;
use Sellinnate\Warden\Enums\Action;

/**
 * The result of a single scanner, modelled on LLM Guard's (valid, sanitized, score)
 * triple. Immutable.
 *
 * @implements Arrayable<string, mixed>
 */
final readonly class ScanResult implements Arrayable, JsonSerializable
{
    /**
     * @param  array<int, Detection>  $detections
     */
    public function __construct(
        public string $scanner,
        public bool $valid,
        public float $riskScore,
        public string $sanitizedText,
        public array $detections = [],
        public Action $action = Action::Detect,
    ) {}

    /**
     * A clean pass-through: nothing found, text untouched.
     */
    public static function clean(string $scanner, string $text, Action $action = Action::Detect): self
    {
        return new self($scanner, true, 0.0, $text, [], $action);
    }

    public function hasDetections(): bool
    {
        return $this->detections !== [];
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'scanner' => $this->scanner,
            'valid' => $this->valid,
            'risk_score' => $this->riskScore,
            'action' => $this->action->value,
            'detections' => array_map(static fn (Detection $d): array => $d->toArray(), $this->detections),
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
