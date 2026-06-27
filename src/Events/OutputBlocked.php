<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Events;

use Sellinnate\Warden\ValueObjects\Detection;

/**
 * Fired when an output-direction scanner blocks the LLM response.
 */
final class OutputBlocked
{
    /**
     * @param  array<int, Detection>  $detections
     */
    public function __construct(
        public readonly string $scanner,
        public readonly float $riskScore,
        public readonly array $detections,
    ) {}
}
