<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Events;

use Sellinnate\Warden\Enums\Direction;
use Sellinnate\Warden\ValueObjects\Detection;

/**
 * Fired when the injection scanner produces one or more detections.
 */
final class InjectionDetected
{
    /**
     * @param  array<int, Detection>  $detections
     */
    public function __construct(
        public readonly Direction $direction,
        public readonly float $riskScore,
        public readonly bool $blocked,
        public readonly array $detections,
    ) {}
}
