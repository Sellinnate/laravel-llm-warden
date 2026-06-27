<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Events;

use Sellinnate\Warden\Enums\Direction;
use Sellinnate\Warden\ValueObjects\Detection;

/**
 * Fired when the PII scanner detects (and possibly redacts) personal data.
 */
final class PiiRedacted
{
    /**
     * @param  array<int, Detection>  $detections
     * @param  array<int, string>  $entityTypes
     */
    public function __construct(
        public readonly Direction $direction,
        public readonly array $detections,
        public readonly array $entityTypes,
    ) {}
}
