<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Events;

use Sellinnate\Warden\Enums\Direction;
use Sellinnate\Warden\ValueObjects\Detection;

/**
 * Fired when the secret scanner detects credentials (whether blocked or redacted).
 */
final class SecretBlocked
{
    /**
     * @param  array<int, Detection>  $detections
     * @param  array<int, string>  $secretTypes
     */
    public function __construct(
        public readonly Direction $direction,
        public readonly bool $blocked,
        public readonly array $detections,
        public readonly array $secretTypes,
    ) {}
}
