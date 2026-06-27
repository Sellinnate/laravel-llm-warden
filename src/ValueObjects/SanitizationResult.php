<?php

declare(strict_types=1);

namespace Sellinnate\Warden\ValueObjects;

/**
 * The result of applying a Sanitizer to a piece of text: the transformed text
 * plus the detections that were actually acted upon.
 */
final readonly class SanitizationResult
{
    /**
     * @param  array<int, Detection>  $applied  detections that were transformed
     */
    public function __construct(
        public string $text,
        public array $applied = [],
    ) {}
}
