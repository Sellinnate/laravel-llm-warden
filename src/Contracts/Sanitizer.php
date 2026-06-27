<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Contracts;

use Sellinnate\Warden\Support\Vault;
use Sellinnate\Warden\ValueObjects\Detection;
use Sellinnate\Warden\ValueObjects\OperatorConfig;
use Sellinnate\Warden\ValueObjects\SanitizationResult;

/**
 * Applies an action (replace/mask/hash/encrypt/redact/keep/custom) to a set of
 * detections over a piece of text.
 */
interface Sanitizer
{
    /**
     * @param  array<int, Detection>  $detections
     */
    public function apply(string $text, array $detections, OperatorConfig $op, ?Vault $vault = null): SanitizationResult;

    /** The operator name this sanitizer implements (e.g. 'mask'). */
    public function operator(): string;
}
