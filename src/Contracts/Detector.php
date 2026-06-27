<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Contracts;

use Sellinnate\Warden\Support\ScanContext;
use Sellinnate\Warden\ValueObjects\Detection;

/**
 * The detection logic inside a scanner (e.g. the "codice fiscale" detector in
 * the PiiScanner). Detect-only: returns typed spans, never mutates the text.
 */
interface Detector
{
    /**
     * @return array<int, Detection> typed spans with scores
     */
    public function detect(string $normalized, ScanContext $context): array;

    /** The entity/detection type this detector emits (e.g. 'IT_FISCAL_CODE'). */
    public function type(): string;
}
