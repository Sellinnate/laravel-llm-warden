<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Contracts;

use Sellinnate\Warden\Support\ScanContext;

/**
 * A single pluggable step in the normalization chain (NFKC, confusable folding,
 * invisible stripping, bidi stripping, de-leet, spacing collapse, decoding).
 *
 * A normalizer transforms the normalized view of the text and may emit signals
 * onto the context (e.g. flag that zero-width characters were present).
 */
interface Normalizer
{
    public function normalize(string $text, ScanContext $context): string;

    public function name(): string;
}
