<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Support\Normalizers;

use Sellinnate\Warden\Contracts\Normalizer;
use Sellinnate\Warden\Support\ScanContext;

/**
 * Strips bidirectional control characters (LRE/RLE/PDF/LRO/RLO and the isolate
 * family LRI/RLI/FSI/PDI) used to visually reorder text — the "Trojan Source"
 * class of attacks. Their presence is flagged as a signal.
 */
final class BidiStripper implements Normalizer
{
    public function normalize(string $text, ScanContext $context): string
    {
        if ($text === '') {
            return $text;
        }

        // U+202A–U+202E (embeddings/overrides) and U+2066–U+2069 (isolates).
        $stripped = preg_replace('/[\x{202A}-\x{202E}\x{2066}-\x{2069}]/u', '', $text) ?? $text;

        if ($stripped !== $text) {
            $context->addSignal('has_bidi');
        }

        return $stripped;
    }

    public function name(): string
    {
        return 'strip_bidi';
    }
}
