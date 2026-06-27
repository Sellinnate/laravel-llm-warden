<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Support\Normalizers;

use Normalizer as IntlNormalizer;
use Sellinnate\Warden\Contracts\Normalizer;
use Sellinnate\Warden\Support\ScanContext;

/**
 * Unicode NFKC normalization: unifies compatibility forms (full-width letters,
 * ligatures, circled/super/sub variants) so that visually-equivalent strings
 * collapse to one canonical form before matching.
 *
 * Applied to the *normalized* (detection) view only — never to the delivered
 * text, because NFKC is lossy for some legitimate content.
 */
final class UnicodeNormalizer implements Normalizer
{
    public function normalize(string $text, ScanContext $context): string
    {
        if ($text === '') {
            return $text;
        }

        $normalized = IntlNormalizer::normalize($text, IntlNormalizer::FORM_KC);

        if ($normalized === false) {
            // Invalid UTF-8 or normalizer failure: leave the input untouched.
            return $text;
        }

        if ($normalized !== $text) {
            $context->addSignal('nfkc_changed');
        }

        return $normalized;
    }

    public function name(): string
    {
        return 'nfkc';
    }
}
