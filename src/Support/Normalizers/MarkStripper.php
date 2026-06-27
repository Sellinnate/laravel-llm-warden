<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Support\Normalizers;

use Normalizer as IntlNormalizer;
use Sellinnate\Warden\Contracts\Normalizer;
use Sellinnate\Warden\Support\ScanContext;

/**
 * Detection-view normalizer that neutralises combining-mark obfuscation:
 * an attacker can sprinkle combining diacritics through a trigger word
 * ("i\u{0301}gnore" → "ígnore", or base-letter + U+0303) so it no longer
 * matches a deny-list.
 *
 * It decomposes (NFD) so precomposed accents split into base + mark, then
 * strips every nonspacing mark (\p{Mn}) and any residual format char (\p{Cf}),
 * leaving the bare ASCII/Latin skeleton. Lossy — detection view only.
 */
final class MarkStripper implements Normalizer
{
    public function normalize(string $text, ScanContext $context): string
    {
        if ($text === '') {
            return $text;
        }

        $decomposed = IntlNormalizer::normalize($text, IntlNormalizer::FORM_D);
        if ($decomposed === false) {
            $decomposed = $text;
        }

        $stripped = preg_replace('/[\p{Mn}\p{Cf}]/u', '', $decomposed);

        if ($stripped === null) {
            return $decomposed;
        }

        if ($stripped !== $text) {
            $context->addSignal('has_combining_marks');
        }

        return $stripped;
    }

    public function name(): string
    {
        return 'strip_marks';
    }
}
