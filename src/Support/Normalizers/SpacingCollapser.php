<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Support\Normalizers;

use Sellinnate\Warden\Contracts\Normalizer;
use Sellinnate\Warden\Support\ScanContext;

/**
 * Collapses intra-word spacing/punctuation used to break trigger words apart,
 * e.g. "i g n o r e" or "i.g.n.o.r.e" -> "ignore". Works on the *normalized*
 * (detection) view only.
 *
 * The heuristic targets runs of single letters separated by a single space or
 * punctuation char — the canonical spacing-evasion shape — without collapsing
 * ordinary spaced words.
 */
final class SpacingCollapser implements Normalizer
{
    public function normalize(string $text, ScanContext $context): string
    {
        if ($text === '') {
            return $text;
        }

        // Match runs of *single* alphanumeric chars each separated by one space/
        // dot/hyphen/underscore (>= 3 chars), anchored so we don't pick the
        // trailing letter of an ordinary word or stray single-letter words
        // ("on a mat"). Digits are included so spaced leet ("1 g n 0 r e")
        // collapses too; de-leet then runs on the result.
        $collapsed = preg_replace_callback(
            '/(?<![A-Za-zÀ-ÿ0-9])(?:[A-Za-zÀ-ÿ0-9][ ._\-]){2,}[A-Za-zÀ-ÿ0-9](?![A-Za-zÀ-ÿ0-9])/u',
            static fn (array $m): string => preg_replace('/[ ._\-]/u', '', $m[0]) ?? $m[0],
            $text,
        );

        if ($collapsed !== null && $collapsed !== $text) {
            $context->addSignal('has_spaced_letters');

            return $collapsed;
        }

        return $text;
    }

    public function name(): string
    {
        return 'collapse_spacing';
    }
}
