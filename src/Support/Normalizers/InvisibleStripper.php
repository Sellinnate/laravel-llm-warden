<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Support\Normalizers;

use Sellinnate\Warden\Contracts\Normalizer;
use Sellinnate\Warden\Support\ScanContext;

/**
 * Strips invisible / formatting code points that are real injection channels:
 * zero-width spaces & joiners, BOM/ZWNBSP, soft hyphen, word joiner, and — most
 * importantly — the entire Unicode Tag block (U+E0000–U+E007F), which can encode
 * fully-invisible instructions.
 *
 * Safe to apply to the delivered text: these characters are virtually never
 * meaningful in user prompts and their presence is itself a signal.
 */
final class InvisibleStripper implements Normalizer
{
    /**
     * Individual invisible code points (outside the Tag block, handled by range).
     *
     * @var array<int, string>
     */
    private const INVISIBLES = [
        "\u{200B}", // zero-width space
        "\u{200C}", // zero-width non-joiner
        "\u{200D}", // zero-width joiner
        "\u{2060}", // word joiner
        "\u{2061}", // function application
        "\u{2062}", // invisible times
        "\u{2063}", // invisible separator
        "\u{2064}", // invisible plus
        "\u{FEFF}", // BOM / zero-width no-break space
        "\u{00AD}", // soft hyphen
        "\u{034F}", // combining grapheme joiner
        "\u{180E}", // mongolian vowel separator
        "\u{200E}", // left-to-right mark
        "\u{200F}", // right-to-left mark
        "\u{061C}", // arabic letter mark
        "\u{115F}", // hangul choseong filler
        "\u{1160}", // hangul jungseong filler
        "\u{3164}", // hangul filler
        "\u{FFA0}", // halfwidth hangul filler
        "\u{17B4}", // khmer vowel inherent aq
        "\u{17B5}", // khmer vowel inherent aa
    ];

    public function normalize(string $text, ScanContext $context): string
    {
        if ($text === '') {
            return $text;
        }

        $stripped = str_replace(self::INVISIBLES, '', $text);

        // Tag block U+E0000–U+E007F (invisible instruction channel) and the
        // variation-selector blocks U+FE00–U+FE0F / U+E0100–U+E01EF (ASCII-
        // smuggling / steganography channels that also split trigger words).
        $stripped = preg_replace(
            '/[\x{FE00}-\x{FE0F}\x{E0000}-\x{E007F}\x{E0100}-\x{E01EF}]/u',
            '',
            $stripped,
        ) ?? $stripped;

        if ($stripped !== $text) {
            $context->addSignal('has_invisible');
        }

        return $stripped;
    }

    public function name(): string
    {
        return 'strip_invisible';
    }
}
