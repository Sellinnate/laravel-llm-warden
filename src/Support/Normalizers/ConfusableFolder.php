<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Support\Normalizers;

use Sellinnate\Warden\Contracts\Normalizer;
use Sellinnate\Warden\Support\ScanContext;

/**
 * Folds confusable (look-alike) characters to their Latin ASCII skeleton,
 * following the spirit of Unicode TR39. Maps the common Cyrillic/Greek/
 * full-width/math-styled homoglyphs that attackers use to smuggle trigger
 * words past a naive deny-list (e.g. Cyrillic "а" for Latin "a").
 *
 * Also flags mixed-script tokens, which are a strong obfuscation signal.
 */
final class ConfusableFolder implements Normalizer
{
    /**
     * Curated confusable => ASCII skeleton map. Not exhaustive (the full TR39
     * table is enormous) but covers the high-frequency attack alphabet.
     *
     * @var array<string, string>
     */
    private const MAP = [
        // Cyrillic look-alikes
        'а' => 'a', 'е' => 'e', 'о' => 'o', 'р' => 'p', 'с' => 'c', 'у' => 'y',
        'х' => 'x', 'к' => 'k', 'м' => 'm', 'н' => 'h', 'т' => 't', 'в' => 'b',
        'А' => 'A', 'В' => 'B', 'Е' => 'E', 'К' => 'K', 'М' => 'M', 'Н' => 'H',
        'О' => 'O', 'Р' => 'P', 'С' => 'C', 'Т' => 'T', 'У' => 'Y', 'Х' => 'X',
        'і' => 'i', 'ј' => 'j', 'ѕ' => 's', 'З' => '3',
        // Greek look-alikes
        'α' => 'a', 'β' => 'b', 'ο' => 'o', 'ρ' => 'p', 'τ' => 't', 'υ' => 'u',
        'ν' => 'v', 'κ' => 'k', 'χ' => 'x', 'ι' => 'i',
        'Α' => 'A', 'Β' => 'B', 'Ε' => 'E', 'Ζ' => 'Z', 'Η' => 'H', 'Ι' => 'I',
        'Κ' => 'K', 'Μ' => 'M', 'Ν' => 'N', 'Ο' => 'O', 'Ρ' => 'P', 'Τ' => 'T',
        'Υ' => 'Y', 'Χ' => 'X',
        // Mathematical alphanumeric "fancy" letters (a small, common subset)
        '𝐚' => 'a', '𝐛' => 'b', '𝐜' => 'c', '𝐢' => 'i', '𝐠' => 'g', '𝐧' => 'n',
        '𝑎' => 'a', '𝒂' => 'a', '𝓪' => 'a', '𝔞' => 'a', '𝕒' => 'a',
        // Full-width Latin (common)
        'ａ' => 'a', 'ｂ' => 'b', 'ｃ' => 'c', 'ｉ' => 'i', 'ｇ' => 'g', 'ｎ' => 'n',
        'ｏ' => 'o', 'ｒ' => 'r', 'ｅ' => 'e', 'ｓ' => 's', 'ｔ' => 't',
    ];

    public function normalize(string $text, ScanContext $context): string
    {
        if ($text === '') {
            return $text;
        }

        $folded = strtr($text, self::MAP);

        if ($folded !== $text) {
            $context->addSignal('has_confusables');
        }

        if ($this->hasMixedScript($text)) {
            $context->addSignal('mixed_script');
        }

        return $folded;
    }

    /**
     * Heuristic: does a single alphabetic run mix Latin with Cyrillic/Greek?
     * That almost never happens in legitimate text and is a classic homoglyph tell.
     */
    private function hasMixedScript(string $text): bool
    {
        $hasLatin = preg_match('/[A-Za-z]/', $text) === 1;
        $hasCyrillicOrGreek = preg_match('/[\x{0370}-\x{03FF}\x{0400}-\x{04FF}]/u', $text) === 1;

        return $hasLatin && $hasCyrillicOrGreek;
    }

    public function name(): string
    {
        return 'confusables';
    }
}
