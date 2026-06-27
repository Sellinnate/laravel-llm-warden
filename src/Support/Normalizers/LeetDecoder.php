<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Support\Normalizers;

use Sellinnate\Warden\Contracts\Normalizer;
use Sellinnate\Warden\Support\ScanContext;

/**
 * Maps leetspeak digit/symbol substitutions back to letters so that trigger
 * words written `1gn0r3` / `h4ck` match the deny-list.
 *
 * Applied to the *normalized* (detection) view only: the mapping is lossy
 * (it would corrupt legitimate numbers) and must never touch delivered text.
 */
final class LeetDecoder implements Normalizer
{
    /**
     * Note: numeric-looking keys (e.g. '4', '0') are cast to int array keys by
     * PHP; strtr handles both transparently.
     *
     * @var array<array-key, string>
     */
    private array $map;

    /**
     * @param  array<array-key, string>  $map
     */
    public function __construct(array $map = [])
    {
        $this->map = $map !== [] ? $map : [
            '4' => 'a', '@' => 'a',
            '3' => 'e',
            '0' => 'o',
            '1' => 'i', '!' => 'i',
            '5' => 's', '$' => 's',
            '7' => 't',
            '8' => 'b',
            '9' => 'g',
        ];
    }

    public function normalize(string $text, ScanContext $context): string
    {
        if ($text === '') {
            return $text;
        }

        // De-leet alphanumeric tokens that contain at least one real letter, so
        // "1gn0r3" / "b0mb" / "4ll" decode but standalone numbers like "2024"
        // or "100" are left untouched.
        $decoded = preg_replace_callback(
            '/[A-Za-zÀ-ÿ0-9@!$]+/u',
            function (array $m): string {
                if (preg_match('/[A-Za-zÀ-ÿ]/u', $m[0]) !== 1) {
                    return $m[0]; // pure number / symbol run — not leet
                }

                return strtr($m[0], $this->map);
            },
            $text,
        );

        return $decoded ?? $text;
    }

    public function name(): string
    {
        return 'deleet';
    }
}
