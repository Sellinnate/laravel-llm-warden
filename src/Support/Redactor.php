<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Support;

/**
 * Applies byte-span replacements to a string. Replacements are applied right-to-
 * left so earlier offsets stay valid, and overlapping spans are skipped (the
 * first-applied, i.e. rightmost, wins) to avoid corrupting the text.
 */
final class Redactor
{
    /**
     * @param  array<int, array{0: int, 1: int, 2: string}>  $spans  list of [start, end, replacement]
     */
    public static function apply(string $text, array $spans): string
    {
        // Sort by start descending so we can splice from the end without shifting
        // offsets we haven't processed yet.
        usort($spans, static fn (array $a, array $b): int => $b[0] <=> $a[0]);

        $lastStart = strlen($text) + 1;

        foreach ($spans as [$start, $end, $replacement]) {
            if ($end > $lastStart || $start < 0 || $end < $start || $end > strlen($text)) {
                // Overlaps an already-applied span, or is out of bounds — skip.
                continue;
            }

            if (self::splitsCodepoint($text, $start) || self::splitsCodepoint($text, $end)) {
                // A boundary that falls inside a multi-byte UTF-8 sequence would
                // corrupt the text — skip rather than emit invalid UTF-8.
                continue;
            }

            $text = substr_replace($text, $replacement, $start, $end - $start);
            $lastStart = $start;
        }

        return $text;
    }

    /**
     * True if byte offset $pos falls in the middle of a UTF-8 multi-byte
     * sequence (i.e. on a continuation byte 0b10xxxxxx).
     */
    private static function splitsCodepoint(string $text, int $pos): bool
    {
        if ($pos <= 0 || $pos >= strlen($text)) {
            return false;
        }

        return (ord($text[$pos]) & 0xC0) === 0x80;
    }
}
