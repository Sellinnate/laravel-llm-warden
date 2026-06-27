<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Support;

/**
 * Shannon entropy, used to gate the generic secret catch-all so that high-
 * entropy values (real keys) are flagged while low-entropy words (`password=hello`)
 * are not.
 */
final class Entropy
{
    /**
     * Shannon entropy in bits per character (0 for empty/uniform input).
     */
    public static function shannon(string $value): float
    {
        $length = strlen($value);
        if ($length === 0) {
            return 0.0;
        }

        $counts = count_chars($value, 1);
        $entropy = 0.0;

        foreach ($counts as $count) {
            $p = $count / $length;
            $entropy -= $p * log($p, 2);
        }

        return $entropy;
    }
}
