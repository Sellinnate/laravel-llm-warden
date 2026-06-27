<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Support;

/**
 * Checksum validators for high-precision PII entities. A passing checksum lets
 * the PII detectors emit near-1.0 confidence with negligible false positives.
 */
final class Checksum
{
    /** Codice Fiscale odd-position character values. */
    private const CF_ODD = [
        '0' => 1, '1' => 0, '2' => 5, '3' => 7, '4' => 9, '5' => 13, '6' => 15, '7' => 17, '8' => 19, '9' => 21,
        'A' => 1, 'B' => 0, 'C' => 5, 'D' => 7, 'E' => 9, 'F' => 13, 'G' => 15, 'H' => 17, 'I' => 19, 'J' => 21,
        'K' => 2, 'L' => 4, 'M' => 18, 'N' => 20, 'O' => 11, 'P' => 3, 'Q' => 6, 'R' => 8, 'S' => 12, 'T' => 14,
        'U' => 16, 'V' => 10, 'W' => 22, 'X' => 25, 'Y' => 24, 'Z' => 23,
    ];

    /** Codice Fiscale even-position character values. */
    private const CF_EVEN = [
        '0' => 0, '1' => 1, '2' => 2, '3' => 3, '4' => 4, '5' => 5, '6' => 6, '7' => 7, '8' => 8, '9' => 9,
        'A' => 0, 'B' => 1, 'C' => 2, 'D' => 3, 'E' => 4, 'F' => 5, 'G' => 6, 'H' => 7, 'I' => 8, 'J' => 9,
        'K' => 10, 'L' => 11, 'M' => 12, 'N' => 13, 'O' => 14, 'P' => 15, 'Q' => 16, 'R' => 17, 'S' => 18, 'T' => 19,
        'U' => 20, 'V' => 21, 'W' => 22, 'X' => 23, 'Y' => 24, 'Z' => 25,
    ];

    /**
     * Validate an Italian Codice Fiscale (16 chars). The odd/even tables accept
     * both digits and the omocodia letter substitutions, so no de-omocodia step
     * is needed to verify the control character.
     */
    public static function codiceFiscale(string $cf): bool
    {
        $cf = strtoupper($cf);

        if (preg_match('/^[A-Z0-9]{16}$/', $cf) !== 1) {
            return false;
        }

        $sum = 0;
        for ($i = 0; $i < 15; $i++) {
            $char = $cf[$i];
            // Position is 1-indexed: 1st,3rd,... are "odd".
            $table = ($i % 2 === 0) ? self::CF_ODD : self::CF_EVEN;

            if (! isset($table[$char])) {
                return false;
            }

            $sum += $table[$char];
        }

        $expected = chr(($sum % 26) + ord('A'));

        return $cf[15] === $expected;
    }

    /**
     * Validate an Italian Partita IVA (11 digits) via its Luhn-like check digit.
     */
    public static function partitaIva(string $piva): bool
    {
        if (preg_match('/^\d{11}$/', $piva) !== 1) {
            return false;
        }

        $sum = 0;
        for ($i = 0; $i < 10; $i++) {
            $digit = (int) $piva[$i];

            if ($i % 2 === 1) { // even position (1-indexed): double
                $digit *= 2;
                if ($digit > 9) {
                    $digit -= 9;
                }
            }

            $sum += $digit;
        }

        $check = (10 - ($sum % 10)) % 10;

        return $check === (int) $piva[10];
    }

    /**
     * Validate an IBAN via the ISO 7064 mod-97 check.
     */
    public static function iban(string $iban): bool
    {
        $iban = strtoupper(preg_replace('/\s+/', '', $iban) ?? $iban);

        if (preg_match('/^[A-Z]{2}\d{2}[A-Z0-9]{10,30}$/', $iban) !== 1) {
            return false;
        }

        // Move the first four chars to the end.
        $rearranged = substr($iban, 4).substr($iban, 0, 4);

        // Convert letters to numbers (A=10 .. Z=35).
        $numeric = '';
        foreach (str_split($rearranged) as $char) {
            $numeric .= ctype_alpha($char) ? (string) (ord($char) - 55) : $char;
        }

        return self::mod97($numeric) === 1;
    }

    /**
     * Luhn check (credit cards). Input may contain spaces/hyphens.
     */
    public static function luhn(string $number): bool
    {
        $digits = preg_replace('/\D/', '', $number) ?? '';

        if (strlen($digits) < 12 || strlen($digits) > 19) {
            return false;
        }

        $sum = 0;
        $alt = false;
        for ($i = strlen($digits) - 1; $i >= 0; $i--) {
            $d = (int) $digits[$i];
            if ($alt) {
                $d *= 2;
                if ($d > 9) {
                    $d -= 9;
                }
            }
            $sum += $d;
            $alt = ! $alt;
        }

        return $sum % 10 === 0;
    }

    /**
     * mod-97 over an arbitrarily long numeric string (chunked to avoid overflow).
     */
    private static function mod97(string $numeric): int
    {
        $remainder = '';
        foreach (str_split($numeric) as $digit) {
            $remainder .= $digit;
            if (strlen($remainder) >= 9) {
                $remainder = (string) ((int) $remainder % 97);
            }
        }

        return (int) $remainder % 97;
    }
}
