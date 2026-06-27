<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Detectors\Pii;

use Sellinnate\Warden\Contracts\Detector;
use Sellinnate\Warden\Support\Checksum;

/**
 * Builds the default, locale-aware set of regex/checksum PII detectors. NER
 * entities (PERSON, LOCATION) are intentionally excluded — they require a model
 * and are added by an optional driver.
 */
final class DefaultDetectors
{
    /**
     * @return array<int, Detector>
     */
    public static function for(string $locale = 'it'): array
    {
        $detectors = [
            // Checksum-validated, high precision, locale-independent.
            new RegexDetector(
                'IBAN',
                ['/\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}[ ]?[A-Z0-9]{0,4}\b/'],
                validator: [Checksum::class, 'iban'],
                validScore: 0.99,
            ),
            new RegexDetector(
                'CREDIT_CARD',
                ['/\b\d(?:[ -]?\d){12,18}\b/'],
                validator: [Checksum::class, 'luhn'],
                validScore: 0.95,
            ),
            new RegexDetector(
                'EMAIL_ADDRESS',
                // RFC-bounded lengths keep matching linear (no class/literal overlap,
                // no unbounded run that rescans from every start) — no ReDoS.
                ['/\b[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,24}\b/'],
                score: 0.9,
            ),
            new RegexDetector(
                'IP_ADDRESS',
                [
                    '/\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/',
                    '/\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b/',
                ],
                score: 0.6,
                // Require context so version strings ("v1.2.3.4") aren't flagged.
                contextWords: ['ip', 'address', 'indirizzo', 'server', 'host', 'gateway'],
                requireContext: true,
            ),
        ];

        if ($locale === 'it') {
            array_unshift(
                $detectors,
                new RegexDetector(
                    'IT_FISCAL_CODE',
                    ['/\b[A-Z]{6}[0-9A-Z]{2}[A-Z][0-9A-Z]{2}[A-Z][0-9A-Z]{3}[A-Z]\b/i'],
                    validator: [Checksum::class, 'codiceFiscale'],
                    validScore: 0.99,
                ),
                new RegexDetector(
                    'IT_VAT',
                    ['/\b\d{11}\b/'],
                    validator: [Checksum::class, 'partitaIva'],
                    validScore: 0.85,
                    contextWords: ['p.iva', 'partita iva', 'piva', 'vat'],
                ),
            );

            // Unambiguous: a +39 prefix is a phone number on its own.
            $detectors[] = new RegexDetector(
                'PHONE_NUMBER',
                ['/(?<![\d\w])\+39[\s.\-]?(?:0\d{1,3}|3\d{2})[\s.\-]?\d{6,7}(?![\d\w])/'],
                score: 0.8,
            );
            // Bare local number: needs a context word so we don't flag order IDs.
            $detectors[] = new RegexDetector(
                'PHONE_NUMBER',
                ['/(?<![\d\w])(?:0\d{1,3}|3\d{2})[\s.\-]?\d{6,7}(?![\d\w])/'],
                score: 0.6,
                contextWords: ['tel', 'telefono', 'cell', 'cellulare', 'phone', 'mobile', 'chiamami', 'numero'],
                requireContext: true,
            );
        } else {
            $detectors[] = new RegexDetector(
                'PHONE_NUMBER',
                ['/(?<![\d\w])\+\d{1,3}[\s.\-]?\d(?:[\d\s.\-]{6,14})\d(?![\d\w])/'],
                score: 0.6,
                contextWords: ['tel', 'phone', 'mobile', 'call', 'number'],
            );
        }

        return $detectors;
    }
}
