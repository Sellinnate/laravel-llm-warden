<?php

declare(strict_types=1);

use Sellinnate\Warden\Support\Checksum;

describe('Codice Fiscale', function () {
    it('accepts valid codes', function () {
        // Well-formed sample codes with correct control characters.
        expect(Checksum::codiceFiscale('RSSMRA80A01H501U'))->toBeTrue();
        expect(Checksum::codiceFiscale('MRTMTT25D09F205Z'))->toBeTrue();
    });

    it('rejects a wrong control character', function () {
        expect(Checksum::codiceFiscale('RSSMRA80A01H501A'))->toBeFalse();
    });

    it('rejects malformed input', function () {
        expect(Checksum::codiceFiscale('NOTACODE'))->toBeFalse();
        expect(Checksum::codiceFiscale('RSSMRA80A01H501UX'))->toBeFalse();
    });
});

describe('Partita IVA', function () {
    it('accepts a valid VAT number', function () {
        expect(Checksum::partitaIva('00743110157'))->toBeTrue(); // known-valid sample
    });

    it('rejects an invalid check digit', function () {
        expect(Checksum::partitaIva('00743110158'))->toBeFalse();
    });

    it('rejects non-11-digit input', function () {
        expect(Checksum::partitaIva('1234567890'))->toBeFalse();
    });
});

describe('IBAN', function () {
    it('accepts valid IBANs and ignores spaces', function () {
        expect(Checksum::iban('IT60X0542811101000000123456'))->toBeTrue();
        expect(Checksum::iban('DE89 3704 0044 0532 0130 00'))->toBeTrue();
    });

    it('rejects a corrupted IBAN', function () {
        expect(Checksum::iban('IT60X0542811101000000123457'))->toBeFalse();
    });
});

describe('Luhn', function () {
    it('accepts valid card numbers', function () {
        expect(Checksum::luhn('4111111111111111'))->toBeTrue();
        expect(Checksum::luhn('4242 4242 4242 4242'))->toBeTrue();
    });

    it('rejects invalid card numbers', function () {
        expect(Checksum::luhn('4111111111111112'))->toBeFalse();
    });
});
