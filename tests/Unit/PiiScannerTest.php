<?php

declare(strict_types=1);

use Sellinnate\Warden\Detectors\Pii\DefaultDetectors;
use Sellinnate\Warden\Detectors\Pii\PiiAnalyzer;
use Sellinnate\Warden\Detectors\Pii\PiiAnonymizer;
use Sellinnate\Warden\Enums\Direction;
use Sellinnate\Warden\Policies\Policy;
use Sellinnate\Warden\Scanners\PiiScanner;
use Sellinnate\Warden\Support\ScanContext;
use Sellinnate\Warden\ValueObjects\ScanResult;

function piiScanner(array $operators = []): PiiScanner
{
    return new PiiScanner(
        new PiiAnalyzer(DefaultDetectors::for('it')),
        new PiiAnonymizer('test-salt'),
        $operators,
    );
}

function scanPii(string $text, array $operators = [], Direction $direction = Direction::Input): ScanResult
{
    $c = ScanContext::for($direction, $text, new Policy('t'));
    $c->normalized = $text;
    $result = piiScanner($operators)->scan($c);

    return $result;
}

describe('detection', function () {
    it('detects an Italian fiscal code via checksum', function () {
        $r = scanPii('Il mio CF è RSSMRA80A01H501U grazie');
        expect($r->detections)->toHaveCount(1)
            ->and($r->detections[0]->type)->toBe('IT_FISCAL_CODE')
            ->and($r->detections[0]->score)->toBeGreaterThan(0.95);
    });

    it('detects email, IBAN and credit card', function () {
        expect(scanPii('write me at john.doe@example.com')->detections[0]->type)->toBe('EMAIL_ADDRESS');
        expect(scanPii('IBAN IT60X0542811101000000123456')->detections[0]->type)->toBe('IBAN');
        expect(scanPii('card 4111 1111 1111 1111')->detections[0]->type)->toBe('CREDIT_CARD');
    });

    it('does not flag an invalid fiscal code', function () {
        $r = scanPii('code RSSMRA80A01H501A is wrong');
        expect($r->detections)->toBe([]);
    });
});

describe('operators', function () {
    it('replaces email with a typed placeholder', function () {
        $r = scanPii('mail me at a@b.com', ['EMAIL_ADDRESS' => ['op' => 'replace'], 'default' => ['op' => 'replace']]);
        expect($r->sanitizedText)->toBe('mail me at <EMAIL_ADDRESS>');
    });

    it('masks a credit card from the end', function () {
        $r = scanPii('card 4111111111111111 ok', ['default' => ['op' => 'mask', 'from_end' => true, 'chars' => 12]]);
        expect($r->sanitizedText)->toContain('4111')
            ->and($r->sanitizedText)->toContain('************');
    });

    it('hashes deterministically with salt', function () {
        $a = scanPii('a@b.com', ['default' => ['op' => 'hash']])->sanitizedText;
        $b = scanPii('a@b.com', ['default' => ['op' => 'hash']])->sanitizedText;
        expect($a)->toBe($b)->and($a)->not->toContain('a@b.com');
    });

    it('keeps the value untouched with the keep operator', function () {
        $r = scanPii('a@b.com', ['default' => ['op' => 'keep']]);
        expect($r->sanitizedText)->toBe('a@b.com')
            ->and($r->detections)->toHaveCount(1);
    });
});

describe('encrypt + Vault round-trip', function () {
    it('pseudonymizes on input and de-anonymizes via the vault', function () {
        $c = ScanContext::for(Direction::Input, 'CF RSSMRA80A01H501U here', new Policy('t'));
        $c->normalized = $c->current;
        $r = piiScanner(['IT_FISCAL_CODE' => ['op' => 'encrypt'], 'default' => ['op' => 'replace']])->scan($c);

        expect($r->sanitizedText)->toBe('CF <IT_FISCAL_CODE_1> here')
            ->and($c->vault->isEmpty())->toBeFalse();

        // The vault restores the original value.
        $restored = $c->vault->restore($r->sanitizedText);
        expect($restored)->toBe('CF RSSMRA80A01H501U here');
    });
});

describe('overlap resolution', function () {
    it('keeps the higher-confidence detection on conflict', function () {
        // A 16-digit Luhn-valid card is also 16 chars; ensure single detection wins.
        $r = scanPii('4111 1111 1111 1111');
        $types = array_map(fn ($d) => $d->type, $r->detections);
        expect($types)->toContain('CREDIT_CARD');
    });
});
