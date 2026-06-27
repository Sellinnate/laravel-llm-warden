<?php

declare(strict_types=1);

use Sellinnate\Warden\Enums\Action;
use Sellinnate\Warden\Enums\Severity;
use Sellinnate\Warden\Support\Vault;
use Sellinnate\Warden\ValueObjects\Detection;
use Sellinnate\Warden\ValueObjects\ScanResult;
use Sellinnate\Warden\ValueObjects\Verdict;

describe('Detection', function () {
    it('exposes span helpers', function () {
        $d = new Detection('EMAIL_ADDRESS', 5, 20, 0.9, 'pii');
        expect($d->length())->toBe(15);
    });

    it('detects overlap and containment', function () {
        $a = new Detection('A', 0, 10, 1.0, 's');
        $b = new Detection('B', 5, 8, 1.0, 's');
        $c = new Detection('C', 20, 30, 1.0, 's');

        expect($a->overlaps($b))->toBeTrue()
            ->and($a->contains($b))->toBeTrue()
            ->and($a->overlaps($c))->toBeFalse();
    });

    it('rejects invalid spans', function () {
        new Detection('X', 10, 5, 1.0, 's');
    })->throws(InvalidArgumentException::class);

    it('rejects out-of-range scores', function () {
        new Detection('X', 0, 1, 1.5, 's');
    })->throws(InvalidArgumentException::class);

    it('serializes to array', function () {
        $d = new Detection('SECRET_AWS', 0, 4, 0.8, 'secret', ['pattern' => 'AKIA']);
        expect($d->toArray())->toMatchArray([
            'type' => 'SECRET_AWS',
            'start' => 0,
            'end' => 4,
            'score' => 0.8,
            'scanner' => 'secret',
        ]);
    });
});

describe('Severity', function () {
    it('maps scores to buckets', function () {
        expect(Severity::fromScore(0.0))->toBe(Severity::Safe)
            ->and(Severity::fromScore(0.3))->toBe(Severity::Low)
            ->and(Severity::fromScore(0.6))->toBe(Severity::Medium)
            ->and(Severity::fromScore(0.95))->toBe(Severity::High);
    });
});

describe('ScanResult', function () {
    it('builds a clean pass-through', function () {
        $r = ScanResult::clean('normalize', 'hi');
        expect($r->valid)->toBeTrue()
            ->and($r->riskScore)->toBe(0.0)
            ->and($r->hasDetections())->toBeFalse();
    });
});

describe('Verdict', function () {
    it('aggregates detections and reports blocked state', function () {
        $injection = new ScanResult('injection', false, 0.9, 'text', [
            new Detection('PROMPT_INJECTION', 0, 6, 0.9, 'injection'),
        ], Action::Block);

        $verdict = new Verdict(
            valid: false,
            riskScore: 0.9,
            severity: Severity::High,
            sanitizedText: 'text',
            originalText: 'text',
            results: ['injection' => $injection],
        );

        expect($verdict->blocked())->toBeTrue()
            ->and($verdict->detections())->toHaveCount(1)
            ->and($verdict->hasDetectionType('PROMPT_INJECTION'))->toBeTrue()
            ->and($verdict->result('injection'))->toBe($injection);
    });

    it('serializes to json safely', function () {
        $verdict = new Verdict(true, 0.0, Severity::Safe, 'clean', 'clean');
        $json = json_encode($verdict);
        expect($json)->toBeString()->toContain('"blocked":false');
    });
});

describe('Vault', function () {
    it('produces stable placeholders and restores values', function () {
        $vault = new Vault;
        $p1 = $vault->store('IT_FISCAL_CODE', 'RSSMRA80A01H501U');
        $p2 = $vault->store('IT_FISCAL_CODE', 'RSSMRA80A01H501U'); // same value -> same placeholder
        $p3 = $vault->store('IT_FISCAL_CODE', 'VRDLGI85M01F205X');

        expect($p1)->toBe('<IT_FISCAL_CODE_1>')
            ->and($p2)->toBe($p1)
            ->and($p3)->toBe('<IT_FISCAL_CODE_2>');

        $restored = $vault->restore("CF: {$p1} and {$p3}");
        expect($restored)->toBe('CF: RSSMRA80A01H501U and VRDLGI85M01F205X');
    });

    it('is empty by default', function () {
        expect((new Vault)->isEmpty())->toBeTrue();
    });
});
