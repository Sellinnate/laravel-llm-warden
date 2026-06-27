<?php

declare(strict_types=1);

use Sellinnate\Warden\Enums\Action;
use Sellinnate\Warden\Enums\Direction;
use Sellinnate\Warden\Policies\Policy;
use Sellinnate\Warden\Scanners\SecretScanner;
use Sellinnate\Warden\Support\Entropy;
use Sellinnate\Warden\Support\ScanContext;
use Sellinnate\Warden\ValueObjects\ScanResult;

function secretScanner(): SecretScanner
{
    /** @var array<int, array{type: string, score: float, pattern: string, group?: int, entropy?: bool}> $patterns */
    $patterns = require __DIR__.'/../../resources/denylists/secrets.php';

    return new SecretScanner($patterns, 3.5);
}

function scanSecret(string $text, Direction $direction = Direction::Input, array $actions = []): ScanResult
{
    $policy = new Policy('t', actions: $actions);
    $c = ScanContext::for($direction, $text, $policy);
    $c->normalized = $text;

    return secretScanner()->scan($c);
}

describe('detection', function () {
    it('detects an AWS access key and blocks on input', function () {
        $r = scanSecret('my key is AKIAIOSFODNN7EXAMPLE here');
        expect($r->valid)->toBeFalse()
            ->and($r->detections[0]->type)->toBe('SECRET_AWS_ACCESS_KEY');
    });

    it('detects OpenAI and Anthropic keys distinctly', function () {
        expect(scanSecret('sk-ant-api03-'.str_repeat('a', 30))->detections[0]->type)->toBe('SECRET_ANTHROPIC_KEY');
        expect(scanSecret('sk-proj-'.str_repeat('b', 30))->detections[0]->type)->toBe('SECRET_OPENAI_KEY');
    });

    it('detects a JWT and a PEM private key', function () {
        $jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcDEFghiJKLmnoPQRstuv';
        expect(scanSecret($jwt)->detections[0]->type)->toBe('SECRET_JWT');
        expect(scanSecret('-----BEGIN RSA PRIVATE KEY-----')->detections[0]->type)->toBe('SECRET_PEM_PRIVATE_KEY');
    });

    it('never stores the raw secret in detection evidence', function () {
        $r = scanSecret('AKIAIOSFODNN7EXAMPLE');
        expect($r->detections[0]->context['evidence'])->not->toContain('IOSFODNN7');
    });
});

describe('generic catch-all with entropy gate', function () {
    it('flags a high-entropy api_key value', function () {
        $r = scanSecret('api_key=Xy9kQ2mZ7pL4wR8tV3nB6cF1aD0');
        expect($r->valid)->toBeFalse()
            ->and($r->detections[0]->type)->toBe('SECRET_GENERIC');
    });

    it('does not flag a low-entropy value like password=password', function () {
        $r = scanSecret('password=password1234');
        expect($r->detections)->toBe([]);
    });
});

describe('redaction on output', function () {
    it('redacts secrets instead of blocking', function () {
        $r = scanSecret('here is sk-proj-'.str_repeat('z', 30).' done', Direction::Output);
        expect($r->valid)->toBeTrue()
            ->and($r->sanitizedText)->toContain('[REDACTED_SECRET]')
            ->and($r->sanitizedText)->not->toContain('sk-proj-zzz');
    });

    it('honours an explicit Detect action (log only)', function () {
        $r = scanSecret('AKIAIOSFODNN7EXAMPLE', Direction::Input, ['secret' => Action::Detect]);
        expect($r->valid)->toBeTrue()
            ->and($r->detections)->toHaveCount(1);
    });
});

describe('clean text', function () {
    it('passes ordinary prose', function () {
        $r = scanSecret('The quick brown fox jumps over the lazy dog.');
        expect($r->valid)->toBeTrue()->and($r->detections)->toBe([]);
    });
});

it('computes Shannon entropy sensibly', function () {
    expect(Entropy::shannon('aaaaaaaa'))->toBe(0.0);
    expect(Entropy::shannon('Xy9kQ2mZ7pL4wR8t'))->toBeGreaterThan(3.5);
});
