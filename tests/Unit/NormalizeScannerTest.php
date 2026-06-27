<?php

declare(strict_types=1);

use Sellinnate\Warden\Enums\Direction;
use Sellinnate\Warden\Policies\Policy;
use Sellinnate\Warden\Scanners\NormalizeScanner;
use Sellinnate\Warden\Support\ScanContext;

function normCtx(string $text): ScanContext
{
    return ScanContext::for(Direction::Input, $text, new Policy('test'));
}

it('strips invisibles from the delivered text but keeps it readable', function () {
    $scanner = new NormalizeScanner;
    $c = normCtx("he\u{200B}llo");
    $result = $scanner->scan($c);

    expect($c->current)->toBe('hello')          // delivered: invisibles removed
        ->and($result->sanitizedText)->toBe('hello')
        ->and($result->valid)->toBeTrue();
});

it('does not NFKC-mangle the delivered text', function () {
    $scanner = new NormalizeScanner;
    // ² is NFKC-folded to 2 only in the detection view.
    $c = normCtx('x²');
    $scanner->scan($c);

    expect($c->current)->toBe('x²')             // delivered preserved
        ->and($c->normalized)->toContain('x2'); // detection view folded
});

it('produces a normalized detection view that de-obfuscates trigger words', function () {
    $scanner = new NormalizeScanner;
    $c = normCtx('1gn0r3 all');
    $scanner->scan($c);

    expect($c->normalized)->toContain('ignore');
});

it('honours disabling normalizers via config', function () {
    $scanner = new NormalizeScanner(['strip_invisible' => false]);
    $c = normCtx("a\u{200B}b");

    $scanner->scan($c);

    expect($c->current)->toBe("a\u{200B}b");
});

it('always supports every direction', function () {
    $scanner = new NormalizeScanner;
    expect($scanner->supports(Direction::Input))->toBeTrue()
        ->and($scanner->supports(Direction::Output))->toBeTrue()
        ->and($scanner->supports(Direction::Retrieval))->toBeTrue();
});
