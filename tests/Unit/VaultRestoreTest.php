<?php

declare(strict_types=1);

use Sellinnate\Warden\Support\Vault;

describe('M1 — Vault::restore single-pass safety', function () {
    it('does not re-expand a restored value that contains another placeholder', function () {
        $vault = new Vault;
        // Force the first entry's value to contain the second placeholder string.
        $p1 = $vault->store('LONGTYPE', 'see token <PIN_1>');
        $p2 = $vault->store('PIN', '1234-SECRET');

        $restored = $vault->restore("Result: {$p1}");

        // The PIN secret must NOT leak into output that only referenced p1.
        expect($restored)->toBe('Result: see token <PIN_1>')
            ->and($restored)->not->toContain('1234-SECRET');

        // p2 still restores correctly when actually referenced.
        expect($vault->restore($p2))->toBe('1234-SECRET');
    });

    it('avoids the <EMAIL_1> / <EMAIL_10> prefix-collision class', function () {
        $vault = new Vault;
        $values = [];
        for ($i = 1; $i <= 12; $i++) {
            $values[] = $vault->store('EMAIL', "user{$i}@example.test");
        }

        $text = implode(' ', $values);
        $restored = $vault->restore($text);

        expect($restored)->toBe(implode(' ', array_map(
            static fn (int $i): string => "user{$i}@example.test",
            range(1, 12),
        )));
    });

    it('leaves unknown placeholder-shaped text untouched', function () {
        $vault = new Vault;
        $vault->store('EMAIL', 'a@b.test');

        expect($vault->restore('Contact <SUPPORT_9> please'))->toBe('Contact <SUPPORT_9> please');
    });
});
