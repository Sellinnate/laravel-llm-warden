---
title: "Vault Round-trip"
description: "Reversible pseudonymization: de-identify for the model, restore for the user."
---

# Vault Round-trip

The **Vault** lets you send **de-identified** text to the LLM and return the
**complete** answer to the user. PII is pseudonymized on input (the `encrypt`
operator), the mapping is kept in a per-request Vault, and the output side
restores it.

## The flow

```php
use Sellinnate\Warden\Facades\Warden;

// 1. INPUT — PII encrypted to placeholders, mapping saved in the Vault
$input = Warden::sanitize('Il mio CF è RSSMRA80A01H501U, mail mario@example.com');
$input->sanitizedText; // "Il mio CF è <IT_FISCAL_CODE_1>, mail <EMAIL_ADDRESS_1>"

// 2. Send the de-identified text to your LLM (any client — see Quick Start).
//    `$llm->chat(...)` here is a stand-in for your real LLM call.
$reply = $llm->chat($input->sanitizedText);
//   "Ho registrato il codice <IT_FISCAL_CODE_1> con email <EMAIL_ADDRESS_1>."

// 3. OUTPUT — restore the user's real values
$final = Warden::inspectOutput($reply, vault: $input->vault)->sanitizedText;
//   "Ho registrato il codice RSSMRA80A01H501U con email mario@example.com."
```

Enable reversible operators in config:

```php
'pii' => [
    'operators' => [
        'IT_FISCAL_CODE' => ['op' => 'encrypt'],
        'EMAIL_ADDRESS'  => ['op' => 'encrypt'],
        'default'        => ['op' => 'replace'],
    ],
],
```

## New leaks are still caught

Restored values are marked **trusted** and not re-redacted — but PII the *model
invents* (a different person's data) is still caught and redacted before the user
sees it:

```php
$reply  = 'Contact leaked@victim.com about <IT_FISCAL_CODE_1>.';
$final  = Warden::inspectOutput($reply, vault: $input->vault)->sanitizedText;
// user's own CF restored; leaked@victim.com -> <EMAIL_ADDRESS>
```

And markdown a restored value might re-introduce is defanged, and JSON the model
emitted is validated **after** restoration.

::: callout warning "Per-request only"
A Vault is never shared between requests or tenants, and verdicts carrying a Vault
are never cached. A user echoing an arbitrary `<TYPE_N>` can at most recover their
own request's data.
:::
