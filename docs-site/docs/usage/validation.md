---
title: "Validation Rules"
description: "Hook Warden into Laravel's native 422 / error-bag flow."
---

# Validation Rules

Warden ships three validation rules that plug into Laravel's native validation —
no extra error handling needed. They **reject** on detection (validation rules
can't mutate input; to accept-and-redact, use the facade or middleware).

```php
use Sellinnate\Warden\Rules\NoPromptInjection;
use Sellinnate\Warden\Rules\NoPii;
use Sellinnate\Warden\Rules\Clean;
```

## In a Form Request

```php
public function rules(): array
{
    return [
        'prompt'  => ['required', 'string', 'max:8000', new NoPromptInjection],
        'bio'     => ['nullable', 'string', new NoPii],
        'message' => ['required', 'string', new Clean('strict')],
    ];
}
```

## NoPromptInjection

Fails when the value looks like a prompt-injection / jailbreak attempt.

```php
new NoPromptInjection;            // default policy
new NoPromptInjection('strict');  // explicit policy
```

## NoPii

Fails when the value contains personal data. Restrict to specific entity types:

```php
new NoPii;                                   // any PII
new NoPii(only: ['IT_FISCAL_CODE', 'IBAN']); // only these types
```

## Clean

General-purpose: fails when the full input pipeline of the policy would block the
value (injection, secret, NSFW, …).

```php
new Clean;          // default policy
new Clean('strict');
```

## Messages & i18n

Error messages are translatable (`warden::messages.*`), shipped in English and
Italian. Publish and customise them:

```bash
php artisan vendor:publish --tag=warden-lang
```
