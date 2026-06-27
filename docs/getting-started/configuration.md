---
title: "Configuration"
description: "Choose a policy, drivers and behaviour via config/warden.php."
---

# Configuration

After publishing, `config/warden.php` controls everything. The defaults are
production-safe and fully offline.

## Pick a policy

```php
'default_policy' => env('WARDEN_POLICY', 'balanced'), // strict | balanced | permissive
```

See **[Policies](/concepts/policies)** for the profiles and how to define your own.

## Choose drivers (all optional)

```php
'injection'  => ['driver' => env('WARDEN_INJECTION_DRIVER', 'deterministic')],
'moderation' => ['driver' => env('WARDEN_MODERATION_DRIVER', 'null')],
```

The defaults (`deterministic` / `null`) make **no network calls**. See
**[AI Drivers](/drivers/overview)**.

## Fail policy per component

What happens when an external driver errors or times out:

```php
'fail_mode' => [
    'injection' => env('WARDEN_FAIL_INJECTION', 'open'),   // when in doubt, allow
    'pii'       => env('WARDEN_FAIL_PII', 'closed'),       // when in doubt, block
    'secret'    => env('WARDEN_FAIL_SECRET', 'closed'),
    'nsfw'      => env('WARDEN_FAIL_NSFW', 'open'),
],
```

## Normalization

```php
'normalize' => [
    'nfkc' => true, 'confusables' => true, 'strip_invisible' => true,
    'strip_bidi' => true, 'strip_marks' => true, 'deleet' => true,
    'collapse_spacing' => true, 'decode_base64' => true, 'max_decode_depth' => 3,
],
```

See **[Normalization](/concepts/normalization)**.

## PII operators

```php
'pii' => [
    'locale' => env('WARDEN_PII_LOCALE', 'it'),
    'operators' => [
        'IT_FISCAL_CODE' => ['op' => 'encrypt'],            // reversible -> Vault
        'IBAN'           => ['op' => 'mask', 'from_end' => true, 'chars' => 18],
        'CREDIT_CARD'    => ['op' => 'mask', 'from_end' => true, 'chars' => 12],
        'EMAIL_ADDRESS'  => ['op' => 'replace'],
        'default'        => ['op' => 'replace'],
    ],
    'hash_salt' => env('WARDEN_PII_HASH_SALT', ''),  // required if you use `hash`
],
```

## Anti-DoS, audit & cache

```php
'max_input_bytes' => (int) env('WARDEN_MAX_INPUT_BYTES', 50_000),

'audit' => ['enabled' => true, 'store' => 'log', 'store_raw' => false, 'redact_in_logs' => true],

'cache' => ['enabled' => env('WARDEN_CACHE', false), 'ttl' => 3600, 'store' => env('WARDEN_CACHE_STORE')],
```

::: callout warning "EU residency & egress"
In the default configuration (deterministic only) **no data leaves your
infrastructure**. Enabling an external driver is an explicit, BYOK choice and the
data goes only to the provider you configured. See
**[Security & Compliance](/observability/audit)**.
:::

The full annotated file is in the **[Configuration Reference](/reference/config)**.
