---
title: "Configuration Reference"
description: "The full annotated config/warden.php."
---

# Configuration Reference

The complete `config/warden.php`. Every value has a production-safe default;
everything network-related is opt-in.

```php
return [

    // Default policy: strict | balanced | permissive, or a custom one you defined.
    'default_policy' => env('WARDEN_POLICY', 'balanced'),

    // Inputs larger than this many bytes are truncated (UTF-8 safe) before scanning.
    'max_input_bytes' => (int) env('WARDEN_MAX_INPUT_BYTES', 50_000),

    // ── AI drivers (all optional; defaults are offline) ──────────────────────
    'injection' => [
        'driver' => env('WARDEN_INJECTION_DRIVER', 'deterministic'), // deterministic | llm-judge
        'escalate_below' => 0.5,
        'prism' => [
            'key'      => env('OPENAI_API_KEY'),
            'model'    => env('WARDEN_PRISM_MODEL', 'gpt-4o-mini'),
            'endpoint' => 'https://api.openai.com/v1/chat/completions',
            'timeout'  => 8,
        ],
    ],

    'moderation' => [
        'driver' => env('WARDEN_MODERATION_DRIVER', 'null'), // null | openai | azure
        'openai' => [
            'key'   => env('OPENAI_API_KEY'),
            'model' => env('WARDEN_OPENAI_MODERATION_MODEL', 'omni-moderation-latest'),
            'endpoint' => 'https://api.openai.com/v1/moderations',
            'timeout'  => 5,
        ],
        'azure' => [
            'key'      => env('AZURE_CONTENT_SAFETY_KEY'),
            'endpoint' => env('AZURE_CONTENT_SAFETY_ENDPOINT'),
            'timeout'  => 5,
        ],
    ],

    // ── Fail policy per component (on driver error/timeout) ──────────────────
    'fail_mode' => [
        'injection' => env('WARDEN_FAIL_INJECTION', 'open'),
        'pii'       => env('WARDEN_FAIL_PII', 'closed'),
        'secret'    => env('WARDEN_FAIL_SECRET', 'closed'),
        'nsfw'      => env('WARDEN_FAIL_NSFW', 'open'),
    ],

    // ── Normalization ────────────────────────────────────────────────────────
    'normalize' => [
        'nfkc' => true, 'confusables' => true, 'strip_invisible' => true,
        'strip_bidi' => true, 'strip_marks' => true, 'deleet' => true,
        'collapse_spacing' => true, 'decode_base64' => true, 'max_decode_depth' => 3,
    ],

    // ── Secret module ────────────────────────────────────────────────────────
    'secret' => ['entropy_threshold' => 3.5],

    // ── PII module ───────────────────────────────────────────────────────────
    'pii' => [
        'locale' => env('WARDEN_PII_LOCALE', 'it'),
        'operators' => [
            'IT_FISCAL_CODE' => ['op' => 'encrypt'],
            'IT_VAT'         => ['op' => 'replace'],
            'IBAN'           => ['op' => 'mask', 'from_end' => true, 'chars' => 18],
            'CREDIT_CARD'    => ['op' => 'mask', 'from_end' => true, 'chars' => 12],
            'EMAIL_ADDRESS'  => ['op' => 'replace'],
            'PHONE_NUMBER'   => ['op' => 'replace'],
            'IP_ADDRESS'     => ['op' => 'replace'],
            'default'        => ['op' => 'replace'],
        ],
        'hash_salt'  => env('WARDEN_PII_HASH_SALT', ''),
        'ner_driver' => env('WARDEN_PII_NER'),
    ],

    // ── NSFW module ──────────────────────────────────────────────────────────
    'nsfw' => ['locales' => ['it', 'en']],

    // ── Output handling ──────────────────────────────────────────────────────
    'output' => [
        'allowed_domains' => [],
        'canary'          => env('WARDEN_CANARY'),
        'system_prompt'   => env('WARDEN_SYSTEM_PROMPT'),
        'require_json'    => env('WARDEN_REQUIRE_JSON', false),
    ],

    // ── Audit & observability ────────────────────────────────────────────────
    'audit' => [
        'enabled' => env('WARDEN_AUDIT', true),
        'store'   => env('WARDEN_AUDIT_STORE', 'log'),
        'channel' => env('WARDEN_AUDIT_CHANNEL'),
        'store_raw' => false,
        'redact_in_logs' => true,
    ],

    // ── Verdict caching ──────────────────────────────────────────────────────
    'cache' => [
        'enabled' => env('WARDEN_CACHE', false),
        'ttl'     => 3600,
        'store'   => env('WARDEN_CACHE_STORE'),
        'prefix'  => 'warden',
    ],
];
```
