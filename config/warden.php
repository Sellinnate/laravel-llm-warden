<?php

declare(strict_types=1);

return [

    /*
    |--------------------------------------------------------------------------
    | Default policy
    |--------------------------------------------------------------------------
    | The policy profile used by the facade when none is given explicitly.
    | One of: strict | balanced | permissive, or a custom policy you registered
    | via Warden::definePolicy().
    */
    'default_policy' => env('WARDEN_POLICY', 'balanced'),

    /*
    |--------------------------------------------------------------------------
    | Maximum input size (anti-DoS)
    |--------------------------------------------------------------------------
    | Inputs larger than this many bytes are truncated (on a UTF-8 boundary)
    | before scanning, and an `input_truncated` signal is recorded. 0 = no cap.
    */
    'max_input_bytes' => (int) env('WARDEN_MAX_INPUT_BYTES', 50_000),

    /*
    |--------------------------------------------------------------------------
    | AI driver selection (all optional; defaults are offline/deterministic)
    |--------------------------------------------------------------------------
    */
    'injection' => [
        'driver' => env('WARDEN_INJECTION_DRIVER', 'deterministic'),

        // For layered drivers (llm-judge): only escalate to the AI judge when the
        // deterministic score is below this (cheap-first).
        'escalate_below' => 0.5,

        'deterministic' => [
            // Risk score added per matched signature, capped at 1.0.
            'signal_weight' => 0.5,
        ],

        // Settings for external injection drivers (prompt-guard, prism-judge, lakera).
        'prompt_guard' => [
            'endpoint' => env('WARDEN_PROMPT_GUARD_ENDPOINT'),
            'timeout' => 5,
        ],
        'prism' => [
            'provider' => env('WARDEN_PRISM_PROVIDER', 'openai'),
            'model' => env('WARDEN_PRISM_MODEL', 'gpt-4o-mini'),
        ],
        'lakera' => [
            'key' => env('WARDEN_LAKERA_KEY'),
            'endpoint' => env('WARDEN_LAKERA_ENDPOINT', 'https://api.lakera.ai/v2/guard'),
            'timeout' => 5,
        ],
    ],

    'moderation' => [
        'driver' => env('WARDEN_MODERATION_DRIVER', 'null'),

        'openai' => [
            'key' => env('OPENAI_API_KEY'),
            'model' => env('WARDEN_OPENAI_MODERATION_MODEL', 'omni-moderation-latest'),
            'endpoint' => env('WARDEN_OPENAI_MODERATION_ENDPOINT', 'https://api.openai.com/v1/moderations'),
            'timeout' => 5,
        ],
        'azure' => [
            'key' => env('AZURE_CONTENT_SAFETY_KEY'),
            'endpoint' => env('AZURE_CONTENT_SAFETY_ENDPOINT'),
            'timeout' => 5,
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Fail policy per component
    |--------------------------------------------------------------------------
    | What happens when a scanner/driver errors or times out:
    |   closed = when in doubt, block · open = when in doubt, allow.
    */
    'fail_mode' => [
        'injection' => env('WARDEN_FAIL_INJECTION', 'open'),
        'pii' => env('WARDEN_FAIL_PII', 'closed'),
        'secret' => env('WARDEN_FAIL_SECRET', 'closed'),
        'nsfw' => env('WARDEN_FAIL_NSFW', 'open'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Normalization (the enabling pre-detector pass)
    |--------------------------------------------------------------------------
    */
    'normalize' => [
        'nfkc' => true,
        'confusables' => true,
        'strip_invisible' => true,
        'strip_bidi' => true,
        'strip_marks' => true,
        'deleet' => true,
        'collapse_spacing' => true,
        'decode_base64' => true,
        'max_decode_depth' => 3,
    ],

    /*
    |--------------------------------------------------------------------------
    | Injection module
    |--------------------------------------------------------------------------
    */
    'injection_scanner' => [
        'max_input_length' => 50_000,
    ],

    /*
    |--------------------------------------------------------------------------
    | Secret module
    |--------------------------------------------------------------------------
    */
    'secret' => [
        // Shannon-entropy gate for the generic key=value catch-all.
        'entropy_threshold' => 3.5,
    ],

    /*
    |--------------------------------------------------------------------------
    | PII module (Presidio-style operator per entity type)
    |--------------------------------------------------------------------------
    */
    'pii' => [
        'locale' => env('WARDEN_PII_LOCALE', 'it'),

        'operators' => [
            'IT_FISCAL_CODE' => ['op' => 'encrypt'],
            'IT_VAT' => ['op' => 'replace'],
            // Hide the account-number tail of the IBAN, reveal only the country/check head.
            'IBAN' => ['op' => 'mask', 'from_end' => true, 'chars' => 18],
            'CREDIT_CARD' => ['op' => 'mask', 'from_end' => true, 'chars' => 12],
            'EMAIL_ADDRESS' => ['op' => 'replace'],
            'PHONE_NUMBER' => ['op' => 'replace'],
            'IP_ADDRESS' => ['op' => 'replace'],
            'default' => ['op' => 'replace'],
        ],

        // Salt for the `hash` operator (referential integrity across requests).
        'hash_salt' => env('WARDEN_PII_HASH_SALT', ''),

        // Optional NER driver for PERSON/LOCATION (null = regex/checksum only).
        'ner_driver' => env('WARDEN_PII_NER'),
    ],

    /*
    |--------------------------------------------------------------------------
    | NSFW / content-safety module
    |--------------------------------------------------------------------------
    */
    'nsfw' => [
        'locales' => ['it', 'en'],
    ],

    /*
    |--------------------------------------------------------------------------
    | Output handling
    |--------------------------------------------------------------------------
    */
    'output' => [
        // Markdown-defang: domains whose links/images are allowed to stay active.
        'allowed_domains' => [],
        // System-prompt canary token to detect leakage (set per-request ideally).
        'canary' => env('WARDEN_CANARY'),
        // Optional system prompt: a verbatim echo of a long slice is flagged as a leak.
        'system_prompt' => env('WARDEN_SYSTEM_PROMPT'),
        // Require the LLM output to be valid JSON (FormatScanner): validate + repair.
        'require_json' => env('WARDEN_REQUIRE_JSON', false),
    ],

    /*
    |--------------------------------------------------------------------------
    | Audit & observability
    |--------------------------------------------------------------------------
    */
    'audit' => [
        'enabled' => env('WARDEN_AUDIT', true),
        'store' => env('WARDEN_AUDIT_STORE', 'log'), // log | database | null
        'channel' => env('WARDEN_AUDIT_CHANNEL'),
        'store_raw' => false,
        'redact_in_logs' => true,
    ],

    /*
    |--------------------------------------------------------------------------
    | Verdict caching
    |--------------------------------------------------------------------------
    */
    'cache' => [
        'enabled' => env('WARDEN_CACHE', false),
        'ttl' => 3600,
        'store' => env('WARDEN_CACHE_STORE'),
        'prefix' => 'warden',
    ],
];
