---
title: "Secrets"
description: "Credential & secret detection (OWASP LLM02)."
---

# Secrets (LLM02)

The `SecretScanner` detects credentials with high-signal, low-false-positive
patterns, plus a generic catch-all gated on **Shannon entropy**. It runs on input
*and* output.

## Default behaviour

- **Input / retrieval:** `block` — a secret in a prompt is almost always a mistake.
- **Output:** `sanitize` — the secret is redacted with `[REDACTED_SECRET]`.

```php
Warden::inspect('my key is AKIAIOSFODNN7EXAMPLE')->blocked(); // true

Warden::inspectOutput('here is sk-proj-… for you')->sanitizedText;
// "here is [REDACTED_SECRET] for you"
```

## Detected types

`SECRET_PEM_PRIVATE_KEY`, `SECRET_AWS_ACCESS_KEY`, `SECRET_GITHUB_PAT` /
`SECRET_GITHUB_TOKEN`, `SECRET_OPENAI_KEY`, `SECRET_ANTHROPIC_KEY`,
`SECRET_GOOGLE_API_KEY`, `SECRET_SLACK_TOKEN`, `SECRET_STRIPE_KEY`,
`SECRET_SENDGRID_KEY`, `SECRET_GITLAB_PAT`, `SECRET_TWILIO_KEY`,
`SECRET_NPM_TOKEN`, `SECRET_JWT`, and a `SECRET_GENERIC` catch-all.

## The entropy gate

The generic `key = value` catch-all only fires when the value's Shannon entropy
clears a threshold, so `password=hello` is ignored but a real high-entropy key is
flagged:

```php
'secret' => ['entropy_threshold' => 3.5],
```

## Encoded secrets

If a secret is hidden in base64/hex, normalization decodes it and the scanner
detects it. Because an encoded run can't be redacted in place, it **forces a
block** even under a sanitize policy — so it can never ship.

## Evidence is always masked

Detections never store the raw secret — only a short masked fingerprint
(`AKI*****`), so verdicts and audit records are safe to log.

## Add your own patterns

Add organisation-specific secret formats in `config/warden.php` (merged with the
built-ins):

```php
'secret' => [
    'patterns' => [
        ['type' => 'SECRET_INTERNAL', 'score' => 0.95, 'pattern' => '/\bint_live_[0-9a-f]{32}\b/'],
    ],
],
```

Each entry needs a `type`, a `score` (0–1) and a `pattern` (a PCRE regex). An
optional `group` (capture-group index) and `entropy => true` (only flag when the
captured value has high Shannon entropy) are also supported.
