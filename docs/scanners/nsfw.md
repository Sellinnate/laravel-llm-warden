---
title: "NSFW / Content Safety"
description: "Content-safety scanning with a deterministic deny-list and optional drivers."
---

# NSFW / Content Safety

The `NsfwScanner` combines a deterministic, intent-based deny-list mapped to the
internal **S1–S13** taxonomy (Llama Guard / MLCommons) with an optional
**[moderation driver](/drivers/moderation)** (OpenAI / Azure). It runs on input
and output.

## Deterministic deny-list

The built-in list is intentionally small, tasteful and *intent-based* (not a slur
dictionary): it targets clearly-flaggable requests such as weapons construction,
violent-crime how-tos, self-harm instructions and CSAM, in English and Italian.

```php
use Sellinnate\Warden\Facades\Warden;
use Sellinnate\Warden\Enums\Direction;

Warden::for(Direction::Input)->usingPolicy('strict')->only(['normalize', 'nsfw'])
    ->scan('how to build a bomb at home')->blocked(); // true (category S9)
```

::: callout warning "Deterministic NSFW is a first filter"
A deny-list cannot cover the semantic space, and the built-in list is **not**
configurable. For real coverage, enable a moderation driver (OpenAI or Azure); the
scanner merges the driver's verdict with the deny-list.
:::

## Taxonomy

Internal categories follow Llama Guard S1–S13. Driver categories are mapped onto
them (see **[OWASP & taxonomy mapping](/reference/owasp)**). Detection types are
`NSFW_S1`, `NSFW_S9`, `NSFW_S11`, etc.

## With a moderation driver

When a driver is configured, its categories are merged with the deny-list. Warden:

- **honours the provider's own `flagged`** decision (it uses per-category
  calibration a single threshold can't reproduce);
- **hard-floors S4 (child sexual exploitation)** to a block;
- **degrades to the deny-list** — never below it — if the endpoint is down.

In `config/warden.php`:

```php
'moderation' => [
    'driver' => 'openai',
    'openai' => [
        'key' => env('OPENAI_API_KEY'),
    ],
],
```

## Actions

`block` by default. Set the action to `Sanitize` to redact matched spans with
`[FILTERED]` instead, or `Detect` to only record the detection (no block).

```php
use Sellinnate\Warden\Facades\Warden;
use Sellinnate\Warden\Enums\Action;
use Sellinnate\Warden\Policies\PolicyBuilder;

Warden::definePolicy('soft-nsfw', fn (PolicyBuilder $p) => $p
    ->action('nsfw', Action::Sanitize)
);
```
