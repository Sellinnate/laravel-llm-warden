---
title: "Caching"
description: "Memoize verdicts to collapse repeated inputs and zero out driver calls."
---

# Caching

Repeated inputs are extremely common in chatbots. Warden can memoize verdicts on a
hash of `(policy, direction, text)`, collapsing them to a lookup — which also
**zeroes out paid driver calls** for those inputs.

```php
'cache' => [
    'enabled' => env('WARDEN_CACHE', false),
    'ttl'     => 3600,
    'store'   => env('WARDEN_CACHE_STORE'), // null = default store
    'prefix'  => 'warden',
],
```

## Safety

::: callout warning "Vault verdicts are never cached"
A verdict that produced a **Vault** (reversible PII) is never cached — the Vault
is per-request and must never be shared between requests or tenants. Caching is
silently skipped for those.
:::

::: callout warning "Cached verdicts are redacted"
The cached copy drops the raw `originalText`, all per-detection evidence, and (for
blocked verdicts) the `sanitizedText` — only the decision, scores and detection
types are stored, so the cache can never become a leak source. On a cache hit the
returned verdict's `originalText` is empty; consume `sanitizedText` (allowed
inputs) and `blocked()` / `detections()` as usual. A cache hit still writes the
audit record and fires events.
:::

## Performance

The deterministic layer targets **p95 < 5 ms** on inputs up to ~4 KB on a single
CPU with no network. Caching turns hot inputs into a single store read. The
deny-lists are compiled once and reused; nothing is recompiled per request.

## Anti-DoS

Independent of caching: inputs over `max_input_bytes` (default 50 KB) are
truncated on a UTF-8 boundary, recursive decode is depth/size-bounded, and every
external driver has a timeout. A huge input can't saturate a worker's CPU.

```php
'max_input_bytes' => (int) env('WARDEN_MAX_INPUT_BYTES', 50_000),
```
