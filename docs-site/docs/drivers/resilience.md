---
title: "Resilience"
description: "Timeouts, retries, fail policy and circuit breaker for external drivers."
---

# Resilience

External drivers can be slow or down. Warden never lets that fail your request in
an unexpected way.

## Timeout & retry

Every external call runs with a configured timeout and bounded retries
(`Http::retry`). Worst-case latency is capped.

## Per-scanner fail policy

When a driver throws, the **fail mode** for that scanner decides:

- **closed** — *when in doubt, block* (safe defaults for PII/secret);
- **open** — *when in doubt, allow* (favours availability for external judges).

```php
'fail_mode' => ['injection' => 'open', 'pii' => 'closed', 'secret' => 'closed', 'nsfw' => 'open'],
```

::: callout tip "Coverage is never reduced"
For NSFW, a moderation outage **degrades to the deterministic deny-list** — it
never drops below the offline baseline, even under fail-open. The injection layer
falls back to the deterministic verdict the same way.
:::

## Circuit breaker

After N consecutive failures of an endpoint, a cache-backed circuit breaker
**opens** for a cooldown and calls fail fast (so the fail policy takes over
cheaply) instead of repeatedly hanging. Breaker state is keyed per
endpoint+credentials, so one BYOK tenant's outage can't open the circuit for
others.

```php
'cache' => ['store' => env('WARDEN_CACHE_STORE')], // Redis recommended for shared breaker state
```

## Putting it together

```text
request → driver call (timeout, retry)
        → success → record success, use verdict
        → failure → record failure → fail mode (open/closed)
        → breaker open → fail fast → fail mode
```

This is why enabling an external driver is always safe: at worst you fall back to
the deterministic guarantee.
