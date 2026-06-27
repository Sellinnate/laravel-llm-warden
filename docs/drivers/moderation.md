---
title: "Moderation (OpenAI / Azure)"
description: "Content-safety moderation drivers."
---

# Moderation Drivers

Moderation drivers feed the `NsfwScanner`. Both map their provider categories onto
Warden's internal **S1–S13** taxonomy.

## OpenAI

Uses `omni-moderation-latest`. Free, low latency. BYOK.

```php
'moderation' => [
    'driver' => 'openai',
    'openai' => [
        'key'   => env('OPENAI_API_KEY'),
        'model' => 'omni-moderation-latest',
        'timeout' => 5,
    ],
],
```

The 13 OpenAI sub-flags map onto the internal taxonomy (e.g. `sexual/minors → S4`,
`violence → S1`, `hate → S10`). Warden honours the provider's own `flagged`
decision and hard-floors **S4 (child sexual exploitation)** to a block.

## Azure Content Safety

Four categories with severity 0–7 (normalised to 0–1). BYOK.

```php
'moderation' => [
    'driver' => 'azure',
    'azure' => [
        'key'      => env('AZURE_CONTENT_SAFETY_KEY'),
        'endpoint' => env('AZURE_CONTENT_SAFETY_ENDPOINT'),
        'timeout'  => 5,
    ],
],
```

## Behaviour

- The driver's categories are **merged** with the deterministic deny-list.
- If the endpoint is down, the scanner **degrades to the deny-list** — coverage
  is never reduced below the offline baseline.
- Calls run with a timeout, bounded retries and a **[circuit breaker](/drivers/resilience)**.

## Testing

Drivers are fully fakeable:

```php
use Illuminate\Support\Facades\Http;

Http::preventStrayRequests();
Http::fake(['*moderations' => Http::response([
    'results' => [['flagged' => true, 'category_scores' => ['violence' => 0.9]]],
])]);
```
