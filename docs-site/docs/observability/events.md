---
title: "Events"
description: "Domain events as a decoupled extension and metrics seam."
---

# Events

Warden dispatches domain events for non-trivial verdicts. They are a decoupled
seam: feed any metrics backend you already use (Sentry, Nightwatch, …), trigger
alerts, or build custom workflows.

| Event | Fired when |
|-------|-----------|
| `InjectionDetected` | the injection scanner produces detections |
| `PiiRedacted` | the PII scanner detects/redacts personal data |
| `SecretBlocked` | the secret scanner detects credentials |
| `OutputBlocked` | an output-direction scanner blocks the response |

## Listening

```php
use Illuminate\Support\Facades\Event;
use Sellinnate\Warden\Events\InjectionDetected;

Event::listen(function (InjectionDetected $event) {
    $event->direction;   // Direction
    $event->riskScore;   // float
    $event->blocked;     // bool
    $event->detections;  // Detection[]

    metrics()->increment('warden.injection', ['blocked' => $event->blocked]);
});
```

```php
use Sellinnate\Warden\Events\PiiRedacted;

Event::listen(function (PiiRedacted $event) {
    $event->entityTypes; // ['IT_FISCAL_CODE', 'EMAIL_ADDRESS', …]
});
```

::: callout tip "Events are redacted too"
Like audit records, events carry detection types/scores and masked evidence —
never raw secrets or PII values.
:::

## Useful metrics

Block rate per category, risk-score distribution, per-scanner latency, cache
hit-rate, external-driver error/timeout rate, circuit-breaker activations.
