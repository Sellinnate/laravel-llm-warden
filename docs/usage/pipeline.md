---
title: "Pipeline API"
description: "The Level-2 fluent, configured-at-call API."
---

# Pipeline API

For advanced cases, configure a one-off scan fluently starting from a named
policy.

```php
use Sellinnate\Warden\Facades\Warden;
use Sellinnate\Warden\Enums\Direction;

$verdict = Warden::for(Direction::Input)
    ->usingPolicy('balanced')
    ->only(['normalize', 'injection', 'pii'])   // subset of scanners
    ->withThreshold('injection', 0.7)
    ->failClosed()
    ->scan($userPrompt);
```

## Methods

| Method | Effect |
|--------|--------|
| `usingPolicy(string)` | Start from a named policy |
| `only(array)` | Restrict to a subset of scanner names |
| `withThreshold(string, float)` | Override a scanner's threshold |
| `withAction(string, Action)` | Override a scanner's action |
| `failClosed()` | Enforce fail-fast |
| `scan(string, ?Vault)` | Run and return the `Verdict` |
| `sanitizedText(string)` | Convenience: return only the cleaned text |

## Directions

```php
Warden::for(Direction::Input)->scan($prompt);
Warden::for(Direction::Output)->scan($response);
Warden::for(Direction::Retrieval)->scan($chunk);
```

::: callout tip "When to use this vs. the facade"
Reach for the pipeline API when a single endpoint needs a one-off tweak (a higher
injection threshold, only PII redaction, etc.). For app-wide behaviour, prefer a
**[custom policy](/concepts/policies)** so the configuration is reusable and named.
:::
