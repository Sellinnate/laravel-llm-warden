---
title: "Policies"
description: "Reusable bundles of scanners, thresholds, actions and fail modes."
---

# Policies

A **policy** is an immutable, reusable bundle of *which scanners run, in what
order, with what threshold, action and fail mode*. The active policy is the only
thing that decides whether a detection becomes a block — never the detector.

## Built-in profiles

| Profile | Philosophy | Thresholds | Fail mode |
|---------|------------|------------|-----------|
| `strict` | Maximum safety, accepts more false positives | injection 0.5, nsfw 0.4 | closed |
| `balanced` *(default)* | Balance of precision and coverage | injection 0.7, nsfw 0.6 | mixed |
| `permissive` | Minimum friction, only severe risks | injection 0.85 | open |

Select the default in config (`default_policy`) or per call:

```php
Warden::inspect($text, 'strict');
```

## Actions

Each scanner has a default action; the policy can override it.

| Action | Meaning |
|--------|---------|
| `Detect` | Only report — record detections, never mutate or block |
| `Sanitize` | Transform the text (redact/mask/encrypt/defang), let it through |
| `Block` | Reject the payload |

```php
use Sellinnate\Warden\Enums\Action;
use Sellinnate\Warden\Facades\Warden;
use Sellinnate\Warden\Policies\PolicyBuilder;

// Roll out in "detect-only" mode first, then tighten.
Warden::definePolicy('rollout', fn (PolicyBuilder $p) => $p->action('injection', Action::Detect));
```

## Custom policies

Register a custom profile in a service provider with the fluent `PolicyBuilder`:

```php
use Sellinnate\Warden\Facades\Warden;
use Sellinnate\Warden\Policies\PolicyBuilder;
use Sellinnate\Warden\Enums\Action;

Warden::definePolicy('public-chatbot', fn (PolicyBuilder $p) => $p
    ->inputScanners(['normalize', 'injection', 'nsfw', 'pii'])
    ->outputScanners(['normalize', 'deanonymize', 'output-leak', 'markdown-defang', 'nsfw'])
    ->threshold('injection', 0.75)
    ->action('pii', Action::Sanitize)
    ->failClosed()
);

Warden::inspect($text, 'public-chatbot');
```

## Fail modes

When an external driver errors or times out, the per-scanner fail mode decides:

- **closed** — *when in doubt, block* (safe for PII/secret);
- **open** — *when in doubt, allow* (favours availability for external judges).

Config overrides (`warden.fail_mode`) are applied on top of every profile:

```php
'fail_mode' => ['injection' => 'open', 'pii' => 'closed', 'secret' => 'closed'],
```

::: callout tip "Multi-tenancy"
Resolve a different policy per tenant by reading tenant config and calling
`Warden::inspect($text, $tenantPolicy)`. The Vault is always per-request and never
shared.
:::
