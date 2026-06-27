---
title: "AI Drivers Overview"
description: "Optional, interchangeable AI components — off by default."
---

# AI Drivers

AI components are **optional and interchangeable**. Warden works out of the box
with the `deterministic` / `null` drivers (zero dependencies, zero network). Each
driver normalises its output into Warden's internal value objects, so the rest of
the pipeline is agnostic to the model behind it.

## Driver matrix

| Component | Driver | Dependency | Notes |
|-----------|--------|------------|-------|
| Injection | `deterministic` *(default)* | none | regex + heuristics + Unicode signals |
| Injection | `llm-judge` | OpenAI-compatible chat endpoint (BYOK) | LLM-as-judge, layered on top |
| Moderation | `null` *(default)* | none | uses the deterministic deny-list |
| Moderation | `openai` | OpenAI key (BYOK) | `omni-moderation-latest`, 13 categories |
| Moderation | `azure` | Azure Content Safety (BYOK) | 4 categories + severity 0–7 |

## Execution hierarchy

Warden filters with the cheap layers first and only spends on the costly ones for
the residual:

```text
normalize → signatures/regex/canary (deterministic, ~ms, free)
          → classifier / LLM-judge (costly, opt-in)
```

The judge is **layered**: the deterministic driver runs first and the judge is
called only when the deterministic score is inconclusive. Verdicts combine with
`max()`, so the judge can only *raise* risk — never lower the deterministic floor.

## Enabling a driver

```php
'injection'  => ['driver' => 'llm-judge'],
'moderation' => ['driver' => 'openai'],
```

::: callout warning "Egress is explicit"
Enabling an external driver sends data to the provider you configured, with your
key. In the default (deterministic) configuration, nothing leaves your
infrastructure.
:::

## Adding your own driver

```php
use Sellinnate\Warden\Facades\Warden; // or resolve the manager

app(\Sellinnate\Warden\Managers\InjectionManager::class)
    ->extend('my-driver', fn ($app) => new MyInjectionDriver());
```
