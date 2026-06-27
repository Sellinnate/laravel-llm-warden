---
title: "LLM Judge"
description: "LLM-as-judge for semantic injection detection — a layered second stage."
---

# LLM Judge

The `llm-judge` injection driver calls an OpenAI-compatible chat-completions
endpoint with a hardened classifier prompt and structured JSON output. It catches
the **semantic, paraphrased** jailbreaks the deterministic layer can't.

In `config/warden.php`:

```php
'injection' => [
    'driver' => 'llm-judge',
    'escalate_below' => 0.5,        // only escalate when deterministic is inconclusive
    'llm_judge' => [
        'key'      => env('OPENAI_API_KEY'),
        'model'    => 'gpt-4o-mini',
        'endpoint' => 'https://api.openai.com/v1/chat/completions',
        'timeout'  => 8,
    ],
],
```

::: callout tip "No Prism / SDK required"
The `llm_judge` block just configures an OpenAI-compatible chat endpoint that
Warden calls directly with Laravel's `Http` client (BYOK). You do **not** need to
install Prism or any other LLM SDK for the judge to work.
:::

## How it's wired

The judge is **layered** on the deterministic driver:

1. The deterministic driver runs first (free).
2. If its score is already ≥ `escalate_below`, that verdict stands — **no judge
   call**.
3. Otherwise the judge runs and the verdicts combine with `max()`.

So the judge only ever *raises* risk, and a gamed judge can never lower the
deterministic floor.

## Hardened against injection

The judge is itself a target. Warden mitigates this:

- a hardened system prompt instructs the classifier to treat the input strictly
  as **data**, never instructions;
- the untrusted text is fenced and any literal fence markers it contains are
  broken, so it can't escape the fence;
- result parsing is crash-safe and clamps the score to `[0, 1]`, failing toward
  over-blocking.

## Resilience

The judge is wrapped in a **[circuit breaker](/drivers/resilience)**; if it's
failing or open, the deterministic verdict stands — a dead judge degrades to the
offline layer rather than failing requests.

::: callout tip "Cost"
Because escalation is cheap-first, the judge only runs on the small fraction of
inputs the deterministic layer can't decide — keeping token spend low.
:::
