---
title: "Warden for Laravel"
description: "Enterprise prompt sanitization & LLM guardrails for Laravel — deterministic-first, offline-by-default, EU-resident."
image: "https://laravel-warden.selli.io/assets/images/banner.png"
ogImage: "https://laravel-warden.selli.io/assets/images/banner.png"
---

![LLM Warden for Laravel — AI guardrails & security](/assets/images/banner.png)

# Warden for Laravel

**Warden** sits between your application and any LLM as a **bidirectional
guardrail layer**. On the way *in* it normalises and inspects prompts (prompt
injection, jailbreak, PII, secrets); on the way *out* it validates and filters the
model's response (unsafe content, data leaks, markdown exfiltration, malformed
output).

::: callout tip "Deterministic-first, offline-by-default"
The core is a rule/heuristic engine that runs **offline at zero cost** — fast
(p95 < 5 ms), explainable and fully testable. Optional, swappable AI drivers add
semantic coverage when you want it. Zero mandatory dependencies beyond
`illuminate/contracts`.
:::

## In one line

```php
use Sellinnate\Warden\Facades\Warden;

$verdict = Warden::inspect($userPrompt);

if ($verdict->blocked()) {
    abort(422, 'Prompt not allowed.');
}

$clean = Warden::sanitize($userPrompt)->sanitizedText; // ready for the LLM
```

## Why Warden

::: card "Deterministic-first"
A high-precision rule layer catches the whole class of obfuscation/evasion
attacks for free, before you ever spend a token. AI is a second stage, never a
prerequisite.
:::

::: card "Normalize before every check"
A single pass — NFKC, confusable folding, invisible/bidi stripping, combining-mark
removal, de-leet, spacing collapse, recursive base64/hex decode — precedes every
detector, so deny-lists can't be bypassed with `1gn0r3` or zero-width tricks.
:::

::: card "Find vs. act are separate"
Detectors return typed spans with scores; the action (allow / redact / mask /
encrypt / block / flag) is a **policy** decision — the Presidio principle applied
to the whole package.
:::

::: card "EU / Italy aware"
Codice Fiscale, Partita IVA and IBAN validated by checksum; GDPR / EU AI Act
friendly; nothing leaves your infrastructure by default (BYOK for any driver).
:::

## The four core mandates

Warden is anchored to the **OWASP Top 10 for LLM Applications (2025)**:

| OWASP | Concern | Warden |
|-------|---------|--------|
| **LLM01** | Prompt Injection | `InjectionScanner` (+ retrieval guard) |
| **LLM02** | Sensitive Information Disclosure | `PiiScanner` + `SecretScanner` (in/out) |
| **LLM05** | Improper Output Handling | `MarkdownDefangScanner` + `FormatScanner` |
| **LLM07** | System Prompt Leakage | `OutputLeakScanner` (canary) |

## Next steps

- **[Installation →](/getting-started/installation)**
- **[Quick Start →](/getting-started/quick-start)**
- **[Architecture →](/concepts/architecture)**
