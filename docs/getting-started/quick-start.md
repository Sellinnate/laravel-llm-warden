---
title: "Quick Start"
description: "The most common Warden flows in a few lines."
---

# Quick Start

## Inspect an input

`inspect()` runs the input pipeline and returns a **`Verdict`**. It mutates
nothing — you decide what to do.

```php
use Sellinnate\Warden\Facades\Warden;

$verdict = Warden::inspect($userPrompt);

$verdict->blocked();        // bool
$verdict->riskScore;        // 0.0 .. 1.0
$verdict->severity->name;   // Safe | Low | Medium | High
$verdict->detections();     // Detection[]
```

## Sanitize an input

`sanitize()` runs the same pipeline; you consume the cleaned text:

```php
$clean = Warden::sanitize($userPrompt)->sanitizedText;
```

## The full LLM round-trip

```php
use Sellinnate\Warden\Facades\Warden;
use Prism\Prism\Prism;
use Prism\Prism\Enums\Provider;

$verdict = Warden::sanitize($userPrompt);

abort_if($verdict->blocked(), 422, 'Prompt not allowed.');

$response = Prism::text()
    ->using(Provider::OpenAI, 'gpt-4o')
    ->withPrompt($verdict->sanitizedText)   // de-identified text to the model
    ->asText();

$safe = Warden::inspectOutput($response->text, vault: $verdict->vault);

return $safe->blocked()
    ? response()->json(['error' => 'output_blocked'], 422)
    : $safe->sanitizedText;                 // user's real data restored
```

::: callout tip "The Vault"
When PII is pseudonymized on input (the `encrypt` operator), the mapping is kept
in a per-request **Vault**. Pass `$verdict->vault` to `inspectOutput()` to restore
the user's real values in the answer. See **[Vault Round-trip](/usage/vault)**.
:::

## Guard a form request

```php
use Sellinnate\Warden\Rules\NoPromptInjection;
use Sellinnate\Warden\Rules\NoPii;

public function rules(): array
{
    return [
        'prompt' => ['required', 'string', 'max:8000', new NoPromptInjection],
        'bio'    => ['nullable', 'string', new NoPii],
    ];
}
```

## Guard a route

```php
Route::post('/chat', ChatController::class)->middleware('warden:input,strict');
```

The middleware sanitizes every (nested) string field and 422s on a block. The
controller reads the verdict via `$request->wardenVerdict()`.

## What next?

- **[Core Concepts → Architecture](/concepts/architecture)** — the five objects.
- **[Scanners](/scanners/injection)** — what each scanner does.
- **[Policies](/concepts/policies)** — tune thresholds and actions.
