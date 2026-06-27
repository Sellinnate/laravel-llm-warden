---
title: "Facade & One-liners"
description: "The Level-1 public API."
---

# Facade & One-liners

The `Warden` facade is the 90%-of-cases entry point. Every method returns a
**`Verdict`**.

```php
use Sellinnate\Warden\Facades\Warden;
```

## inspect()

Run the input pipeline; mutate nothing.

```php
$verdict = Warden::inspect($userPrompt);
$verdict = Warden::inspect($userPrompt, 'strict'); // explicit policy
```

## sanitize()

Same pipeline; you consume the cleaned text.

```php
$clean = Warden::sanitize($userPrompt)->sanitizedText;
```

## inspectOutput()

Run the output pipeline on the LLM's response, optionally restoring the Vault.

```php
$safe = Warden::inspectOutput($llmResponse, vault: $verdict->vault);
```

## inspectRetrieval() / inspectChunks()

Treat retrieved content as untrusted (indirect injection). See **[RAG](/usage/rag)**.

```php
use Sellinnate\Warden\Facades\Warden;
use Sellinnate\Warden\Guard;

$verdict  = Warden::inspectRetrieval($chunkText);

// inspectChunks() is the batch helper — it lives on the Guard instance, NOT on
// the facade. Resolve the Guard from the container to use it.
$verdicts = app(Guard::class)->inspectChunks($chunks);
```

## Custom policies

```php
use Sellinnate\Warden\Policies\PolicyBuilder;

Warden::definePolicy('my-policy', fn (PolicyBuilder $p) => $p
    ->inputScanners(['normalize', 'injection', 'pii'])
    ->threshold('injection', 0.8)
);
```

## Framework-agnostic

Outside a full Laravel app:

```php
use Sellinnate\Warden\Guard;

$guard = Guard::make(['default_policy' => 'strict']);
$verdict = $guard->inspect($anyInput);
```

## Public API surface (SemVer)

Bound by SemVer: the `Warden` facade and its methods; the `Contracts\*`
interfaces; the `Verdict` / `ScanResult` / `Detection` value objects; the domain
enums; the top-level `config/warden.php` keys; the `extend*()` methods; the
middleware and validation-rule signatures; the event names. Concrete driver/
scanner classes and deny-list contents are internal and may change.
