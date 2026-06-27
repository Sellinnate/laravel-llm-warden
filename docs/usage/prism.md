---
title: "Prism & laravel-ai"
description: "The main integration: guard the input and output around any LLM SDK."
---

# Prism & laravel-ai

Warden is SDK-agnostic — it guards the **text** going to and coming from any LLM
client. The canonical pattern wraps a Prism call:

```php
use Sellinnate\Warden\Facades\Warden;
use Prism\Prism\Prism;
use Prism\Prism\Enums\Provider;

$verdict = Warden::sanitize($userPrompt);
abort_if($verdict->blocked(), 422);

$response = Prism::text()
    ->using(Provider::OpenAI, 'gpt-4o')
    ->withPrompt($verdict->sanitizedText)
    ->asText();

$safe = Warden::inspectOutput($response->text, vault: $verdict->vault);

return $safe->blocked()
    ? response()->json(['error' => 'output_blocked'], 422)
    : $safe->sanitizedText;
```

The same shape works with the official OpenAI/Anthropic SDKs, NeuronAI, LLPhant
or `laravel/ai` — Warden never touches the transport, only the strings.

## Warden's own AI drivers are independent of Prism

Warden's optional AI drivers — `openai` / `azure` moderation and the `llm-judge`
injection driver — call the provider's HTTP endpoint **directly** (using Laravel's
`Http` client, BYOK). They do **not** use the Prism package, and installing Prism
is neither required nor used by them. Prism (or the official OpenAI/Anthropic SDK,
NeuronAI, etc.) is only *your* app-side LLM client — the thing you call to actually
generate the answer, as shown above.

To enable Warden's AI drivers, just point them at a provider in `config/warden.php`:

```php
'moderation' => ['driver' => 'openai'],   // content-safety driver
'injection'  => ['driver' => 'llm-judge'], // semantic injection second-stage
```

See **[AI Drivers](/drivers/overview)** for the full driver matrix.

::: callout tip "Agents and tool-calling"
For agents, also guard **tool outputs** with the retrieval guard before they
re-enter the prompt — a poisoned tool return is indirect injection with your
app's privileges. See **[RAG / Retrieval Guard](/usage/rag)**.
:::
