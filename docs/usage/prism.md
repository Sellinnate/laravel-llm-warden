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

## Sharing Prism as the AI driver

If you already use Prism, you can also let Warden use it for the **moderation**
and **judge** drivers (Prism gives OpenAI moderation and multi-provider structured
output from one dependency). Configure the OpenAI moderation driver and the LLM
judge:

```php
'moderation' => ['driver' => 'openai'],
'injection'  => ['driver' => 'llm-judge'],
```

See **[AI Drivers](/drivers/overview)** for the full driver matrix.

::: callout tip "Agents and tool-calling"
For agents, also guard **tool outputs** with the retrieval guard before they
re-enter the prompt — a poisoned tool return is indirect injection with your
app's privileges. See **[RAG / Retrieval Guard](/usage/rag)**.
:::
