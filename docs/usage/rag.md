---
title: "RAG / Retrieval Guard"
description: "Treat retrieved chunks as untrusted input (indirect injection, LLM08)."
---

# RAG / Retrieval Guard

Retrieved documents, tool outputs, web pages and emails are **untrusted input**:
an attacker can plant instructions in a document that your model later ingests
(indirect prompt injection, OWASP LLM01 + LLM08). Pass them through the retrieval
guard before they enter the prompt.

## One chunk

```php
use Sellinnate\Warden\Facades\Warden;

$verdict = Warden::inspectRetrieval($chunk->text);

if ($verdict->blocked()) {
    // drop the poisoned chunk
}
```

## A batch of chunks

```php
use Sellinnate\Warden\Facades\Warden;
use Sellinnate\Warden\Guard;

$chunks   = RagEngine::retrieve($query);            // your retriever
$verdicts = app(Guard::class)->inspectChunks(
    collect($chunks)->pluck('text')->all()
);

$safe = collect($chunks)
    ->zip($verdicts)
    ->reject(fn ($pair) => $pair[1]->blocked())     // drop poisoned chunks
    ->map(fn ($pair) => $pair[1]->sanitizedText)    // use the sanitized text
    ->all();
```

## The retrieval policy

The `Direction::Retrieval` pipeline runs `normalize → injection → secret → pii`
by default — it focuses on neutralising planted instructions and stripping
secrets/PII from third-party content, without the output-handling stages.

::: callout tip "Selli suite"
Warden pairs naturally with *RAG Engine for Laravel*: the retrieval guard treats
recovered chunks as untrusted input, and an optional vector-similarity detector
can reuse the RAG embedding store for paraphrase-resistant injection detection.
:::
