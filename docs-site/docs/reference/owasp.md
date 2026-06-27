---
title: "OWASP LLM Coverage"
description: "How Warden maps to the OWASP Top 10 for LLM Applications and content-safety taxonomies."
---

# OWASP LLM Coverage

Warden is anchored to the **OWASP Top 10 for LLM Applications (2025)**.

| OWASP 2025 | Item | Warden coverage |
|------------|------|-----------------|
| **LLM01** | Prompt Injection | **Direct** — `InjectionScanner` (direct + indirect via retrieval guard) |
| **LLM02** | Sensitive Information Disclosure | **Direct** — `PiiScanner` + `SecretScanner` (in/out) |
| LLM03 | Supply Chain | Indirect — the package's own dependency discipline |
| LLM04 | Data & Model Poisoning | Out of scope (training-time) |
| **LLM05** | Improper Output Handling | **Direct** — `MarkdownDefangScanner` + `FormatScanner` |
| LLM06 | Excessive Agency | **Partial** — output/tool guard reduces surface; authorization stays the app's |
| **LLM07** | System Prompt Leakage | **Partial** — `OutputLeakScanner` (canary + echo) |
| LLM08 | Vector & Embedding Weaknesses | **Partial** — retrieval guard for indirect injection via RAG |
| LLM09 | Misinformation | Out of deterministic scope (needs a groundedness judge) |
| LLM10 | Unbounded Consumption | **Partial** — length/decode limits and driver budgets |

The three core mandates are **LLM01, LLM02, LLM05**.

## Prompt-injection taxonomy

Warden adopts the canonical OWASP/MITRE ATLAS distinction:

- **Direct injection** (`AML.T0051.000`) — the payload arrives in the user's own
  channel. Inspected by the input pipeline.
- **Indirect injection** (`AML.T0051.001`) — the payload arrives via content the
  model ingests (RAG documents, web pages, tool output, emails). Inspected by the
  **[retrieval guard](/usage/rag)**.

> An injection doesn't need to be human-readable — it only needs the model to
> interpret it. Warden inspects bytes and code points, not the rendered view.

## Content-safety taxonomy mapping

Warden's internal taxonomy is **Llama Guard / MLCommons S1–S13**. Provider
categories are mapped onto it (approximate, by nature):

| Internal (S1–S13) | OpenAI Moderation | Azure Content Safety |
|-------------------|-------------------|----------------------|
| S1 Violent / S2 Non-Violent Crimes | illicit, illicit/violent, violence | Violence |
| S3 Sex Crimes / S4 Child Exploitation | sexual, **sexual/minors** | Sexual |
| S10 Hate | hate, hate/threatening, harassment | Hate and Fairness |
| S11 Suicide & Self-Harm | self-harm (+intent/instructions) | Self-Harm |
| S12 Sexual Content | sexual | Sexual |

The mapping is heuristic (Azure has 4 coarse buckets, OpenAI 13 sub-flags, Llama
Guard 13 granular categories), so Warden also honours the provider's own
`flagged` decision rather than relying only on mapped scores.
