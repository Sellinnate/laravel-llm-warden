# ADR-0002 — Phase 1 Deterministic MVP

**Status:** Accepted · **Phase:** 1 · **Date:** 2026-06-27

## Context

Phase 1 delivers the four core deterministic scanners (injection, secret, PII,
NSFW), the driver/manager pattern, validation rules, middleware and events — a
v0.1 that is useful and completely offline.

## Decisions

### D1 — Injection scoring combines probabilistically

The deterministic injection driver returns `1 - ∏(1 - sᵢ)` over matched signature
scores + obfuscation-signal weights + structural heuristics (many-shot, payload
splitting). This lets several weak signals accumulate toward a block without any
single one exceeding 1.0, and keeps the verdict explainable (every contributing
signal is listed). High precision is the priority; novel paraphrased jailbreaks
are explicitly out of deterministic scope (use an AI driver — Phase 3).

A versioned **corpus** (`tests/Corpus/`) gates precision/recall in CI: recall ≥ 95%
on attacks, false-positive-rate ≤ 5% on a benign corpus that includes code,
security discussion and multilingual text.

### D2 — Secrets detect on the delivered text, block on input / redact on output

High-signal prefixed patterns (AWS, GitHub, OpenAI, Anthropic, …) plus a generic
`key=value` catch-all gated on Shannon entropy. Detection runs on `current` so
spans map byte-accurately. Encoded (base64/hex) secrets are detected via the
decoded payloads and — because they can't be redacted in place — force a **block**
even under a Sanitize policy (Phase 1 review finding H3).

### D3 — PII follows Presidio's Analyzer/Anonymizer split

`PiiAnalyzer` runs a registry of `Detector`s and merges results with Presidio's
overlap rules (full overlap → higher score; containment → longer span; partial →
keep both). `PiiAnonymizer` applies a per-entity operator
(replace/redact/mask/hash/encrypt/keep/custom). Italian/EU entities are validated
by **checksum** (Codice Fiscale with omocodia, Partita IVA, IBAN mod-97, Luhn) so
they emit near-1.0 confidence with negligible false positives. NER entities
(PERSON/LOCATION) are deliberately driver-only.

Ambiguous regex-only entities (IP, bare local phone) **require a context word**
to emit, so version strings and order numbers don't trigger false 422s via the
`NoPii` rule (review finding M3).

### D4 — `encrypt` = reversible pseudonymization via the Vault

The `encrypt` operator stores the original in the per-request Vault and emits a
stable `<TYPE_N>` placeholder, enabling the output side to de-anonymize. The
`hash` operator is HMAC-SHA256 and refuses to run without a configured salt
(review finding M5). Plain `replace` emits a non-reversible `<TYPE>`.

### D5 — NSFW is intent-based and driver-augmented

The deterministic NSFW deny-list is intentionally small, tasteful and
intent-based (not a slur dictionary), mapped to the internal S1–S13 taxonomy. It
is acknowledged as a fragile first filter; real semantic coverage comes from a
`ModerationDriver` (Phase 3). The scanner merges deny-list hits with optional
driver categories.

### D6 — Driver/manager pattern, secret/pii in/out

`InjectionManager` and `ModerationManager` extend `Illuminate\Support\Manager`
(lazy, `extend()`-able, config-driven default). Per the threat model, secret and
PII scanners run on **both** input and output pipelines (output catches data the
model emitted that shouldn't ship); the output pipeline runs `deanonymize` first
(Phase 2) so legitimate placeholders are restored before leak detection.

### D7 — Middleware recurses; validation rules reject

`WardenMiddleware` recurses into nested arrays (the OpenAI `messages[]` shape) on
input and is JSON-aware on output (review finding H2/M4). Validation rules
(`NoPromptInjection`, `NoPii`, `Clean`) *reject* on detection — Laravel rules
can't mutate input, so accept-and-redact is the facade/middleware's job.

## Consequences

- A fully-offline v0.1 that blocks the common attack/leak classes with high
  precision and explainable verdicts.
- Every entity/pattern/operator is extensible via config or a registered class.
- The three High findings from the Phase 1 adversarial review (EMAIL ReDoS,
  nested-field bypass, encoded-secret-on-output leak) were fixed before merge.
