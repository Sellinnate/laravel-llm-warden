---
title: "Verdicts & Detections"
description: "The immutable result objects returned by Warden."
---

# Verdicts & Detections

Every Warden call returns an immutable, serializable **`Verdict`**. Determinism
and explainability are guaranteed: the same input yields the same verdict, and
every detection reports its type, span, score and scanner.

## Verdict

```php
$verdict = Warden::inspect($text);

$verdict->valid;          // bool — passed all scanners
$verdict->blocked();      // ! valid
$verdict->riskScore;      // 0.0 .. 1.0 (max across scanners)
$verdict->severity;       // Severity::Safe|Low|Medium|High
$verdict->sanitizedText;  // text after sanitizing scanners
$verdict->originalText;   // pristine input
$verdict->results;        // array<string, ScanResult> keyed by scanner
$verdict->vault;          // ?Vault (present when PII was pseudonymized)

$verdict->detections();                       // flatten all Detection[]
$verdict->detectionsOfType('PROMPT_INJECTION');
$verdict->hasDetectionType('SECRET_AWS_ACCESS_KEY');
$verdict->result('pii');                      // ?ScanResult for one scanner
```

`Verdict` implements `Arrayable` and `JsonSerializable`, so it logs and caches
cleanly:

```php
json_encode($verdict);
// {"valid":false,"blocked":true,"risk_score":0.9,"severity":"High","sanitized_text":"…","results":{…}}
```

## ScanResult

One per scanner that ran:

```php
$result = $verdict->result('injection');

$result->scanner;        // 'injection'
$result->valid;          // bool
$result->riskScore;      // 0.0 .. 1.0
$result->sanitizedText;  // text after this scanner
$result->detections;     // Detection[]
$result->action;         // Action::Detect|Sanitize|Block
```

## Detection

A single typed finding (modelled on Presidio's `RecognizerResult`):

```php
$d = $verdict->detections()[0];

$d->type;     // 'IT_FISCAL_CODE' | 'PROMPT_INJECTION' | 'SECRET_AWS_ACCESS_KEY' | …
$d->start;    // byte offset (inclusive)
$d->end;      // byte offset (exclusive)
$d->score;    // 0.0 .. 1.0
$d->scanner;  // producing scanner
$d->context;  // redacted evidence (matched signal, masked snippet, …)
```

::: callout warning "Detections never carry raw secrets"
A `Detection`'s `context` keeps only a masked fingerprint of a secret/PII value,
never the raw value — so verdicts are safe to log. See
**[Audit & Compliance](/observability/audit)**.
:::

## Severity buckets

| Severity | Score |
|----------|-------|
| `Safe` | `< 0.2` |
| `Low` | `0.2 – 0.5` |
| `Medium` | `0.5 – 0.8` |
| `High` | `≥ 0.8` |
