---
title: "Audit & Compliance"
description: "Redacted audit trail, log redaction, GDPR & EU AI Act posture."
---

# Audit & Compliance

## Audit trail

Every non-trivial verdict (any detection or block) produces an optional audit
record, designed for defensibility after an incident or a controller request. It
contains the timestamp, direction, active policy, scanners that fired, detection
types and scores, action and severity — and an integrity **hash** of the input.

```php
'audit' => [
    'enabled'   => true,
    'store'     => 'log',  // log | database | null
    'channel'   => env('WARDEN_AUDIT_CHANNEL'),
    'store_raw' => false,  // never store raw text by default
],
```

The default `LogAuditor` writes to a PSR-3 logger; only non-trivial verdicts are
logged (`warning` for blocks, `info` otherwise). Swap it for your own by binding
the `Contracts\Auditor` interface.

## Log redaction (non-negotiable)

The guardrail must never become a leak source. PII and secrets are **always**
redacted in logs and events — detections carry only a masked fingerprint, never
the raw value, and `store_raw=false` keeps the original text out of the sink.

Each audit record contains only:

- `direction` — input / output / retrieval;
- `valid` / `risk_score` / `severity` — the decision;
- `detections` — a list of `{ type, scanner, score }` (no raw values);
- `text_hash` — a non-reversible hash of the input (so you can correlate repeats
  without storing the text).

A blocked prompt containing an AWS key produces a record where the key never
appears — only `{"type":"SECRET_AWS_ACCESS_KEY","scanner":"secret","score":0.97}`
and the hash.

## GDPR & EU AI Act

In the default (deterministic-only) configuration, **no data leaves your
infrastructure**. Enabling an external driver is an explicit, BYOK choice and the
data goes only to the provider you configured.

Warden gives you the tools to meet your obligations — pseudonymization via the
**[Vault](/usage/vault)** before any egress, PII/secret redaction, a redacted
audit trail — without claiming to replace your legal assessment. With respect to
the **EU AI Act**, Warden is a documentable *risk-mitigation* measure to cite in
your technical safeguards, not a certification of conformity.

::: callout warning "Risk mitigation, not a guarantee"
Warden reduces a real, well-understood class of risk. It does not make an LLM
system "safe" on its own — pair it with the rest of your defence-in-depth and
communicate its limits honestly.
:::
