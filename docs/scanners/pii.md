---
title: "PII"
description: "Presidio-style PII detection and anonymization, EU/Italy-first."
---

# PII (LLM02)

The `PiiScanner` follows Microsoft Presidio's separation of **Analyzer** (find)
and **Anonymizer** (act). Detection runs against the delivered text so spans are
byte-accurate.

## Detected entities

High-precision, **checksum-validated** entities (near-1.0 confidence):

| Entity | Validation |
|--------|------------|
| `IT_FISCAL_CODE` | control-char algorithm (handles omocodia) |
| `IT_VAT` (Partita IVA) | mod-10 check digit |
| `IBAN` | ISO 7064 mod-97 |
| `CREDIT_CARD` | Luhn |

Plus regex entities: `EMAIL_ADDRESS`, `IP_ADDRESS`, `PHONE_NUMBER`. Ambiguous
shapes (IP, bare local phone) **require a context word** so version strings
(`1.2.3.4`) and order numbers don't false-positive.

```php
$v = Warden::inspect('Il mio CF è RSSMRA80A01H501U');
$v->hasDetectionType('IT_FISCAL_CODE'); // true
```

::: callout tip "NER entities are driver-only"
`PERSON` / `LOCATION` need a model, not regex. They are available via an optional
NER driver (`warden.pii.ner_driver`), never by default.
:::

## Operators

Each entity type maps to an **operator** (config `pii.operators`):

| Operator | Result |
|----------|--------|
| `replace` | `<EMAIL_ADDRESS>` (non-reversible placeholder) |
| `redact` | removed |
| `mask` | keep N chars, mask the rest (`from_end`, `char`) |
| `hash` | HMAC-SHA256 (requires a salt) |
| `encrypt` | reversible placeholder `<TYPE_N>` stored in the **Vault** |
| `keep` | untouched |
| `custom` | your closure |

```php
'pii' => [
    'operators' => [
        'IT_FISCAL_CODE' => ['op' => 'encrypt'],                       // -> Vault
        'IBAN'           => ['op' => 'mask', 'from_end' => true, 'chars' => 18],
        'EMAIL_ADDRESS'  => ['op' => 'replace'],
        'default'        => ['op' => 'replace'],
    ],
],
```

## Overlap resolution

When detectors overlap, Presidio's rules apply: full overlap → higher score wins;
containment → longer span wins; partial intersection → keep both.

## Direction-aware

- **Input:** applies your configured operators (e.g. `encrypt` → Vault).
- **Output:** always `replace` — any PII the *model* emitted is a leak to
  neutralise. Values the model legitimately got back from the Vault are restored
  first and marked trusted, so they're not re-redacted. See
  **[Vault Round-trip](/usage/vault)**.

## The `hash` operator needs a salt

`hash` uses HMAC-SHA256 and **refuses to run with an empty salt** (an unsalted
hash of low-cardinality PII is reversible):

```php
'pii' => ['hash_salt' => env('WARDEN_PII_HASH_SALT')],
```
