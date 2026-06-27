---
title: "Contracts & Value Objects"
description: "The stable, public interfaces and result objects you can build against."
---

# Contracts & Value Objects

These are the parts of Warden covered by semantic versioning — safe to depend on.
The concrete scanner/driver classes behind them are internal and may change.

## Public surface (bound by SemVer)

- the `Warden` facade and its methods;
- the interfaces in `Sellinnate\Warden\Contracts\*`;
- the value objects `Verdict`, `ScanResult`, `Detection`;
- the enums (`Direction`, `Action`, `Severity`, `FailMode`);
- the top-level keys of `config/warden.php`;
- the validation rules, middleware alias and event names.

## Contracts (for extension authors)

You implement one of these only when [extending Warden](/guides/extending).

```php
namespace Sellinnate\Warden\Contracts;

interface Scanner
{
    public function supports(Direction $direction): bool;   // which directions it runs on
    public function scan(ScanContext $context): ScanResult; // run and return a result
    public function name(): string;                         // stable id used in policies/config
}

interface InjectionDriver
{
    public function evaluate(string $normalized, ScanContext $context): InjectionVerdict;
    public function name(): string;
}

interface ModerationDriver
{
    public function moderate(string $text): ModerationVerdict;
    public function name(): string;
}

interface Auditor
{
    public function record(Verdict $verdict, Direction $direction): void;
}
```

## Value objects (what you read)

These are immutable and serializable.

### `Verdict`

The aggregate returned by every `Warden::*` call. See
**[Verdicts & Detections](/concepts/verdicts)** for the full property list and
helper methods (`blocked()`, `detections()`, `hasDetectionType()`, `result()`).

### `ScanResult`

One per scanner that ran: `scanner`, `valid`, `riskScore`, `sanitizedText`,
`detections`, `action`.

### `Detection`

A single finding: `type`, `start`, `end` (byte offsets), `score`, `scanner`,
`context` (diagnostic, not a stable shape).

## Enums

| Enum | Cases |
|------|-------|
| `Direction` | `Input`, `Output`, `Retrieval` |
| `Action` | `Detect`, `Sanitize`, `Block` |
| `Severity` | `Safe`, `Low`, `Medium`, `High` |
| `FailMode` | `Open`, `Closed` |
