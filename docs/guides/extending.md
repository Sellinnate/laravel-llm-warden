---
title: "Extending Warden"
description: "Add a custom injection/moderation driver or a custom scanner — without forking the package."
---

# Extending Warden

Warden is built around a few small interfaces (**contracts**). You add behaviour
by writing a class that implements one of them and **registering** it — you never
fork the package. All registration happens in the `boot()` method of a service
provider (e.g. your app's `App\Providers\AppServiceProvider`).

::: callout tip "You only need this page if you're customising Warden"
For everyday use you never implement these interfaces. Read on only if the
built-in scanners/drivers don't cover something you need.
:::

## Add a custom injection driver

Use this to plug in your own prompt-injection backend (a self-hosted classifier,
a different AI provider, …). Implement
`Sellinnate\Warden\Contracts\InjectionDriver` and return an `InjectionVerdict`
(a `score` from 0 to 1, plus optional `signals` for diagnostics).

```php
namespace App\Warden;

use Sellinnate\Warden\Contracts\InjectionDriver;
use Sellinnate\Warden\Support\ScanContext;
use Sellinnate\Warden\ValueObjects\InjectionVerdict;

final class MyInjectionDriver implements InjectionDriver
{
    public function evaluate(string $normalized, ScanContext $context): InjectionVerdict
    {
        // $normalized is the de-obfuscated text to classify.
        $score = $this->callMyClassifier($normalized); // 0.0 .. 1.0

        return new InjectionVerdict($score, signals: ['my-classifier'], driver: 'my-driver');
    }

    public function name(): string
    {
        return 'my-driver';
    }
}
```

Register it and select it:

```php
// AppServiceProvider::boot()
use Sellinnate\Warden\Managers\InjectionManager;

$this->app->make(InjectionManager::class)
    ->extend('my-driver', fn ($app) => new \App\Warden\MyInjectionDriver());
```

```php
// config/warden.php
'injection' => ['driver' => 'my-driver'],
```

## Add a custom moderation driver

Same pattern for content-safety. Implement
`Sellinnate\Warden\Contracts\ModerationDriver` and return a `ModerationVerdict`
(`flagged`, plus per-category scores keyed by the internal `S1`–`S13` taxonomy).

```php
namespace App\Warden;

use Sellinnate\Warden\Contracts\ModerationDriver;
use Sellinnate\Warden\ValueObjects\ModerationVerdict;

final class MyModerationDriver implements ModerationDriver
{
    public function moderate(string $text): ModerationVerdict
    {
        $scores = ['S1' => 0.0, 'S10' => 0.0]; // category => 0..1
        $flagged = max($scores) >= 0.5;

        return new ModerationVerdict($flagged, $scores, driver: 'my-moderation');
    }

    public function name(): string
    {
        return 'my-moderation';
    }
}
```

```php
// AppServiceProvider::boot()
use Sellinnate\Warden\Managers\ModerationManager;

$this->app->make(ModerationManager::class)
    ->extend('my-moderation', fn ($app) => new \App\Warden\MyModerationDriver());

// config/warden.php
'moderation' => ['driver' => 'my-moderation'],
```

## Add a custom scanner

A scanner is a full pipeline stage. Implement
`Sellinnate\Warden\Contracts\Scanner` and return a `ScanResult`.

```php
namespace App\Warden;

use Sellinnate\Warden\Contracts\Scanner;
use Sellinnate\Warden\Enums\Action;
use Sellinnate\Warden\Enums\Direction;
use Sellinnate\Warden\Support\ScanContext;
use Sellinnate\Warden\ValueObjects\ScanResult;

final class ProfanityScanner implements Scanner
{
    public function supports(Direction $direction): bool
    {
        return $direction === Direction::Input;
    }

    public function scan(ScanContext $context): ScanResult
    {
        $blocked = str_contains(strtolower($context->normalized), 'badword');

        return new ScanResult(
            scanner: $this->name(),
            valid: ! $blocked,            // false => the pipeline blocks
            riskScore: $blocked ? 1.0 : 0.0,
            sanitizedText: $context->current,
            detections: [],
            action: Action::Block,
        );
    }

    public function name(): string
    {
        return 'profanity';
    }
}
```

Register it under a stable name, then add that name to a **policy** so it actually
runs:

```php
// AppServiceProvider::boot()
use Sellinnate\Warden\Facades\Warden;
use Sellinnate\Warden\Policies\PolicyBuilder;
use Sellinnate\Warden\Support\ScannerRegistry;

$this->app->make(ScannerRegistry::class)
    ->register('profanity', \App\Warden\ProfanityScanner::class);

Warden::definePolicy('with-profanity', fn (PolicyBuilder $p) => $p
    ->inputScanners(['normalize', 'injection', 'profanity'])
);
```

```php
Warden::inspect($text, 'with-profanity');
```

::: callout warning "Custom scanners must be added to a policy"
Registering a scanner only makes its name resolvable. A scanner runs only when a
policy lists it (the built-in `strict` / `balanced` / `permissive` policies don't
know about your custom names), so define a custom policy that includes it.
:::

## What the contracts give you

| Contract | Method | Returns |
|----------|--------|---------|
| `InjectionDriver` | `evaluate(string $normalized, ScanContext $ctx)` | `InjectionVerdict` |
| `ModerationDriver` | `moderate(string $text)` | `ModerationVerdict` |
| `Scanner` | `scan(ScanContext $ctx)` | `ScanResult` |

`ScanContext` is the object that travels through the pipeline; inside a custom
scanner/driver you mainly read `$context->normalized` (the de-obfuscated text),
`$context->current` (the text being delivered) and `$context->direction`.
