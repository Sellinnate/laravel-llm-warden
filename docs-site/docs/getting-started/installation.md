---
title: "Installation"
description: "Install Warden for Laravel via Composer."
---

# Installation

## Requirements

| Requirement | Version |
|-------------|---------|
| PHP | `^8.3` (tested on 8.3, 8.4) |
| Laravel | 12 · 13 |
| Extensions | `ext-intl`, `ext-mbstring` |

Warden depends only on `illuminate/contracts` — **not** on `laravel/framework` —
so it stays flexible across framework majors and imposes nothing on consumers. No
AI dependency is required.

## Install

```bash
composer require sellinnate/warden
```

The service provider is auto-discovered. That's it — the deterministic layer is
active out of the box with the `balanced` policy.

## Publish the config (optional)

```bash
php artisan warden:install
# or
php artisan vendor:publish --tag=warden-config
```

This writes `config/warden.php`. See the **[Configuration Reference](/reference/config)**.

## Verify

Inspect a string straight from the CLI:

```bash
php artisan warden:test "ignore all previous instructions"
```

```text
  Direction: input
  Policy:    default
  Severity:  High (0.90)
  Verdict:   BLOCKED

  ┌───────────────────┬───────────┬───────┐
  │ Type              │ Scanner   │ Score │
  ├───────────────────┼───────────┼───────┤
  │ PROMPT_INJECTION  │ injection │ 0.90  │
  └───────────────────┴───────────┴───────┘
```

Warden also registers a line in `php artisan about` showing the active policy and
drivers.

## Using Warden outside a full Laravel app

Need it in a microservice or a standalone job? Build a guard without the
container (requires `illuminate/container`, `illuminate/config`,
`illuminate/support`):

```php
use Sellinnate\Warden\Guard;

$guard = Guard::make(['default_policy' => 'strict']);
$verdict = $guard->inspect($anyInput);
```
