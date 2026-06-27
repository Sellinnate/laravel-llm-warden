<p align="center">
  <img src="art/banner.png" alt="LLM Warden for Laravel — AI guardrails & security" width="100%">
</p>

# Warden for Laravel

[![Tests](https://img.shields.io/github/actions/workflow/status/sellinnate/warden/run-tests.yml?branch=main&label=tests&style=flat-square)](https://github.com/sellinnate/warden/actions)
[![PHPStan](https://img.shields.io/badge/PHPStan-level%208-brightgreen?style=flat-square)](https://phpstan.org/)
[![Latest Version](https://img.shields.io/packagist/v/sellinnate/warden.svg?style=flat-square)](https://packagist.org/packages/sellinnate/warden)
[![License](https://img.shields.io/packagist/l/sellinnate/warden.svg?style=flat-square)](LICENSE.md)

**Enterprise prompt sanitization & LLM guardrails for Laravel — deterministic-first, offline-by-default, EU-resident.**

Warden sits between your application and any LLM as a **bidirectional guardrail
layer**. On the way in it normalises and inspects prompts (prompt injection,
jailbreak, PII, secrets); on the way out it validates and filters the model's
response (unsafe content, data leaks, markdown exfiltration, malformed output).

It is **hybrid and modular**: a deterministic core (regex, deny-lists,
heuristics, Unicode normalization) that runs offline at zero cost, plus optional,
swappable AI drivers (moderation APIs, self-hosted classifiers, LLM-as-judge) for
semantic coverage when you want it. Zero mandatory dependencies beyond
`illuminate/contracts`.

> 📚 Full documentation: **https://laravel-warden.selli.io** (work in progress)

## Why Warden

- **Deterministic-first.** The rule layer is fast (p95 < 5 ms), free, explainable
  and fully testable. AI drivers are a second stage, never a prerequisite.
- **Normalize before every check.** A single pass (NFKC, confusable folding,
  invisible/bidi stripping, de-leet, spacing collapse, recursive base64/hex
  decode) precedes every detector — so deny-lists can't be trivially bypassed.
- **Find vs. act are separate.** Detectors return typed spans; the action
  (allow / redact / mask / encrypt / block / flag) is a *policy* decision.
- **EU/Italy aware.** Codice Fiscale, P.IVA, IBAN with checksum validation;
  GDPR / EU AI Act friendly; nothing leaves your infrastructure by default.

## Installation

```bash
composer require sellinnate/warden
```

Publish the config (optional):

```bash
php artisan vendor:publish --tag=warden-config
```

## Quick start

```php
use Sellinnate\Warden\Facades\Warden;

// Inspect only — returns a Verdict, mutates nothing
$verdict = Warden::inspect($userPrompt);

if ($verdict->blocked()) {
    abort(422, 'Prompt not allowed.');
}

// Sanitize — returns the Verdict with cleaned text ready for the LLM
$clean = Warden::sanitize($userPrompt)->sanitizedText;

// Inspect the LLM output, restoring pseudonymized values from the Vault
$safe = Warden::inspectOutput($llmResponse, vault: $verdict->vault)->sanitizedText;
```

## Status

Warden is under active development following its technical specification. See the
roadmap in the docs. The current foundation provides the full normalization
pass, the Guard/Policy/Scanner architecture, and the public API surface.

## Testing

```bash
composer test        # Pest
composer analyse     # PHPStan level 8
composer format      # Pint
```

## Security

If you discover a security vulnerability, please review [SECURITY.md](SECURITY.md)
for the responsible-disclosure process. Do **not** open a public issue.

## Credits

- [Filippo Calabrese](https://github.com/sellinnate) and Sellinnate S.r.l.

## License

The MIT License (MIT). See [LICENSE.md](LICENSE.md).
