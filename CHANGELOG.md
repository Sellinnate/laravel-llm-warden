# Changelog

All notable changes to `sellinnate/warden` will be documented in this file.

## v1.0.0 — Warden for Laravel - 2026-06-27

First stable release. **Enterprise prompt sanitization & LLM guardrails for Laravel** — deterministic-first, offline-by-default, EU-resident.

📚 Docs: https://laravel-warden.selli.io · 📦 `composer require sellinnate/warden`

### Highlights

- **Bidirectional guardrail**: input (prompt injection/jailbreak, secrets, PII, NSFW) and output (system-prompt leak, PII/secret leak, markdown exfiltration, JSON format).
- **Deterministic-first, offline-by-default**: a normalization pass (NFKC, confusables, invisibles/bidi, de-leet, spacing, recursive base64/hex decode) + rule/heuristic scanners, with **zero mandatory dependencies beyond `illuminate/contracts`** and no network calls.
- **EU/Italy-first PII** with checksum validation (Codice Fiscale incl. omocodia, Partita IVA, IBAN, Luhn) and a reversible **Vault** round-trip.
- **Optional AI drivers** (OpenAI/Azure moderation, layered LLM-as-judge) — BYOK, circuit-broken, fail-policy aware; coverage never drops below the offline baseline.
- Full public API: facade, fluent pipeline, validation rules, HTTP middleware, events, audit trail, caching, Artisan commands, framework-agnostic `Guard::make()`.

Anchored to the OWASP Top 10 for LLM Applications (2025): LLM01, LLM02, LLM05, LLM07.

219 tests · PHPStan level 8 · PHP 8.3/8.4 · Laravel 12/13.

## v1.0.0 — 2026-06-27

Initial release. Enterprise prompt sanitization & LLM guardrails for Laravel —
deterministic-first, offline-by-default, EU-resident.

### Added

- **Normalization** pass (always first): NFKC, confusable folding, combining-mark
  removal, invisible/bidi stripping, de-leet, spacing collapse, recursive
  base64/hex decode — with a delivered/detection two-view split.
- **Injection scanner** (OWASP LLM01): deterministic high-signal signatures,
  Unicode-obfuscation signals and structural heuristics, with a versioned
  attack/benign corpus and precision/recall CI gates.
- **Secret scanner** (LLM02): high-signal prefixed patterns + Shannon-entropy
  catch-all; block on input, redact on output; encoded-secret handling.
- **PII scanner** (LLM02): Presidio-style Analyzer/Anonymizer; IT/EU checksum
  detectors (Codice Fiscale w/ omocodia, Partita IVA, IBAN, Luhn); operators
  replace/redact/mask/hash(HMAC)/encrypt(Vault)/keep/custom.
- **NSFW scanner**: intent-based S1–S13 deny-list + optional moderation drivers.
- **Output pipeline**: de-anonymize (Vault), output-leak (canary), markdown
  defang (markdown/HTML/autolink exfil), format (JSON) validation.
- **AI drivers** (opt-in, BYOK): OpenAI & Azure moderation, LLM-as-judge
  (layered, cheap-first), with circuit breaker, timeouts and per-scanner fail
  modes.
- **Public API**: `Warden` facade, fluent pipeline API, validation rules
  (`NoPromptInjection`, `NoPii`, `Clean`), HTTP middleware, domain events,
  `Guard::make()` framework-agnostic factory.
- **Policies**: `strict` / `balanced` / `permissive` profiles + custom builder.
- **Observability**: redacted audit trail, verdict caching, i18n (it/en),
  `warden:install` / `warden:test` commands and an `about` section.
- Full documentation site (docmd) and `decisions/` ADRs + adversarial
  review log.

### Security

- The guardrail never logs raw secrets/PII (masked evidence only); cached
  verdicts are redacted; nothing leaves your infrastructure without an explicit
  driver. Each phase shipped after an aggressive adversarial review.
