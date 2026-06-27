# ADR-0005 — Phase 4 Hardening & Launch

**Status:** Accepted · **Phase:** 4 · **Date:** 2026-06-27

## Context

Phase 4 makes Warden enterprise-adoptable: audit trail, caching, retrieval guard,
CLI, a framework-agnostic factory, CI, and the public documentation site.

## Decisions

### D1 — Redacted-by-default audit trail

`AuditRecord::fromVerdict()` records only detection type/scanner/score, a coarse
direction/severity, and a **non-reversible hash** of the input — never the raw
text or per-detection evidence. `store_raw` defaults to `false`. The guardrail
cannot become a leak source. The store is pluggable via the `Auditor` contract
(`LogAuditor` by default).

### D2 — Caching is opt-in and cache-safe

`Cache::remember`-style memoization on `hash(policy, direction, text)` collapses
repeated inputs (and zeroes paid driver calls). Two safety rules:

- a verdict carrying a **Vault** is never cached (per-request);
- the cached copy is **redacted** (`Verdict::forCache()`): no `originalText`, no
  detection evidence, and no `sanitizedText` for blocked verdicts.

A cache hit still audits and emits events, so repeated payloads never go invisible
to observability (Phase 4 review finding #1).

### D3 — Retrieval guard as a first-class surface

`Direction::Retrieval` + `inspectChunks()` treat RAG/tool content as untrusted
input for indirect injection. `inspectChunks()` skips non-string elements so one
bad chunk can't abort a batch.

### D4 — Framework-agnostic via `Guard::make()`

`Guard::make()` builds a self-contained guard on a fresh container by reusing the
provider's static `registerBindings()` — no wiring duplication. It guards its
dependencies (container/config/`env()`) and throws a clear `WardenException` if
they're missing.

### D5 — CLI and discoverability

`warden:install` (publish config), `warden:test` (inspect a string, with
terminal-escape-safe output), and an `php artisan about` section. Operators can
debug and verify the install without writing code.

### D6 — Quality gates as part of the product

CI runs `{ubuntu, windows} × {PHP 8.3, 8.4} × {Laravel 12, 13} × {prefer-lowest,
prefer-stable}` plus PHPStan level 8 and Pint. SECURITY.md defines responsible
disclosure. The public docs site (docmd) is complete and exhaustive.

## Consequences

- A v1.0-ready package: deterministic + AI hybrid, fully tested (219 tests),
  PHPStan level 8, documented, auditable, with safe-by-default observability.
- Every phase shipped only after an aggressive adversarial review, all recorded
  in [`adversarial-reviews.md`](adversarial-reviews.md).
