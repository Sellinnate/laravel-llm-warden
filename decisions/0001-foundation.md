# ADR-0001 — Phase 0 Foundation

**Status:** Accepted · **Phase:** 0 · **Date:** 2026-06-27

## Context

Phase 0 establishes the skeleton every later phase builds on: the five core
concepts (Guard, Scanner, Detector, Driver, Verdict/ScanResult), the
normalization pass, and the orchestration/policy machinery.

## Decisions

### D1 — Two-view normalization (delivered vs detection)

The spec (§7.1) says PII/secret redaction uses the *original* text by offset
while detection runs on the *normalized* text. Naively this is contradictory:
aggressive normalization (NFKC, de-leet, spacing collapse) changes byte offsets,
so a detection offset cannot map back to the delivered text.

We resolve it by maintaining **two views** on `ScanContext`:

- `current` — the **delivered** text. Only genuinely unwanted characters are
  removed (invisibles, bidi controls). Sanitizing scanners (PII/secret) detect
  and redact against *this* view, so offsets always align with what ships.
- `normalized` — the **detection** view. The delivered text plus lossy
  transforms (NFKC, confusable folding, mark stripping, de-leet, spacing
  collapse) used by detect-only scanners (injection, NSFW keyword).

NFKC is therefore **never** applied to delivered text (it is lossy for legit
content like `²`, ligatures, full-width). This keeps redaction byte-accurate
*and* detection obfuscation-resistant.

### D2 — Decoding is out-of-band, before de-leet

base64/hex decode must see the *intact* encoded run. Running de-leet first
corrupts the base64 alphabet (digits → letters) and silently disables the whole
decode channel (caught in the Phase 0 adversarial review, finding C1). So the
`NormalizeScanner` extracts and decodes from the delivered (pre-de-leet) text,
then pushes each decoded payload back through the **full** detection chain — so
obfuscation hidden *inside* an encoding is also caught.

### D3 — `Illuminate\Pipeline` not used directly (yet)

The spec proposes `Illuminate\Pipeline\Pipeline` as the backbone. We implement
the ordered run loop directly in `Guard::run()` because we need fine-grained
short-circuit + per-scanner fail-policy + event dispatch between stages, which is
clearer as an explicit loop than as pipe closures. The properties the spec wanted
from the pipeline (explicit ordering, DI per stage, isolated testability,
short-circuit) are all preserved; the registry resolves each scanner from the
container. Revisit if a public extension point needs the literal Pipeline.

### D4 — Scanner registry via name → resolver, tolerant resolution

Scanners are referenced by stable names in policies (`normalize`, `injection`,
…). `ScannerRegistry` maps names to class-strings/closures resolved from the
container. `resolveMany()` silently skips names that aren't registered, so a
build that ships a subset of scanners still works and phased development can add
scanners incrementally without breaking policies. **Caveat:** in production a
missing *security* scanner silently not running is a risk — Phase 4 adds an
install-time check / `warden:doctor` to surface gaps.

### D5 — Policy is data, action is policy (Presidio principle)

`Policy` is an immutable bundle of scanner order + thresholds + actions + fail
modes. Scanners read their threshold/action from `ScanContext->policy`; the Guard
only aggregates and short-circuits. This keeps "what to do about a finding" out
of detector code.

### D6 — Depend on `illuminate/contracts` only

No `laravel/framework`, no `spatie/laravel-package-tools`. The service provider
extends `Illuminate\Support\ServiceProvider` (present in any host app). Required
runtime deps: `illuminate/contracts`, `ext-intl`, `ext-mbstring`.

## Consequences

- Byte-accurate redaction and obfuscation-resistant detection coexist.
- Adding a scanner/normalizer/driver is a class + a registration, no core edits.
- The delivered text is minimally mutated (only invisibles/bidi removed),
  preserving user intent while still neutralising the invisible-injection channel.
