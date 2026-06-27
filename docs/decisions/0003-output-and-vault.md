# ADR-0003 — Phase 2 Output & Vault

**Status:** Accepted · **Phase:** 2 · **Date:** 2026-06-27

## Context

Phase 2 completes the bidirectional guarantee: a dedicated output pipeline plus
the reversible-pseudonymization (Vault) round-trip.

## Decisions

### D1 — Output pipeline order: deanonymize early, defang/format late

The output pipeline runs:

```
normalize → deanonymize → output-leak → secret → pii → markdown-defang → nsfw → format
```

`deanonymize` runs **early** (right after normalize) so every later scanner —
especially `markdown-defang` and `format` — processes the *restored* text. This
closes two exfil/correctness gaps the Phase 2 review found (M5: a restored value
containing markdown re-introducing an active URL after defang; M6: restored
values breaking certified-valid JSON).

### D2 — Trusted spans prevent re-redacting the user's own data

Restoring PII early would normally make the output PII/secret scanners redact the
user's own data again. To avoid that, `DeanonymizeScanner` records the byte spans
of the values it restored as **trusted spans** on the `ScanContext`. The output
PII and secret scanners drop any detection that lies entirely within a trusted
span. New PII/secrets the model *invents* (outside those spans) are still caught
and redacted.

### D3 — Markdown defang covers the channels attackers actually reach

`MarkdownDefangScanner` neutralizes inline markdown images/links, reference-style
definitions, raw HTML `<img>`/`<a>`, and angle-bracket autolinks. URLs are
classified by host against an allow-list; protocol-relative (`//host`) and
non-http(s) schemes (`data:`, `javascript:`, `mailto:`) are always defanged. It
is explicitly scoped as a defensive transform over common renderer behaviour, not
a full HTML sanitizer — consumers must still escape/sanitize at render time.

### D4 — System-prompt leak detection is whitespace-robust

`OutputLeakScanner` detects a seeded canary token and verbatim echoes of the
configured system prompt. Both comparisons are done on whitespace-stripped copies
so an attacker can't evade by interleaving spaces/newlines (review M7).

### D5 — FormatScanner is opt-in and repair-first

A no-op unless `output.require_json` is set. When required it validates a
structured (object/array) JSON root and, if the JSON is wrapped in prose/code
fences, conservatively extracts the first balanced JSON value before blocking.

## Consequences

- The headline round-trip (`sanitize` → LLM → `inspectOutput(vault:)`) returns
  the user's real data while still blocking new leaks and defanging exfil.
- The output layer resists the three independent auto-loading-image bypasses the
  Phase 2 adversarial review demonstrated.
