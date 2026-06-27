# Adversarial Review Log

A running record of the aggressive pre-merge reviews. For a security package the
review *is* part of the product: every phase is attacked before it merges.

---

## Phase 0 — Foundation (2026-06-27)

Reviewer brief: hunt for normalization bypasses, ReDoS/decode-bombs, offset/mb
bugs, Vault collisions, and pipeline crashes on adversarial input. Findings and
resolutions:

| ID | Severity | Finding | Resolution |
|----|----------|---------|------------|
| C1 | Critical | De-leet ran before the base64/hex decoder, corrupting the payload → the entire decode channel was a no-op for any real base64 (which contains digits). | **Fixed.** Decoding is now out-of-band on the intact delivered text, before de-leet; decoded payloads are re-normalized through the full detection chain. (`NormalizeScanner`, `RecursiveDecoder::collect`) Regression: `NormalizationBypassTest` C1. |
| H1 | High | Combining marks (`\p{Mn}`) were not stripped → `i◌́gnore` / base+U+0303 evaded the detection view. | **Fixed.** New `MarkStripper` (NFD → strip `\p{Mn}`/`\p{Cf}`) in the detection chain. Regression: bypass test H1. |
| H2 | High | Decoded payloads were appended raw, never re-normalized → obfuscation *inside* an encoding survived. | **Fixed** with C1 (each decoded payload re-runs the detection chain). Regression: bypass test H2. |
| H3 | High | `InvisibleStripper` missed U+034F (CGJ), U+2061–2064, variation selectors (FE00–FE0F / E0100–E01EF), Hangul/Khmer fillers. | **Fixed.** Added all of the above to the strip set. Regression: bypass test H3. |
| M1 | Medium | `Vault::restore()` used sequential `str_replace`; a restored value containing another placeholder string got re-expanded → cross-field secret leak. | **Fixed.** Single-pass `preg_replace_callback` over the placeholder pattern; restored values are never re-scanned. Regression: `VaultRestoreTest`. |
| M2 | Medium | No max input-size guard; `RecursiveDecoder` decoded a full candidate before the budget truncation. | **Fixed.** `Guard` truncates input above `warden.max_input_bytes` (UTF-8-safe) and signals `input_truncated`; decoder skips candidates above `MAX_CANDIDATE`. |
| M3 | Medium | Confusable map is a narrow curated subset; mixed-script heuristic only Latin+Cyrillic/Greek. | **Accepted for Phase 0.** Covers the high-frequency attack alphabet. Tracked for a generated TR39 skeleton table post-v1. |
| L1 | Low | Placeholders `<TYPE_N>` are user-forgeable (a user typing `<EMAIL_1>` could collide). | **Accepted/partially mitigated.** Single-pass restore only substitutes placeholders actually present in the Vault; unknown placeholder-shaped text is left untouched. Per-request nonce considered for the PII phase. |
| L3 | Low | Guard aggregation is AND-of-valid / max-of-risk; `Policy` thresholds/actions are enforced *by scanners*, not the orchestrator. | **By design.** Phase 1 scanners read `ScanContext->policy`. Noted so reviewers verify each scanner honours it. |

Robustness positives confirmed by the reviewer: no ReDoS in any regex
(backtracking-free), invalid UTF-8 does not crash the pipeline (NFKC/`/u` regex
fallbacks, `mb_check_encoding` guard), fail-open/closed wiring correct.

**Verdict:** foundation sound after C1/H1/H2/H3/M1/M2 fixes. Cleared to build
Phase 1.

---

## Phase 1 — Deterministic MVP (2026-06-27)

Reviewer brief: detection bypasses, redaction correctness, checksum correctness,
ReDoS, false positives that block legit traffic, middleware coverage, entropy
gate. Findings and resolutions:

| ID | Severity | Finding | Resolution |
|----|----------|---------|------------|
| H1 | High | Quadratic ReDoS in the EMAIL detector (`a.a.a…@` → 0.77s at the 50 KB default cap; CPU DoS). | **Fixed.** RFC-bounded lengths (`{1,64}@{1,63}(\.{1,63})*\.{2,24}`) make matching linear (4ms on the same input). Regression in `Phase1ReviewRegressionTest`. |
| H2 | High | Middleware only scanned top-level string fields → the OpenAI `messages[]` nested shape was completely unprotected. | **Fixed.** `WardenMiddleware` now recurses into arrays (dot-path keys) on input and JSON output. Regression: nested middleware test. |
| H3 | High | A base64-encoded secret was detected on output but its zero-length detection produced no redaction under `Sanitize` → the encoded secret shipped. | **Fixed.** Any unredactable (zero-length) secret detection forces a block even under a Sanitize policy. Regression in review test. |
| M1 | Medium | Entropy gate (3.5) lets low-entropy hex/numeric secrets through the generic catch-all. | **Accepted/noted.** The prefixed high-signal patterns cover the real vendor tokens; the generic catch-all is a best-effort net. Threshold is configurable. Tracked for length-aware tuning. |
| M2 | Medium | INSTRUCTION_OVERRIDE was word-order brittle ("ignore the instructions you were given earlier" passed). | **Fixed.** Added noun-first ordering branch + "from now on you have no restrictions" (EN+IT). Regression in review test; corpus recall still 100%. |
| M3 | Medium | IP/version strings ("1.2.3.4") and bare numbers flagged as PII → `NoPii` rule 422s on benign input. | **Fixed.** Added `requireContext` to `RegexDetector`; IP and bare local phone now require a nearby context word. `+39` phones and contextual IPs still caught. Regression in review test. |
| M4 | Medium | Output middleware treated the serialized response body as opaque text. | **Fixed.** JSON-aware output: decode → scan each string value → re-encode; sets `Content-Type` on block. |
| M5 | Medium | `hash` operator: 64-bit truncation + empty default salt → reversible PII. | **Fixed.** Switched to HMAC-SHA256 (128-bit) and throws if the salt is empty. Regression in review test. |
| L1 | Low | IBAN mask config revealed too much of the account number. | **Fixed.** Bumped `chars` 8 → 18 to mask the account tail. |
| L2 | Low | `Redactor` could split a UTF-8 codepoint for a future mis-aligned span. | **Fixed.** Added a codepoint-boundary guard that skips mid-sequence spans. |
| L3 | Low | Partial (non-containment) overlapping detections: `Redactor` skips one, leaving it un-redacted. | **Accepted for Phase 1.** Not reachable with the default detector set (they don't produce partial non-containment overlaps). Tracked: merge partial overlaps before redaction. |
| L4 | Low | Future Vault de-anonymization oracle via user-injected `<TYPE_N>`. | **Tracked for Phase 2** (DeanonymizeScanner): restore only placeholders this request minted. |

Verified correct by the reviewer: all four checksums (CF incl. omocodia, P.IVA,
IBAN mod-97, Luhn), no backtracking in injection/secret/nsfw patterns, byte-
accurate redaction, normalization interplay, encoded-secret-on-input blocking.

**Verdict:** deterministic core sound after the three High fixes + Mediums.
Cleared to build Phase 2.

---

## Phase 2 — Output & Vault (2026-06-27)

Reviewer brief: markdown-defang bypasses, deanonymize ordering/leak, canary
evasion, FormatScanner state machine, output pipeline correctness.

| ID | Severity | Finding | Resolution |
|----|----------|---------|------------|
| H1 | High | Protocol-relative image URL (`![x](//evil/x.png)`) classified as a harmless relative URL → shipped active. | **Fixed.** `isAllowed()` now rejects `//`-prefixed URLs before the relative short-circuit. Regression in `Phase2ReviewRegressionTest`. |
| H2 | High | Reference-style images/links (`![x][1]` + `[1]: http://evil`) entirely unhandled → auto-loading image shipped. | **Fixed.** Added a reference-definition pass that neutralizes off-domain definition URLs. |
| H3 | High | Raw HTML `<img>`/`<a>` and angle-bracket autolinks unhandled (LLM output is rendered as markdown+HTML). | **Fixed.** Added HTML img/anchor and autolink passes. Class docblock now scopes it as a defensive transform, not a full HTML sanitizer. |
| M4 | Medium | Escaped `\]` in alt/text defeated the capture. | **Fixed.** Alt/text now matches `(?:[^\]\\]|\\.)*` (escape-aware). |
| M5 | Medium | `deanonymize` ran LAST → a restored value containing markdown re-introduced an active URL after defang. | **Fixed.** Reordered `deanonymize` to run early (after normalize); restored regions are marked **trusted spans** so output PII/secret scanners skip them, while defang/format still process the restored text. |
| M6 | Medium | `deanonymize` after `format` could inject quotes into certified-valid JSON. | **Fixed** by the same reorder (format now runs after deanonymize). |
| M7 | Medium | Canary/system-prompt-echo checked `current`; a whitespace-split canary leaked undetected. | **Fixed.** Both checks now compare whitespace-stripped copies. Regression test added. |
| L8 | Low | `requireJson` accepted bare scalars (`5`, `true`) as valid. | **Fixed.** Requires an object/array root. |
| L9 | Low | Bidi-control stripping on output can mis-render legitimate RTL text. | **Accepted/documented.** Security (Trojan-source defence) is prioritised; configurable via `normalize.strip_bidi`. |

Verified sound by the reviewer: allow-list subdomain matching (no
`evil-trusted.test` / `trusted.test.evil.com` / `user@host` bypass), `data:`/
`mailto:` defanged, FormatScanner JSON state machine (strings/escapes, no ReDoS),
Vault single-pass restore isolation, byte-accurate secret/PII output redaction.

**Verdict:** output layer sound after the three High fixes + reorder/trusted-span
design. Cleared to build Phase 3.
