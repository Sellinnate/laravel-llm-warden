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
