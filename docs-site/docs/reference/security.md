---
title: "Security & Limitations"
description: "What Warden does, what it doesn't, and how to report issues."
---

# Security & Limitations

Warden is a **risk-mitigation** layer, not a guarantee. Being honest about its
limits is part of using it well.

## What the deterministic layer wins on

- Encoding (base64/hex) and the whole class of **obfuscation/evasion** attacks —
  zero-width, bidi, confusables, combining marks, leet, spacing.
- High-signal override / refusal-suppression / persona keywords.
- Checksum-validated PII (Codice Fiscale, P.IVA, IBAN, cards) at near-zero false
  positives.
- High-signal secret formats and markdown/HTML exfiltration defang.

## What it does **not** catch

- **Novel, paraphrased** semantic jailbreaks with no keyword signal — use the
  **[LLM judge](/drivers/judge)**.
- **Multi-turn** attacks (Crescendo, Echo Chamber) that unfold across messages —
  out of the "sanitize this input" contract of v1 (a stateful hook is on the
  roadmap).
- **Image/audio** moderation — text only in v1.
- It is **not** a network WAF or anti-bot — it protects the application↔LLM
  boundary, not the internet↔application one.

## Defence-in-depth

Warden is one layer. Combine it with: authorization on tool calls (LLM06),
render-time output escaping/sanitization (it is not a full HTML sanitizer),
rate limiting, and your provider's own safety features.

## Rolling out safely

Start in **detect-only** mode (action `Detect`) to measure block/false-positive
rates against real traffic, watch the **[events](/observability/events)**, then
tighten to `Sanitize` / `Block`. Keep a **[false-positive corpus](/scanners/injection)**
of legitimate inputs that must never block.

## Reporting a vulnerability

Please **do not** open a public issue. Use GitHub private vulnerability reporting
or email **security@selli.io**. A bypass of a control Warden advertises (a
normalization evasion, a redaction leak, a defang bypass, a checksum false-accept,
a ReDoS) is in scope and very welcome. See `SECURITY.md` in the repository.

## Quality posture

Every release passes a matrix of `{ubuntu, windows} × {PHP 8.3, 8.4} × {Laravel
12, 13} × {prefer-lowest, prefer-stable}`, PHPStan level 8, Pint, and a corpus
with CI gates on recall and false-positive rate. Each development phase ships only
after an aggressive adversarial self-review (recorded in `docs/decisions/`).
