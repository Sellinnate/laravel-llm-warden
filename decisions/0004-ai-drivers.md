# ADR-0004 — Phase 3 AI Drivers & Resilience

**Status:** Accepted · **Phase:** 3 · **Date:** 2026-06-27

## Context

Phase 3 adds the optional AI layer: moderation drivers (OpenAI, Azure) and an
LLM-as-judge injection driver, plus the resilience needed to depend on external
endpoints. The deterministic/null drivers remain the default — nothing here runs
unless explicitly configured.

## Decisions

### D1 — Cheap-first escalation (LayeredInjectionDriver)

When an AI judge is selected, it is layered on top of the deterministic driver:
the deterministic filter runs first, and the judge is only called when the
deterministic score is inconclusive (below `injection.escalate_below`). The
verdicts are combined with `max()`, so the judge can only *raise* risk, never
lower the deterministic floor — this also neutralises any attempt to talk the
judge into a false-negative.

### D2 — Degrade, never reduce coverage

A moderation outage must never make the system *less* safe than the offline
baseline. `NsfwScanner` keeps its deterministic deny-list detections and raises a
`moderation_unavailable` signal when the driver throws, instead of letting the
exception discard local findings (Phase 3 review H1). The injection layer behaves
the same way (the judge failure falls back to the deterministic verdict).

### D3 — Honour the provider's calibrated flag

Providers calibrate per-category thresholds we can't reproduce with one number,
so `NsfwScanner` treats `ModerationVerdict::flagged` as a hard block (flooring
risk to the policy threshold) and hard-floors S4 (child sexual exploitation) to
1.0 (review H2).

### D4 — Circuit breaker + per-endpoint isolation

External drivers are wrapped in a cache-backed `CircuitBreaker`: after N
consecutive failures it opens for a cooldown and calls fail fast, so the
per-scanner fail policy takes over cheaply. Breaker keys include a hash of the
endpoint+credentials so one BYOK tenant's outage can't open the circuit for
others (review M1). Timeouts and bounded retries are set on every request.

### D5 — Hardened judge, fenced input

The LLM judge uses a hardened classifier system prompt and presents the untrusted
text strictly as fenced DATA; literal fence markers in the text are broken so it
can't escape the fence (review M2). Result parsing is crash-safe and clamps
scores to [0,1], failing toward over-blocking.

### D6 — Config-driven fail modes

`warden.fail_mode` per-scanner overrides are applied on top of every policy
profile by `PolicyRepository` (review M3), so operators can tune open/closed
behaviour without writing a custom policy.

## Consequences

- A complete hybrid (deterministic + AI) guardrail where the AI is a strict
  second stage; the offline guarantee (no network without an explicit driver) is
  preserved and tested (`Http::preventStrayRequests`).
- Enabling an external driver can only add coverage, never remove it, even when
  the endpoint is down.
