# Warden — Internal Documentation (`decisions/`)

This folder holds **implementation decisions** taken during development of
`sellinnate/warden`, separate from the public documentation site (which lives in
the root `docs/` folder and is built with docmd → `laravel-warden.selli.io`).

- `0001`–`0005` — Architecture Decision Records (ADRs).
- [`adversarial-reviews.md`](adversarial-reviews.md) — a running log of the
  aggressive adversarial reviews performed before each phase merge.

The authoritative product specification is
`specifiche-tecniche-llm-guardrails.md` (outside this repo). The public ADR
summary from the spec (§17) is the *intent*; the files here record how that
intent was actually realised, plus decisions the spec left open.

## Development workflow

Each phase from the roadmap (spec §16) is developed on a feature branch and
merged to `main` only after:

1. `vendor/bin/pest` — unit + feature + corpus tests green;
2. `vendor/bin/phpstan analyse` — level 8 clean;
3. `vendor/bin/pint` — formatted;
4. an **aggressive adversarial self-review** (a dedicated reviewer hunts for
   bypasses, ReDoS, correctness bugs); findings are fixed or explicitly accepted
   and logged in [`adversarial-reviews.md`](adversarial-reviews.md).
