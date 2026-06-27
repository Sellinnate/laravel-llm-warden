# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Operating guide for working on **Warden for Laravel** (`sellinnate/warden`).
Follow this methodology for every task in this repo. It encodes how the project is
built, reviewed, documented and released — keep new work consistent with it.

## What this project is

A Laravel package that sits between an application and any LLM as a **bidirectional
sanitization & guardrail layer**: on input it normalises and inspects prompts
(prompt injection/jailbreak, PII, secrets, NSFW); on output it validates and
filters the model's reply (system-prompt leak, PII/secret leak, markdown
exfiltration, format). Deterministic-first and offline-by-default; optional AI
drivers are opt-in.

- **Package:** `sellinnate/warden` · **Namespace:** `Sellinnate\Warden` · **Facade:** `Warden`
- **Repo:** https://github.com/Sellinnate/laravel-llm-warden (remote `origin`)
- **Docs site:** https://laravel-warden.selli.io (docmd, hosted on Cloudflare, rebuilt from `main`)
- **Requirements:** PHP `^8.3`, Laravel 12/13 (`illuminate/contracts ^11||^12||^13`), `ext-intl`, `ext-mbstring`. Runtime deps are **only** `illuminate/contracts` + the two extensions — never depend on `laravel/framework`.

## Golden rules

1. **Everything we claim must exist.** Never document, advertise, or ship a config
   key / env var / driver / feature that isn't implemented and wired. Public docs,
   `README.md` and the published `config/warden.php` must contain **zero**
   non-existent features and **zero internal code** a consumer wouldn't use. If
   something is roadmap, label it a limitation; if a config value is unsupported,
   **fail closed** (throw a clear exception — see the PII `hash` operator) rather
   than silently no-op. Remove dead config keys, don't leave them unwired.
2. **All quality gates green before any merge to `main`** (tests, PHPStan level 8, Pint).
3. **Docs and code change together.** Any behaviour/feature/config change updates,
   in the same change: the docmd site (`docs/`), `config/warden.php` (+ its
   comments), `README.md` and `CHANGELOG.md` as needed.
4. **Junior-proof docs.** Define every term before use (there's a glossary in
   `docs/getting-started/what-is-warden.md`), give complete runnable examples with
   the `use` imports a copy-paste needs, and never expose internal class names
   (`ScanContext`, `EventFactory`, `AuditRecord`, `VerdictCache`, registries,
   analyzers…) on consumer pages.
5. **The guardrail must never become a leak source.** PII/secrets are always
   redacted in logs, events, audit records and cached verdicts (masked
   fingerprints only). Nothing leaves the user's infrastructure unless an external
   driver is explicitly enabled (BYOK).

## The defining practice: adversarial review before every merge

This is the most important workflow in the repo. Each development cycle (a feature
branch) is merged to `main` **only after an aggressive adversarial self-review**:

1. Build the feature on a branch (`feat/...`, `fix/...`, `docs/...`).
2. Get the quality gates green.
3. Launch a dedicated **adversarial reviewer subagent** (via the Agent tool) that
   tries to break the work — hunting bypasses, ReDoS, redaction/leak bugs,
   off-by-ones, fail-policy mistakes, and (for docs) non-existent features /
   internal leaks / junior-proofing gaps. It must demonstrate findings with
   concrete inputs, not assertions.
4. Fix every Critical/High (and cheap Medium) finding, add a **regression test**
   for each, and record the round in
   [`decisions/adversarial-reviews.md`](decisions/adversarial-reviews.md).
5. Re-review (another round) until clean, then merge `--no-ff` to `main`.

This process has repeatedly caught serious bugs (dead base64 decode channel,
auto-loading-image exfil bypasses, moderation outage reducing coverage, cache
leaking raw text). Do not skip it. Treat the reviewer's output as authoritative
and verify findings against the code before fixing.

## Architecture & conventions

Warden is five concepts; keep them clear and the rest follows.

- **`Guard`** (`src/Guard.php`) — orchestrator and public entry point
  (`inspect`/`sanitize`/`inspectOutput`/`inspectRetrieval`/`for`/`run`). Resolves
  the active policy, runs the ordered scanner pipeline for a `Direction`, and
  aggregates per-scanner results into one `Verdict`. Also `Guard::make()` builds a
  container-free guard for standalone use.
- **`Scanner`** — one pipeline stage (`src/Scanners/*`). Input/output/retrieval.
- **`Detector`** — detection logic inside a scanner (regex/checksum), separate from
  the action. (Presidio "find vs. act" split — the action is **policy**, never
  hard-coded in a detector.)
- **`Driver`** — swappable backend (deterministic vs AI), fronted by a Laravel
  `Manager` (`InjectionManager`, `ModerationManager`). Add a provider by
  implementing the contract + `create<Studly>Driver()` or `extend()`. **Never**
  edit the pipeline to add one.
- **`Verdict` / `ScanResult` / `Detection`** — immutable, serializable value objects
  (`src/ValueObjects/*`).

Key invariants to preserve:

- **Two-view normalization.** The `NormalizeScanner` runs first on every direction
  and keeps a **delivered** view (`current`, only unwanted chars removed — what
  ships, what PII/secret scanners redact against byte-accurately) and a **detection**
  view (`normalized`, aggressively de-obfuscated — what injection/NSFW match on).
  NFKC and other lossy transforms touch only the detection view. Decoding runs on
  the intact pre-de-leet text. See `decisions/0001-foundation.md`.
- **Find ≠ act.** Scanners read their threshold/action from the active `Policy`
  (`ScanContext->policy`); the `Guard` only aggregates and short-circuits.
- **Explicit, per-scanner fail policy.** On driver error/timeout the per-scanner
  `FailMode` (open/closed) decides. External drivers are wrapped in a
  `CircuitBreaker`; a moderation outage **degrades to the deny-list**, never below it.
- **Contract-first / public surface = the `Warden` facade + `Contracts\*` +
  the value objects + the enums + top-level `config/warden.php` keys + the
  validation rules + middleware alias + event names.** Everything else is internal
  and may change. Add facade `@method` docblocks when you add an accessor.

## Development workflow

1. Branch from `main`.
2. Implement following the patterns above; match surrounding code style, comment
   density and naming. Read like the code already there.
3. Add/extend tests (mandatory).
4. Update docs / config / README / CHANGELOG.
5. All gates green → adversarial review → fix + regression tests → merge `--no-ff`.
6. Push to `origin` **only when the user asks**; if on `main`, that's the release
   branch — branch first for non-trivial work.

## Testing methodology

- **Framework:** Pest 4 on Orchestra Testbench. Tests in `tests/Unit`,
  `tests/Feature`; versioned attack/benign data in `tests/Corpus/`.
- **Offline & deterministic by default.** The deterministic layer must make **no
  network calls** — there's an explicit `Http::preventStrayRequests()` +
  `Http::assertNothingSent()` test guarding this. Driver tests use `Http::fake()`
  (+ `preventStrayRequests()`); never hit a real service.
- **Cover real behaviour, not happy paths:** assert request shape, response
  mapping, error/retry/fail-policy paths, and invariants (byte-accurate redaction,
  no raw secret in detections/audit/cache, vault per-request isolation,
  obfuscation bypasses caught).
- **Detection quality is gated.** The injection corpus has CI-style thresholds on
  recall and false-positive rate (`tests/Feature/InjectionCorpusTest.php`). A
  change that lowers recall or raises false positives there fails — grow the
  corpus when you find a new attack.
- **Every adversarial-review finding gets a regression test** (see the
  `*ReviewRegressionTest.php` files).

Run a single test / filter:

```bash
vendor/bin/pest tests/Unit/NormalizerTest.php          # one file
vendor/bin/pest --filter="canary"                      # by name
vendor/bin/pest --compact                              # terse output
```

## Quality gates (run before every merge)

```bash
composer test        # Pest suite
composer analyse     # PHPStan level 8 (Larastan) — zero errors
composer format      # Laravel Pint — zero style changes
```

PHPStan (level 8): **fix the underlying type**, never silence. No `@phpstan-ignore`,
no new baseline entries, no `assert()`/inline `@var` overrides, no casts-to-silence,
no widening params/returns just to pass. Analysis covers `src/` only (config files
use `env()` and aren't analysed).

## Documentation (what goes where)

Two distinct doc surfaces — keep them separate:

### Public docs site — `docs/` (docmd, consumer-facing)

- Built with **docmd** (`@mgks/docmd`). Lives at the **repo root**: root
  `package.json` (`docs:dev`/`docs:build` = `docmd dev`/`docmd build`) + root
  `docmd.config.json` (`src: docs`, `out: site`). Cloudflare rebuilds from `main`
  with build command `npm run docs:build`, output `site` (gitignored).
- Structure mirrors the sibling RAG site: Introduction → Getting Started
  (**"What is Warden? (start here)"** beginner intro + glossary → Installation →
  Quick Start → Configuration) → Core Concepts → Scanners → Usage → AI Drivers →
  Observability → **Guides** (Extending, Troubleshooting & FAQ) → Reference.
- **Conventions:**
  - Callouts use three colons: `::: callout tip "Title"` … `:::`; cards
    `::: card "Title"` … `:::`. Keep fences balanced.
  - **Images use Markdown syntax** `![alt](/assets/images/x.png)`, NOT raw `<img>`
    HTML — docmd renders Markdown images but escapes raw HTML to text. Assets live
    in `docs/assets/`, served at `/assets/...`.
  - Add every new page to the nav in `docmd.config.json`.
  - Must satisfy the Golden Rules: junior-proof, no internal code, no non-existent
    features. Every code example carries its `use` imports.
- **After doc changes:** `npm run docs:build` then
  `npx @mgks/docmd validate` (checks all internal links/anchors). Both must pass.

### Internal decision records — `decisions/` (NOT published, `export-ignore`d)

- `0001`…`0005` — Architecture Decision Records: the *why* behind structural
  choices (two-view normalization, deanonymize ordering + trusted spans,
  degrade-don't-reduce-coverage, cache redaction, etc.). Add/extend one per cycle.
- `adversarial-reviews.md` — the running log of every pre-merge review (findings,
  severity, resolution). Append a section each cycle.

`TASKS.md` (gitignored) is the working task tracker. `README.md`, `CHANGELOG.md`,
`SECURITY.md`, `CONTRIBUTING.md` are maintained alongside features.

## Config & environment conventions

- `config/warden.php` is committed and `config:cache`-safe: scalars/arrays/`env()`
  only, no closures, no secrets. Every value has a production-safe default; all
  network behaviour is opt-in (default drivers are `deterministic` / `null`).
- Provider keys via `env()` in config; real values only in `.env`.
- Drivers that exist: injection `deterministic` (default) | `llm-judge`;
  moderation `null` (default) | `openai` | `azure`. Do **not** reintroduce config
  blocks for unimplemented drivers.

## Security & data posture (preserve these)

- **Deterministic-first, offline-by-default, EU-resident, BYOK.** No egress without
  an explicit driver.
- **Redaction everywhere:** detections carry masked fingerprints only; audit
  records store a non-reversible hash, never raw text (`store_raw=false` default);
  cached verdicts are redacted (`Verdict::forCache()`); verdicts with a Vault are
  never cached (Vault is per-request, never shared between requests/tenants).
- **Anti-DoS:** input is truncated above `max_input_bytes` on a UTF-8 boundary;
  recursive decode is depth/size-bounded; all regexes are backtracking-free (no
  ReDoS — verify any new pattern).
- The package distribution is kept lean via `.gitattributes` `export-ignore`
  (docs/, decisions/, tests/, the JS docs tooling are excluded from the Composer dist).

## Commit messages

- Conventional-style subject (`feat:`, `fix:`, `docs:`, `chore:`, `ci:`, `test:`).
- Explain *what* and *why*; note the gates that passed.
- End every commit (and PR body) with:
  `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`

## Key commands

```bash
composer test                 # Pest suite
composer analyse              # PHPStan level 8
composer format               # Pint
vendor/bin/pest --filter=X    # run a single test by name
npm run docs:build            # build the docs site into ./site
npm run docs:dev              # preview docs locally
npx @mgks/docmd validate      # check docs internal links/anchors
```
