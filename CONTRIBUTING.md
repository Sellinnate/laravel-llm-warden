# Contributing to Warden

Thanks for considering a contribution! Warden is a security package, so quality
and test coverage are part of the product.

## Workflow

1. Fork and create a feature branch (`feat/...` or `fix/...`).
2. Make your change with tests (see below).
3. Ensure the full quality gate passes locally.
4. Open a pull request describing the change and its motivation.

## Quality gate

Every PR must pass:

```bash
composer test       # Pest — unit, feature and corpus tests
composer analyse    # PHPStan / Larastan level 8
composer format     # Laravel Pint (run it; commit the result)
```

CI runs the matrix `{ubuntu, windows} × {PHP 8.3, 8.4} × {Laravel 12, 13} ×
{prefer-lowest, prefer-stable}`. `prefer-lowest` is the highest-value axis — it
catches use of APIs newer than our declared floor.

## Tests we expect

- **Every detector/normalizer** ships positive *and* negative cases.
- **New injection attacks** go into `tests/Corpus/injection_attacks.php`; benign
  look-alikes go into `tests/Corpus/injection_benign.php`. The corpus has CI
  gates on recall and false-positive rate — a PR that lowers recall or raises
  false positives below threshold will fail.
- **Drivers** are tested with `Http::fake()` + `Http::preventStrayRequests()`;
  the deterministic layer must never make a network call.
- **Security fixes** include a regression test that reproduces the issue.

## Adding a scanner / detector / driver

Warden is extensible without forking:

- A **scanner** implements `Contracts\Scanner` and is registered with the
  `ScannerRegistry`.
- A **detector** implements `Contracts\Detector`.
- A **driver** implements `Contracts\InjectionDriver` / `Contracts\ModerationDriver`
  and is registered on the relevant manager via `extend()`.

See `docs/decisions/` for the architecture decisions behind these seams.

## Reporting security issues

Do **not** open a public issue — see [SECURITY.md](SECURITY.md).

## Code style

We use Laravel Pint (`laravel` preset). Run `composer format` before pushing.
Keep code, comments and naming consistent with the surrounding files.
