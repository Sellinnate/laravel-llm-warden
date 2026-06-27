<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Drivers\Injection;

use Sellinnate\Warden\Contracts\InjectionDriver;
use Sellinnate\Warden\Support\CircuitBreaker;
use Sellinnate\Warden\Support\ScanContext;
use Sellinnate\Warden\ValueObjects\InjectionVerdict;

/**
 * Runs the cheap deterministic driver first and only escalates to the expensive
 * AI judge when the deterministic score is inconclusive (below the escalation
 * threshold) — the economic→costly hierarchy from the spec (§8.5).
 *
 * The judge is wrapped in a circuit breaker; if it's failing (or open) the
 * deterministic verdict stands, so a dead judge endpoint degrades to the offline
 * layer rather than failing the request.
 */
final class LayeredInjectionDriver implements InjectionDriver
{
    public function __construct(
        private readonly InjectionDriver $primary,
        private readonly InjectionDriver $secondary,
        private readonly float $escalateBelow = 0.5,
        private readonly ?CircuitBreaker $breaker = null,
    ) {}

    public function evaluate(string $normalized, ScanContext $context): InjectionVerdict
    {
        $primary = $this->primary->evaluate($normalized, $context);

        // Confident already, or the judge is short-circuited — keep deterministic.
        if ($primary->score >= $this->escalateBelow) {
            return $primary;
        }

        if ($this->breaker !== null && $this->breaker->isOpen()) {
            return $primary;
        }

        try {
            $secondary = $this->secondary->evaluate($normalized, $context);
            $this->breaker?->recordSuccess();
        } catch (\Throwable $e) {
            $this->breaker?->recordFailure();

            // Fail toward the deterministic result (availability over coverage).
            return $primary;
        }

        // Combine: take the stronger signal, keep both sets of evidence.
        if ($secondary->score >= $primary->score) {
            return new InjectionVerdict(
                $secondary->score,
                array_values(array_unique([...$primary->signals, ...$secondary->signals])),
                'layered',
            );
        }

        return $primary;
    }

    public function name(): string
    {
        return 'layered';
    }
}
