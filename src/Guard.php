<?php

declare(strict_types=1);

namespace Sellinnate\Warden;

use Illuminate\Contracts\Events\Dispatcher;
use Sellinnate\Warden\Enums\Direction;
use Sellinnate\Warden\Enums\FailMode;
use Sellinnate\Warden\Enums\Severity;
use Sellinnate\Warden\Policies\Policy;
use Sellinnate\Warden\Policies\PolicyRepository;
use Sellinnate\Warden\Support\PendingScan;
use Sellinnate\Warden\Support\ScanContext;
use Sellinnate\Warden\Support\ScannerRegistry;
use Sellinnate\Warden\Support\Vault;
use Sellinnate\Warden\ValueObjects\ScanResult;
use Sellinnate\Warden\ValueObjects\Verdict;
use Throwable;

/**
 * The orchestrator and public entry point. Resolves the active policy, runs the
 * ordered scanner pipeline for a direction, and aggregates the per-scanner
 * results into a single {@see Verdict}.
 */
final class Guard
{
    public function __construct(
        private readonly ScannerRegistry $scanners,
        private readonly PolicyRepository $policies,
        private readonly ?Dispatcher $events = null,
        private readonly int $maxInputBytes = 0,
    ) {}

    /**
     * Inspect an input: run the full input pipeline and return a Verdict. The
     * caller decides what to do with `blocked()` / `sanitizedText`.
     */
    public function inspect(string $text, ?string $policy = null): Verdict
    {
        return $this->run(Direction::Input, $text, $this->policies->get($policy));
    }

    /**
     * Sanitize an input: identical pipeline to {@see inspect()}; the name signals
     * intent to consume `sanitizedText`.
     */
    public function sanitize(string $text, ?string $policy = null): Verdict
    {
        return $this->run(Direction::Input, $text, $this->policies->get($policy));
    }

    /**
     * Inspect an LLM output: runs the output pipeline, optionally restoring
     * pseudonymized values from the request's {@see Vault}.
     */
    public function inspectOutput(string $text, ?Vault $vault = null, ?string $policy = null): Verdict
    {
        return $this->run(Direction::Output, $text, $this->policies->get($policy), $vault);
    }

    /**
     * Inspect retrieved/ingested content (RAG chunks, tool output) as untrusted
     * input for indirect-injection purposes.
     */
    public function inspectRetrieval(string $text, ?string $policy = null): Verdict
    {
        return $this->run(Direction::Retrieval, $text, $this->policies->get($policy));
    }

    /**
     * Start a fluent, configured-at-call scan (Level 2 API).
     */
    public function for(Direction $direction): PendingScan
    {
        return new PendingScan($this, $this->policies, $direction);
    }

    /**
     * Run an explicit policy/direction. Used by {@see PendingScan} and the
     * public methods above.
     */
    public function run(Direction $direction, string $text, Policy $policy, ?Vault $vault = null): Verdict
    {
        $truncated = false;

        if ($this->maxInputBytes > 0 && strlen($text) > $this->maxInputBytes) {
            // mb_strcut respects UTF-8 boundaries so we never split a code point.
            $text = mb_strcut($text, 0, $this->maxInputBytes, 'UTF-8');
            $truncated = true;
        }

        $context = ScanContext::for($direction, $text, $policy, $vault);

        if ($truncated) {
            $context->addSignal('input_truncated');
        }

        foreach ($policy->scannersFor($direction) as $name) {
            if (! $this->scanners->has($name)) {
                continue;
            }

            $scanner = $this->scanners->resolve($name);

            if (! $scanner->supports($direction)) {
                continue;
            }

            try {
                $result = $scanner->scan($context);
            } catch (Throwable $e) {
                $result = $this->onFailure($name, $context, $e);
            }

            $context->record($result);
            $this->dispatch($result, $context);

            if (! $result->valid && $policy->failFast) {
                $context->shortCircuit();
                break;
            }
        }

        return $this->aggregate($context);
    }

    /**
     * Apply the per-scanner fail policy when a scanner throws.
     */
    private function onFailure(string $name, ScanContext $context, Throwable $e): ScanResult
    {
        $mode = $context->policy->failMode($name);

        if ($mode === FailMode::Closed) {
            return new ScanResult(
                scanner: $name,
                valid: false,
                riskScore: 1.0,
                sanitizedText: $context->current,
                detections: [],
            );
        }

        // Fail-open: degrade gracefully, let the payload through.
        return ScanResult::clean($name, $context->current);
    }

    private function aggregate(ScanContext $context): Verdict
    {
        $results = $context->results();

        $valid = true;
        $risk = 0.0;

        foreach ($results as $result) {
            $valid = $valid && $result->valid;
            $risk = max($risk, $result->riskScore);
        }

        $vault = $context->vault->isEmpty() ? null : $context->vault;

        return new Verdict(
            valid: $valid,
            riskScore: $risk,
            severity: Severity::fromScore($risk),
            sanitizedText: $context->current,
            originalText: $context->original,
            results: $results,
            vault: $vault,
        );
    }

    private function dispatch(ScanResult $result, ScanContext $context): void
    {
        if ($this->events === null || ! $result->hasDetections()) {
            return;
        }

        foreach (EventFactory::forScanResult($result, $context) as $event) {
            $this->events->dispatch($event);
        }
    }
}
