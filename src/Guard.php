<?php

declare(strict_types=1);

namespace Sellinnate\Warden;

use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Sellinnate\Warden\Audit\NullAuditor;
use Sellinnate\Warden\Contracts\Auditor;
use Sellinnate\Warden\Enums\Direction;
use Sellinnate\Warden\Enums\FailMode;
use Sellinnate\Warden\Enums\Severity;
use Sellinnate\Warden\Exceptions\WardenException;
use Sellinnate\Warden\Policies\Policy;
use Sellinnate\Warden\Policies\PolicyRepository;
use Sellinnate\Warden\Support\PendingScan;
use Sellinnate\Warden\Support\ScanContext;
use Sellinnate\Warden\Support\ScannerRegistry;
use Sellinnate\Warden\Support\Vault;
use Sellinnate\Warden\Support\VerdictCache;
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
    private readonly Auditor $auditor;

    public function __construct(
        private readonly ScannerRegistry $scanners,
        private readonly PolicyRepository $policies,
        private readonly ?Dispatcher $events = null,
        private readonly int $maxInputBytes = 0,
        ?Auditor $auditor = null,
        private readonly ?VerdictCache $cache = null,
    ) {
        $this->auditor = $auditor ?? new NullAuditor;
    }

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
     * Inspect a batch of retrieved chunks (RAG integration). Returns one Verdict
     * per chunk; callers typically keep `$v->sanitizedText` for non-blocked chunks.
     *
     * @param  array<array-key, mixed>  $chunks  string chunks; non-strings are skipped
     * @return array<array-key, Verdict>
     */
    public function inspectChunks(array $chunks, ?string $policy = null): array
    {
        $resolved = $this->policies->get($policy);
        $verdicts = [];

        foreach ($chunks as $key => $chunk) {
            // Skip non-string elements (RAG metadata, nulls) so one bad chunk
            // doesn't abort the whole batch.
            if (is_string($chunk)) {
                $verdicts[$key] = $this->run(Direction::Retrieval, $chunk, $resolved);
            }
        }

        return $verdicts;
    }

    /**
     * Build a self-contained Guard without a full Laravel application — for use
     * in microservices or standalone jobs. Requires illuminate/container,
     * illuminate/config and illuminate/support to be installed.
     *
     * @param  array<string, mixed>  $config  overrides merged over config/warden.php
     */
    public static function make(array $config = []): self
    {
        if (! class_exists(Container::class) || ! class_exists(Repository::class) || ! function_exists('env')) {
            throw new WardenException(
                'Guard::make() requires illuminate/container, illuminate/config and illuminate/support.',
            );
        }

        $container = new Container;

        /** @var array<string, mixed> $defaults */
        $defaults = require dirname(__DIR__).'/config/warden.php';
        $container->instance('config', new Repository([
            'warden' => array_replace_recursive($defaults, $config),
        ]));

        WardenServiceProvider::registerBindings($container);

        /** @var self $guard */
        $guard = $container->make(self::class);

        return $guard;
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

        // Cache lookup (only when no caller-supplied Vault, to keep results shareable).
        $cacheKey = null;
        if ($this->cache !== null && $vault === null) {
            $cacheKey = $this->cache->key($policy->name, $direction, $text);
            $cached = $this->cache->get($cacheKey);
            if ($cached !== null) {
                // A cache hit still audits and emits events, so repeated payloads
                // never go invisible to the audit log / SIEM / metrics.
                $this->auditor->record($cached, $direction);
                foreach ($cached->results as $result) {
                    $this->dispatch($result, $direction);
                }

                return $cached;
            }
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
            $this->dispatch($result, $direction);

            if (! $result->valid && $policy->failFast) {
                $context->shortCircuit();
                break;
            }
        }

        $verdict = $this->aggregate($context);

        $this->auditor->record($verdict, $direction);

        if ($cacheKey !== null) {
            $this->cache->put($cacheKey, $verdict);
        }

        return $verdict;
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

    private function dispatch(ScanResult $result, Direction $direction): void
    {
        if ($this->events === null || ! $result->hasDetections()) {
            return;
        }

        foreach (EventFactory::forScanResult($result, $direction) as $event) {
            $this->events->dispatch($event);
        }
    }
}
