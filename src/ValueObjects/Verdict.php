<?php

declare(strict_types=1);

namespace Sellinnate\Warden\ValueObjects;

use Illuminate\Contracts\Support\Arrayable;
use JsonSerializable;
use Sellinnate\Warden\Enums\Severity;
use Sellinnate\Warden\Support\Vault;

/**
 * The final aggregate returned by the public API. Immutable and serializable so
 * it can be logged, cached and asserted in tests.
 *
 * @implements Arrayable<string, mixed>
 */
final readonly class Verdict implements Arrayable, JsonSerializable
{
    /**
     * @param  array<string, ScanResult>  $results  keyed by scanner name
     */
    public function __construct(
        public bool $valid,
        public float $riskScore,
        public Severity $severity,
        public string $sanitizedText,
        public string $originalText,
        public array $results = [],
        public ?Vault $vault = null,
    ) {}

    /**
     * Was the payload rejected by policy?
     */
    public function blocked(): bool
    {
        return ! $this->valid;
    }

    /**
     * Flatten every Detection across all scanners.
     *
     * @return array<int, Detection>
     */
    public function detections(): array
    {
        $all = [];

        foreach ($this->results as $result) {
            foreach ($result->detections as $detection) {
                $all[] = $detection;
            }
        }

        return $all;
    }

    /**
     * Detections of a given type (e.g. 'PROMPT_INJECTION').
     *
     * @return array<int, Detection>
     */
    public function detectionsOfType(string $type): array
    {
        return array_values(array_filter(
            $this->detections(),
            static fn (Detection $d): bool => $d->type === $type,
        ));
    }

    public function hasDetectionType(string $type): bool
    {
        return $this->detectionsOfType($type) !== [];
    }

    public function result(string $scanner): ?ScanResult
    {
        return $this->results[$scanner] ?? null;
    }

    /**
     * A cache-safe copy: drops the raw original text and any per-detection
     * evidence, and (for blocked verdicts) the sanitized text — so a stored
     * verdict never persists secrets/PII to the cache. The decision, scores and
     * detection types are preserved.
     */
    public function forCache(): self
    {
        $results = [];
        foreach ($this->results as $name => $result) {
            $detections = array_map(
                static fn (Detection $d): Detection => new Detection(
                    $d->type, $d->start, $d->end, $d->score, $d->scanner, [],
                ),
                $result->detections,
            );

            $results[$name] = new ScanResult(
                $result->scanner,
                $result->valid,
                $result->riskScore,
                $this->valid ? $result->sanitizedText : '',
                $detections,
                $result->action,
            );
        }

        return new self(
            valid: $this->valid,
            riskScore: $this->riskScore,
            severity: $this->severity,
            sanitizedText: $this->valid ? $this->sanitizedText : '',
            originalText: '',
            results: $results,
            vault: null,
        );
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'valid' => $this->valid,
            'blocked' => $this->blocked(),
            'risk_score' => $this->riskScore,
            'severity' => $this->severity->name,
            'sanitized_text' => $this->sanitizedText,
            'results' => array_map(static fn (ScanResult $r): array => $r->toArray(), $this->results),
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }
}
