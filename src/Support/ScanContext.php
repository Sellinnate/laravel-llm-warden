<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Support;

use Sellinnate\Warden\Enums\Direction;
use Sellinnate\Warden\Policies\Policy;
use Sellinnate\Warden\ValueObjects\ScanResult;

/**
 * The mutable-per-stage payload that travels through the scanner pipeline.
 *
 * It carries two views of the text:
 *  - {@see $original}: the untouched input, used for byte-accurate redaction.
 *  - {@see $normalized}: the de-obfuscated view, used for detector matching.
 *
 * plus the working text ({@see $current}) that successive sanitizing scanners
 * mutate, the per-request {@see Vault}, the active {@see Policy}, accumulated
 * {@see ScanResult}s, and normalization signals.
 */
final class ScanContext
{
    /** @var array<string, ScanResult> keyed by scanner name */
    private array $results = [];

    /**
     * Free-form signals emitted by the NormalizeScanner (e.g. has_zero_width,
     * has_bidi, mixed_script, decoded_layers) consumed by later scanners to
     * raise risk scores.
     *
     * @var array<string, mixed>
     */
    public array $signals = [];

    /**
     * Decoded payloads (base64/hex) queued for re-scanning by detectors.
     *
     * @var array<int, string>
     */
    public array $decodedPayloads = [];

    /**
     * Byte spans of de-anonymized (restored) values in {@see $current}. These are
     * the user's own data and must not be re-redacted by PII/secret scanners.
     *
     * @var array<int, array{0: int, 1: int}>
     */
    public array $trustedSpans = [];

    private bool $shortCircuited = false;

    public function __construct(
        public readonly Direction $direction,
        public readonly string $original,
        public string $normalized,
        public string $current,
        public readonly Policy $policy,
        public readonly Vault $vault = new Vault,
    ) {}

    public static function for(Direction $direction, string $text, Policy $policy, ?Vault $vault = null): self
    {
        return new self(
            direction: $direction,
            original: $text,
            normalized: $text,
            current: $text,
            policy: $policy,
            vault: $vault ?? new Vault,
        );
    }

    public function record(ScanResult $result): void
    {
        $this->results[$result->scanner] = $result;
    }

    /**
     * @return array<string, ScanResult>
     */
    public function results(): array
    {
        return $this->results;
    }

    public function result(string $scanner): ?ScanResult
    {
        return $this->results[$scanner] ?? null;
    }

    public function shortCircuit(): void
    {
        $this->shortCircuited = true;
    }

    public function isShortCircuited(): bool
    {
        return $this->shortCircuited;
    }

    public function addSignal(string $key, mixed $value = true): void
    {
        $this->signals[$key] = $value;
    }

    public function signal(string $key, mixed $default = null): mixed
    {
        return $this->signals[$key] ?? $default;
    }

    /**
     * True if [$start, $end) lies entirely within a trusted (restored) span.
     */
    public function isTrustedSpan(int $start, int $end): bool
    {
        foreach ($this->trustedSpans as [$s, $e]) {
            if ($start >= $s && $end <= $e) {
                return true;
            }
        }

        return false;
    }
}
