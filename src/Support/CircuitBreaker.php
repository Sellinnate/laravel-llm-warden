<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Support;

use Illuminate\Contracts\Cache\Repository as Cache;

/**
 * A simple cache-backed circuit breaker: after N consecutive failures of an
 * external driver it "opens" for a cooldown, so we stop hammering a dead endpoint
 * and let the per-scanner fail policy take over cheaply.
 *
 * Falls back to in-process state when no cache is provided.
 */
final class CircuitBreaker
{
    /** @var array<string, array{failures: int, open_until: int}> */
    private static array $memory = [];

    public function __construct(
        private readonly string $key,
        private readonly ?Cache $cache = null,
        private readonly int $threshold = 5,
        private readonly int $cooldownSeconds = 60,
    ) {}

    public function isOpen(): bool
    {
        $state = $this->state();

        return $state['open_until'] > $this->now();
    }

    public function recordSuccess(): void
    {
        $this->put(['failures' => 0, 'open_until' => 0]);
    }

    public function recordFailure(): void
    {
        $state = $this->state();
        $failures = $state['failures'] + 1;

        $this->put([
            'failures' => $failures,
            'open_until' => $failures >= $this->threshold ? $this->now() + $this->cooldownSeconds : 0,
        ]);
    }

    /**
     * @return array{failures: int, open_until: int}
     */
    private function state(): array
    {
        if ($this->cache !== null) {
            /** @var array{failures: int, open_until: int}|null $state */
            $state = $this->cache->get($this->cacheKey());

            return $state ?? ['failures' => 0, 'open_until' => 0];
        }

        return self::$memory[$this->key] ?? ['failures' => 0, 'open_until' => 0];
    }

    /**
     * @param  array{failures: int, open_until: int}  $state
     */
    private function put(array $state): void
    {
        if ($this->cache !== null) {
            $this->cache->put($this->cacheKey(), $state, $this->cooldownSeconds + 60);

            return;
        }

        self::$memory[$this->key] = $state;
    }

    private function cacheKey(): string
    {
        return 'warden:breaker:'.$this->key;
    }

    private function now(): int
    {
        return time();
    }

    /**
     * Test helper: clear in-process state.
     */
    public static function flushMemory(): void
    {
        self::$memory = [];
    }
}
