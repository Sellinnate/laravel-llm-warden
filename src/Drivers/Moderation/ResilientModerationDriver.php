<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Drivers\Moderation;

use Sellinnate\Warden\Contracts\ModerationDriver;
use Sellinnate\Warden\Exceptions\DriverException;
use Sellinnate\Warden\Support\CircuitBreaker;
use Sellinnate\Warden\ValueObjects\ModerationVerdict;
use Throwable;

/**
 * Wraps a moderation driver with a circuit breaker: when the endpoint has failed
 * repeatedly the breaker opens and calls fail fast (raising a DriverException so
 * the per-scanner fail policy decides open/closed) instead of repeatedly hanging.
 */
final class ResilientModerationDriver implements ModerationDriver
{
    public function __construct(
        private readonly ModerationDriver $inner,
        private readonly CircuitBreaker $breaker,
    ) {}

    public function moderate(string $text): ModerationVerdict
    {
        if ($this->breaker->isOpen()) {
            throw new DriverException("Moderation driver [{$this->inner->name()}] circuit is open.");
        }

        try {
            $verdict = $this->inner->moderate($text);
            $this->breaker->recordSuccess();

            return $verdict;
        } catch (Throwable $e) {
            $this->breaker->recordFailure();

            throw $e instanceof DriverException
                ? $e
                : new DriverException($e->getMessage(), 0, $e);
        }
    }

    public function name(): string
    {
        return $this->inner->name();
    }
}
