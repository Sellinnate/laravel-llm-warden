<?php

declare(strict_types=1);

namespace Sellinnate\Warden\ValueObjects;

/**
 * Configuration for a single anonymization operator (Presidio-style), resolved
 * per entity type from policy/config.
 */
final readonly class OperatorConfig
{
    /**
     * @param  string  $operator  one of: replace|redact|mask|hash|encrypt|keep|custom
     * @param  array<string, mixed>  $params  operator-specific params (e.g. chars, from_end, char, salt)
     */
    public function __construct(
        public string $operator = 'replace',
        public array $params = [],
    ) {}

    /**
     * @param  array<string, mixed>  $config
     */
    public static function fromArray(array $config): self
    {
        $operator = is_string($config['op'] ?? null) ? $config['op'] : 'replace';
        unset($config['op']);

        return new self($operator, $config);
    }

    public function param(string $key, mixed $default = null): mixed
    {
        return $this->params[$key] ?? $default;
    }
}
