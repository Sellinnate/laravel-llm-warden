<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Policies;

use Closure;
use Sellinnate\Warden\Enums\Action;
use Sellinnate\Warden\Enums\FailMode;
use Sellinnate\Warden\Exceptions\WardenException;

/**
 * Resolves named policies. Ships three profiles (strict/balanced/permissive)
 * and lets applications register custom ones via {@see PolicyBuilder}.
 */
final class PolicyRepository
{
    /** @var array<string, Policy|Closure(PolicyBuilder):PolicyBuilder> */
    private array $custom = [];

    /** @var array<string, Policy> resolved cache */
    private array $resolved = [];

    public function __construct(
        private readonly string $default = 'balanced',
    ) {}

    /**
     * @param  Policy|Closure(PolicyBuilder):PolicyBuilder  $definition
     */
    public function define(string $name, Policy|Closure $definition): void
    {
        $this->custom[$name] = $definition;
        unset($this->resolved[$name]);
    }

    public function defaultName(): string
    {
        return $this->default;
    }

    public function get(?string $name = null): Policy
    {
        $name ??= $this->default;

        if (isset($this->resolved[$name])) {
            return $this->resolved[$name];
        }

        $policy = $this->build($name);

        return $this->resolved[$name] = $policy;
    }

    private function build(string $name): Policy
    {
        if (isset($this->custom[$name])) {
            $definition = $this->custom[$name];

            if ($definition instanceof Policy) {
                return $definition;
            }

            return $definition(new PolicyBuilder($name))->build();
        }

        return match ($name) {
            'strict' => $this->strict(),
            'balanced' => $this->balanced(),
            'permissive' => $this->permissive(),
            default => throw new WardenException("Unknown Warden policy [{$name}]."),
        };
    }

    private function strict(): Policy
    {
        return new Policy(
            name: 'strict',
            inputScanners: ['normalize', 'injection', 'secret', 'pii', 'nsfw'],
            outputScanners: ['normalize', 'deanonymize', 'output-leak', 'secret', 'pii', 'markdown-defang', 'nsfw', 'format'],
            retrievalScanners: ['normalize', 'injection', 'secret', 'pii'],
            thresholds: ['injection' => 0.5, 'nsfw' => 0.4],
            actions: [],
            failModes: [],
            failFast: true,
            defaultThreshold: 0.5,
            defaultFailMode: FailMode::Closed,
        );
    }

    private function balanced(): Policy
    {
        return new Policy(
            name: 'balanced',
            inputScanners: ['normalize', 'injection', 'secret', 'pii', 'nsfw'],
            outputScanners: ['normalize', 'deanonymize', 'output-leak', 'secret', 'pii', 'markdown-defang', 'nsfw', 'format'],
            retrievalScanners: ['normalize', 'injection', 'secret', 'pii'],
            thresholds: ['injection' => 0.7, 'nsfw' => 0.6],
            actions: [],
            failModes: ['injection' => FailMode::Open, 'pii' => FailMode::Closed, 'secret' => FailMode::Closed],
            failFast: true,
            defaultThreshold: 0.7,
            defaultFailMode: FailMode::Closed,
        );
    }

    private function permissive(): Policy
    {
        return new Policy(
            name: 'permissive',
            inputScanners: ['normalize', 'injection', 'secret', 'pii', 'nsfw'],
            outputScanners: ['normalize', 'deanonymize', 'output-leak', 'secret', 'markdown-defang', 'format'],
            retrievalScanners: ['normalize', 'injection'],
            thresholds: ['injection' => 0.85, 'nsfw' => 0.85],
            // Permissive: only hard-block secrets; everything else only sanitizes/detects.
            actions: ['nsfw' => Action::Detect, 'pii' => Action::Sanitize],
            failModes: [],
            failFast: true,
            defaultThreshold: 0.85,
            defaultFailMode: FailMode::Open,
        );
    }
}
