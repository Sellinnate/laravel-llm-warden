<?php

declare(strict_types=1);

namespace Sellinnate\Warden\ValueObjects;

/**
 * Normalized output of any InjectionDriver (deterministic, prompt-guard,
 * prism-judge, lakera). Keeps the pipeline agnostic to the model behind it.
 */
final readonly class InjectionVerdict
{
    /**
     * @param  float  $score  0..1 likelihood the text is an injection/jailbreak attempt.
     * @param  array<int, string>  $signals  Human-readable evidence (matched signature, heuristic, category).
     * @param  string  $driver  Driver that produced the verdict.
     */
    public function __construct(
        public float $score,
        public array $signals = [],
        public string $driver = 'deterministic',
    ) {}

    public static function benign(string $driver = 'deterministic'): self
    {
        return new self(0.0, [], $driver);
    }
}
