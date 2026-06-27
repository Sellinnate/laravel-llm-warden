<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Policies;

use Sellinnate\Warden\Enums\Action;
use Sellinnate\Warden\Enums\FailMode;

/**
 * Fluent builder for custom policies.
 *
 * Warden::definePolicy('chatbot', fn (PolicyBuilder $p) => $p
 *     ->inputScanners(['normalize', 'injection', 'nsfw', 'pii'])
 *     ->outputScanners(['deanonymize', 'output-leak', 'markdown-defang', 'nsfw'])
 *     ->threshold('injection', 0.75)
 *     ->action('pii', Action::Sanitize)
 *     ->failClosed()
 * );
 */
final class PolicyBuilder
{
    /** @var array<int, string> */
    private array $inputScanners = ['normalize', 'injection', 'secret', 'pii', 'nsfw'];

    /** @var array<int, string> */
    private array $outputScanners = ['deanonymize', 'output-leak', 'markdown-defang', 'nsfw', 'format'];

    /** @var array<int, string> */
    private array $retrievalScanners = ['normalize', 'injection', 'secret', 'pii'];

    /** @var array<string, float> */
    private array $thresholds = [];

    /** @var array<string, Action> */
    private array $actions = [];

    /** @var array<string, FailMode> */
    private array $failModes = [];

    private bool $failFast = true;

    private float $defaultThreshold = 0.7;

    private FailMode $defaultFailMode = FailMode::Closed;

    public function __construct(
        private readonly string $name,
    ) {}

    /**
     * @param  array<int, string>  $scanners
     */
    public function inputScanners(array $scanners): self
    {
        $this->inputScanners = $scanners;

        return $this;
    }

    /**
     * @param  array<int, string>  $scanners
     */
    public function outputScanners(array $scanners): self
    {
        $this->outputScanners = $scanners;

        return $this;
    }

    /**
     * @param  array<int, string>  $scanners
     */
    public function retrievalScanners(array $scanners): self
    {
        $this->retrievalScanners = $scanners;

        return $this;
    }

    public function threshold(string $scanner, float $threshold): self
    {
        $this->thresholds[$scanner] = $threshold;

        return $this;
    }

    public function defaultThreshold(float $threshold): self
    {
        $this->defaultThreshold = $threshold;

        return $this;
    }

    public function action(string $scanner, Action $action): self
    {
        $this->actions[$scanner] = $action;

        return $this;
    }

    public function failMode(string $scanner, FailMode $mode): self
    {
        $this->failModes[$scanner] = $mode;

        return $this;
    }

    public function failClosed(): self
    {
        $this->defaultFailMode = FailMode::Closed;

        return $this;
    }

    public function failOpen(): self
    {
        $this->defaultFailMode = FailMode::Open;

        return $this;
    }

    public function failFast(bool $enabled = true): self
    {
        $this->failFast = $enabled;

        return $this;
    }

    public function build(): Policy
    {
        return new Policy(
            name: $this->name,
            inputScanners: $this->inputScanners,
            outputScanners: $this->outputScanners,
            retrievalScanners: $this->retrievalScanners,
            thresholds: $this->thresholds,
            actions: $this->actions,
            failModes: $this->failModes,
            failFast: $this->failFast,
            defaultThreshold: $this->defaultThreshold,
            defaultFailMode: $this->defaultFailMode,
        );
    }
}
