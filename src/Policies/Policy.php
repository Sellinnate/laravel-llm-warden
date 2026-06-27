<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Policies;

use Sellinnate\Warden\Enums\Action;
use Sellinnate\Warden\Enums\Direction;
use Sellinnate\Warden\Enums\FailMode;

/**
 * An immutable, reusable bundle of scanners, thresholds, actions and fail-modes.
 * Built via {@see PolicyBuilder}. The active policy determines *which* tagged
 * scanners run, *in what order*, and *with what action/threshold*.
 */
final readonly class Policy
{
    /**
     * @param  array<int, string>  $inputScanners  ordered scanner names for the input pipeline
     * @param  array<int, string>  $outputScanners  ordered scanner names for the output pipeline
     * @param  array<int, string>  $retrievalScanners  ordered scanner names for the retrieval pipeline
     * @param  array<string, float>  $thresholds  scanner name => risk threshold (block at/above)
     * @param  array<string, Action>  $actions  scanner name => action override
     * @param  array<string, FailMode>  $failModes  scanner name => fail mode override
     */
    public function __construct(
        public string $name,
        public array $inputScanners = [],
        public array $outputScanners = [],
        public array $retrievalScanners = [],
        public array $thresholds = [],
        public array $actions = [],
        public array $failModes = [],
        public bool $failFast = true,
        public float $defaultThreshold = 0.7,
        public FailMode $defaultFailMode = FailMode::Closed,
    ) {}

    /**
     * Ordered scanner names for the given direction.
     *
     * @return array<int, string>
     */
    public function scannersFor(Direction $direction): array
    {
        return match ($direction) {
            Direction::Input => $this->inputScanners,
            Direction::Output => $this->outputScanners,
            Direction::Retrieval => $this->retrievalScanners,
        };
    }

    public function threshold(string $scanner): float
    {
        return $this->thresholds[$scanner] ?? $this->defaultThreshold;
    }

    public function action(string $scanner, Action $default): Action
    {
        return $this->actions[$scanner] ?? $default;
    }

    public function failMode(string $scanner): FailMode
    {
        return $this->failModes[$scanner] ?? $this->defaultFailMode;
    }

    public function withThreshold(string $scanner, float $threshold): self
    {
        $thresholds = $this->thresholds;
        $thresholds[$scanner] = $threshold;

        return $this->cloneWith(thresholds: $thresholds);
    }

    public function withAction(string $scanner, Action $action): self
    {
        $actions = $this->actions;
        $actions[$scanner] = $action;

        return $this->cloneWith(actions: $actions);
    }

    /**
     * @param  array<int, string>  $only
     */
    public function only(array $only): self
    {
        $filter = static fn (array $scanners): array => array_values(array_filter(
            $scanners,
            static fn (string $s): bool => in_array($s, $only, true),
        ));

        return $this->cloneWith(
            inputScanners: $filter($this->inputScanners),
            outputScanners: $filter($this->outputScanners),
            retrievalScanners: $filter($this->retrievalScanners),
        );
    }

    /**
     * @param  array<int, string>|null  $inputScanners
     * @param  array<int, string>|null  $outputScanners
     * @param  array<int, string>|null  $retrievalScanners
     * @param  array<string, float>|null  $thresholds
     * @param  array<string, Action>|null  $actions
     * @param  array<string, FailMode>|null  $failModes
     */
    public function cloneWith(
        ?array $inputScanners = null,
        ?array $outputScanners = null,
        ?array $retrievalScanners = null,
        ?array $thresholds = null,
        ?array $actions = null,
        ?array $failModes = null,
        ?bool $failFast = null,
    ): self {
        return new self(
            name: $this->name,
            inputScanners: $inputScanners ?? $this->inputScanners,
            outputScanners: $outputScanners ?? $this->outputScanners,
            retrievalScanners: $retrievalScanners ?? $this->retrievalScanners,
            thresholds: $thresholds ?? $this->thresholds,
            actions: $actions ?? $this->actions,
            failModes: $failModes ?? $this->failModes,
            failFast: $failFast ?? $this->failFast,
            defaultThreshold: $this->defaultThreshold,
            defaultFailMode: $this->defaultFailMode,
        );
    }
}
