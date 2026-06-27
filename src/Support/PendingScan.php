<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Support;

use Sellinnate\Warden\Enums\Action;
use Sellinnate\Warden\Enums\Direction;
use Sellinnate\Warden\Guard;
use Sellinnate\Warden\Policies\Policy;
use Sellinnate\Warden\Policies\PolicyRepository;
use Sellinnate\Warden\ValueObjects\Verdict;

/**
 * Level-2 fluent API: configure a one-off scan starting from a named policy.
 *
 *   Warden::for(Direction::Input)
 *       ->usingPolicy('balanced')
 *       ->only(['normalize', 'injection', 'pii'])
 *       ->withThreshold('injection', 0.7)
 *       ->failClosed()
 *       ->scan($userPrompt);
 */
final class PendingScan
{
    private Policy $policy;

    public function __construct(
        private readonly Guard $guard,
        private readonly PolicyRepository $policies,
        private readonly Direction $direction,
    ) {
        $this->policy = $policies->get();
    }

    public function usingPolicy(string $name): self
    {
        $this->policy = $this->policies->get($name);

        return $this;
    }

    /**
     * @param  array<int, string>  $scanners
     */
    public function only(array $scanners): self
    {
        $this->policy = $this->policy->only($scanners);

        return $this;
    }

    public function withThreshold(string $scanner, float $threshold): self
    {
        $this->policy = $this->policy->withThreshold($scanner, $threshold);

        return $this;
    }

    public function withAction(string $scanner, Action $action): self
    {
        $this->policy = $this->policy->withAction($scanner, $action);

        return $this;
    }

    public function failClosed(): self
    {
        $this->policy = $this->policy->cloneWith(failFast: true);

        return $this;
    }

    public function scan(string $text, ?Vault $vault = null): Verdict
    {
        return $this->guard->run($this->direction, $text, $this->policy, $vault);
    }

    public function sanitizedText(string $text): string
    {
        return $this->scan($text)->sanitizedText;
    }
}
