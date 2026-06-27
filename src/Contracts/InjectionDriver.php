<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Contracts;

use Sellinnate\Warden\Support\ScanContext;
use Sellinnate\Warden\ValueObjects\InjectionVerdict;

/**
 * An interchangeable prompt-injection backend (deterministic, prompt-guard,
 * prism-judge, lakera). Normalizes its native output into an InjectionVerdict.
 */
interface InjectionDriver
{
    public function evaluate(string $normalized, ScanContext $context): InjectionVerdict;

    public function name(): string;
}
