<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Contracts;

use Sellinnate\Warden\Enums\Direction;
use Sellinnate\Warden\Support\ScanContext;
use Sellinnate\Warden\ValueObjects\ScanResult;

/**
 * One stage of the scan pipeline. Receives the (possibly already transformed)
 * context, produces a per-scanner result, and passes the context onward.
 */
interface Scanner
{
    /** Whether this scanner operates on the given direction. */
    public function supports(Direction $direction): bool;

    /** Run the scan against the context and return the per-scanner result. */
    public function scan(ScanContext $context): ScanResult;

    /** Stable identifier used in config, events and audit. */
    public function name(): string;
}
