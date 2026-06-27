<?php

declare(strict_types=1);

namespace Sellinnate\Warden;

use Sellinnate\Warden\Support\ScanContext;
use Sellinnate\Warden\ValueObjects\ScanResult;

/**
 * Translates a {@see ScanResult} into the domain events that should fire for it.
 * Centralised so the Guard stays agnostic to the event catalogue. Phase 1 wires
 * the concrete events (InjectionDetected, PiiRedacted, SecretBlocked, …).
 *
 * @internal
 */
final class EventFactory
{
    /**
     * @return iterable<int, object>
     */
    public static function forScanResult(ScanResult $result, ScanContext $context): iterable
    {
        return [];
    }
}
