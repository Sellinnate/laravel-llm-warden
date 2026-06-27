<?php

declare(strict_types=1);

namespace Sellinnate\Warden;

use Sellinnate\Warden\Enums\Direction;
use Sellinnate\Warden\Events\InjectionDetected;
use Sellinnate\Warden\Events\OutputBlocked;
use Sellinnate\Warden\Events\PiiRedacted;
use Sellinnate\Warden\Events\SecretBlocked;
use Sellinnate\Warden\Support\ScanContext;
use Sellinnate\Warden\ValueObjects\Detection;
use Sellinnate\Warden\ValueObjects\ScanResult;

/**
 * Translates a {@see ScanResult} into the domain events that should fire for it.
 * Centralised so the Guard stays agnostic to the event catalogue.
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
        $events = [];
        $direction = $context->direction;

        switch ($result->scanner) {
            case 'injection':
                $events[] = new InjectionDetected(
                    $direction,
                    $result->riskScore,
                    ! $result->valid,
                    $result->detections,
                );
                break;

            case 'pii':
                $events[] = new PiiRedacted(
                    $direction,
                    $result->detections,
                    self::types($result->detections),
                );
                break;

            case 'secret':
                $events[] = new SecretBlocked(
                    $direction,
                    ! $result->valid,
                    $result->detections,
                    self::types($result->detections),
                );
                break;
        }

        if ($direction === Direction::Output && ! $result->valid) {
            $events[] = new OutputBlocked($result->scanner, $result->riskScore, $result->detections);
        }

        return $events;
    }

    /**
     * @param  array<int, Detection>  $detections
     * @return array<int, string>
     */
    private static function types(array $detections): array
    {
        return array_values(array_unique(array_map(
            static fn (Detection $d): string => $d->type,
            $detections,
        )));
    }
}
