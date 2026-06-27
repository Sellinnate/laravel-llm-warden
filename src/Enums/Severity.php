<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Enums;

/**
 * Coarse severity bucket derived from a 0..1 risk score, used for
 * human-facing reporting and policy thresholds.
 */
enum Severity: int
{
    case Safe = 0;
    case Low = 1;
    case Medium = 2;
    case High = 3;

    /**
     * Map a normalized 0..1 risk score onto a severity bucket.
     */
    public static function fromScore(float $score): self
    {
        return match (true) {
            $score >= 0.8 => self::High,
            $score >= 0.5 => self::Medium,
            $score >= 0.2 => self::Low,
            default => self::Safe,
        };
    }

    public function label(): string
    {
        return ucfirst($this->name);
    }
}
