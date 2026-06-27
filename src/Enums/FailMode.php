<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Enums;

/**
 * Behaviour when a scanner/driver errors or times out.
 *
 * - Closed: "when in doubt, block" — safe for high-risk contexts (PII/secret).
 * - Open:   "when in doubt, let through" — favours availability (external judges).
 */
enum FailMode: string
{
    case Open = 'open';
    case Closed = 'closed';

    public static function fromString(?string $value, self $default = self::Closed): self
    {
        return self::tryFrom((string) $value) ?? $default;
    }
}
