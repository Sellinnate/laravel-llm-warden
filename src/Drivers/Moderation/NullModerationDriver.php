<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Drivers\Moderation;

use Sellinnate\Warden\Contracts\ModerationDriver;
use Sellinnate\Warden\ValueObjects\ModerationVerdict;

/**
 * The default offline moderation driver: defers entirely to the deterministic
 * deny-list in the NsfwScanner and never makes a network call.
 */
final class NullModerationDriver implements ModerationDriver
{
    public function moderate(string $text): ModerationVerdict
    {
        return ModerationVerdict::safe('null');
    }

    public function name(): string
    {
        return 'null';
    }
}
