<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Contracts;

use Sellinnate\Warden\ValueObjects\ModerationVerdict;

/**
 * An interchangeable content-moderation backend (null/deterministic, openai,
 * azure, llama-guard). Normalizes its native output into a ModerationVerdict.
 */
interface ModerationDriver
{
    public function moderate(string $text): ModerationVerdict;

    public function name(): string;
}
