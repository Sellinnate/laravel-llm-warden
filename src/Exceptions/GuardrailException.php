<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Exceptions;

use Sellinnate\Warden\ValueObjects\Verdict;

/**
 * Thrown when a guardrail blocks a payload and the caller opted into the
 * exception-based flow (e.g. the HTTP middleware). Carries the full Verdict.
 */
final class GuardrailException extends WardenException
{
    public function __construct(
        public readonly Verdict $verdict,
        string $message = 'The payload was blocked by a Warden guardrail.',
    ) {
        parent::__construct($message);
    }
}
