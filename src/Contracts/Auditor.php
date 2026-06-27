<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Contracts;

use Sellinnate\Warden\Enums\Direction;
use Sellinnate\Warden\ValueObjects\Verdict;

/**
 * Records a redacted audit trail of non-trivial verdicts. Pluggable so the
 * package isn't coupled to a specific logging/storage stack.
 */
interface Auditor
{
    public function record(Verdict $verdict, Direction $direction): void;
}
