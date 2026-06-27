<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Audit;

use Sellinnate\Warden\Contracts\Auditor;
use Sellinnate\Warden\Enums\Direction;
use Sellinnate\Warden\ValueObjects\Verdict;

/**
 * No-op auditor used when auditing is disabled.
 */
final class NullAuditor implements Auditor
{
    public function record(Verdict $verdict, Direction $direction): void {}
}
