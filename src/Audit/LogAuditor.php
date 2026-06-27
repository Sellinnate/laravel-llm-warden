<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Audit;

use Psr\Log\LoggerInterface;
use Sellinnate\Warden\Contracts\Auditor;
use Sellinnate\Warden\Enums\Direction;
use Sellinnate\Warden\ValueObjects\Verdict;

/**
 * Default auditor: writes a redacted {@see AuditRecord} to a PSR-3 logger. Only
 * non-trivial verdicts (a detection or a block) are recorded.
 */
final class LogAuditor implements Auditor
{
    public function __construct(
        private readonly LoggerInterface $logger,
        private readonly bool $storeRaw = false,
    ) {}

    public function record(Verdict $verdict, Direction $direction): void
    {
        if ($verdict->valid && $verdict->detections() === []) {
            return; // nothing worth auditing
        }

        $record = AuditRecord::fromVerdict($verdict, $direction, $this->storeRaw);

        $level = $verdict->blocked() ? 'warning' : 'info';
        $this->logger->log($level, 'warden.audit', $record->toArray());
    }
}
