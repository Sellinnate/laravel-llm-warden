<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Scanners;

use Sellinnate\Warden\Contracts\Scanner;
use Sellinnate\Warden\Enums\Action;
use Sellinnate\Warden\Enums\Direction;
use Sellinnate\Warden\Managers\InjectionManager;
use Sellinnate\Warden\Support\ScanContext;
use Sellinnate\Warden\ValueObjects\Detection;
use Sellinnate\Warden\ValueObjects\ScanResult;

/**
 * Prompt-injection / jailbreak scanner (OWASP LLM01). Runs the active injection
 * driver against the normalized detection view and turns its verdict into a
 * policy-gated ScanResult. Operates on input and retrieved (RAG/tool) content.
 */
final class InjectionScanner implements Scanner
{
    public const NAME = 'injection';

    public function __construct(
        private readonly InjectionManager $manager,
    ) {}

    public function supports(Direction $direction): bool
    {
        return $direction === Direction::Input || $direction === Direction::Retrieval;
    }

    public function scan(ScanContext $context): ScanResult
    {
        $verdict = $this->manager->driver()->evaluate($context->normalized, $context);

        $score = min(1.0, max(0.0, $verdict->score));
        $threshold = $context->policy->threshold(self::NAME);
        $action = $context->policy->action(self::NAME, Action::Block);

        $detections = [];
        if ($score > 0.0) {
            $detections[] = new Detection(
                type: 'PROMPT_INJECTION',
                start: 0,
                end: strlen($context->current),
                score: $score,
                scanner: self::NAME,
                context: ['signals' => $verdict->signals, 'driver' => $verdict->driver],
            );
        }

        $flagged = $score >= $threshold;
        $valid = ! ($flagged && $action === Action::Block);

        return new ScanResult(
            scanner: self::NAME,
            valid: $valid,
            riskScore: $score,
            sanitizedText: $context->current,
            detections: $detections,
            action: $action,
        );
    }

    public function name(): string
    {
        return self::NAME;
    }
}
