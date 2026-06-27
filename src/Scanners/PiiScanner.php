<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Scanners;

use Sellinnate\Warden\Contracts\Scanner;
use Sellinnate\Warden\Detectors\Pii\PiiAnalyzer;
use Sellinnate\Warden\Detectors\Pii\PiiAnonymizer;
use Sellinnate\Warden\Enums\Action;
use Sellinnate\Warden\Enums\Direction;
use Sellinnate\Warden\Support\ScanContext;
use Sellinnate\Warden\ValueObjects\OperatorConfig;
use Sellinnate\Warden\ValueObjects\ScanResult;

/**
 * PII scanner (OWASP LLM02), Presidio-style Analyzer + Anonymizer. Detects on
 * and redacts against the delivered text so spans stay byte-accurate.
 *
 * On input/retrieval it applies the per-entity operators from config (e.g.
 * reversible `encrypt` → Vault for Codice Fiscale). On output it always replaces
 * (any PII the model emitted is a leak to neutralise), letting the
 * DeanonymizeScanner restore legitimately pseudonymized values first.
 */
final class PiiScanner implements Scanner
{
    public const NAME = 'pii';

    /**
     * @param  array<string, array<string, mixed>>  $operators  entity-type => operator config
     */
    public function __construct(
        private readonly PiiAnalyzer $analyzer,
        private readonly PiiAnonymizer $anonymizer,
        private readonly array $operators = [],
    ) {}

    public function supports(Direction $direction): bool
    {
        return true;
    }

    public function scan(ScanContext $context): ScanResult
    {
        $detections = array_values(array_filter(
            $this->analyzer->analyze($context->current, $context),
            static fn ($d): bool => ! $context->isTrustedSpan($d->start, $d->end),
        ));

        $action = $context->policy->action(self::NAME, Action::Sanitize);

        $risk = 0.0;
        foreach ($detections as $d) {
            $risk = max($risk, $d->score);
        }

        $sanitized = $context->current;
        $valid = true;

        if ($detections !== []) {
            if ($action === Action::Block) {
                $valid = false;
            } elseif ($action === Action::Sanitize) {
                $result = $this->anonymizer->anonymize(
                    $context->current,
                    $detections,
                    fn (string $type): OperatorConfig => $this->operatorFor($type, $context->direction),
                    $context->vault,
                );
                $sanitized = $result->text;
                $context->current = $sanitized;
            }
        }

        return new ScanResult(
            scanner: self::NAME,
            valid: $valid,
            riskScore: $risk,
            sanitizedText: $sanitized,
            detections: $detections,
            action: $action,
        );
    }

    private function operatorFor(string $type, Direction $direction): OperatorConfig
    {
        // Output: never re-pseudonymize — replace any emitted PII outright.
        if ($direction === Direction::Output) {
            return new OperatorConfig('replace');
        }

        $config = $this->operators[$type] ?? $this->operators['default'] ?? ['op' => 'replace'];

        return OperatorConfig::fromArray($config);
    }

    public function name(): string
    {
        return self::NAME;
    }
}
