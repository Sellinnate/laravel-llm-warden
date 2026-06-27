<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Scanners;

use Sellinnate\Warden\Contracts\Scanner;
use Sellinnate\Warden\Enums\Action;
use Sellinnate\Warden\Enums\Direction;
use Sellinnate\Warden\Support\ScanContext;
use Sellinnate\Warden\ValueObjects\ScanResult;

/**
 * Output-only scanner that restores the original values pseudonymized on the
 * input side (the inverse of the PII `encrypt` operator). It runs EARLY in the
 * output pipeline (right after normalize) so the later defang/format scanners
 * still process the restored text — while the restored spans are marked
 * "trusted" so the output PII/secret scanners don't re-redact the user's own data.
 *
 * Only placeholders this request actually minted are restored (the Vault's
 * restore is a single-pass lookup), so a user echoing an arbitrary `<TYPE_N>`
 * can at most recover their own request's data.
 */
final class DeanonymizeScanner implements Scanner
{
    public const NAME = 'deanonymize';

    public function supports(Direction $direction): bool
    {
        return $direction === Direction::Output;
    }

    public function scan(ScanContext $context): ScanResult
    {
        if ($context->vault->isEmpty()) {
            return ScanResult::clean(self::NAME, $context->current, Action::Sanitize);
        }

        $result = $context->vault->restoreWithSpans($context->current);
        $restored = $result['text'];

        $context->current = $restored;
        // Keep the normalized view consistent for later output scanners.
        $context->normalized = $restored;
        // Mark restored regions trusted so output PII/secret scanners skip them.
        $context->trustedSpans = array_merge($context->trustedSpans, $result['spans']);

        return new ScanResult(
            scanner: self::NAME,
            valid: true,
            riskScore: 0.0,
            sanitizedText: $restored,
            detections: [],
            action: Action::Sanitize,
        );
    }

    public function name(): string
    {
        return self::NAME;
    }
}
