<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Scanners;

use Sellinnate\Warden\Contracts\Scanner;
use Sellinnate\Warden\Enums\Action;
use Sellinnate\Warden\Enums\Direction;
use Sellinnate\Warden\Support\ScanContext;
use Sellinnate\Warden\ValueObjects\Detection;
use Sellinnate\Warden\ValueObjects\ScanResult;

/**
 * Output-only scanner that enforces structured output (OWASP LLM05, machine-to-
 * machine consumers). When JSON is required it validates the output and, if it's
 * wrapped in prose / code fences, attempts a conservative repair (extract the
 * first balanced JSON value); if it still isn't valid JSON it blocks.
 *
 * A no-op unless JSON is required, so ordinary text output is untouched.
 */
final class FormatScanner implements Scanner
{
    public function __construct(
        private readonly bool $requireJson = false,
    ) {}

    public const NAME = 'format';

    public function supports(Direction $direction): bool
    {
        return $direction === Direction::Output;
    }

    public function scan(ScanContext $context): ScanResult
    {
        if (! $this->requireJson) {
            return ScanResult::clean(self::NAME, $context->current, Action::Block);
        }

        $text = $context->current;

        if ($this->isValidJson($text)) {
            return ScanResult::clean(self::NAME, $text, Action::Block);
        }

        $repaired = $this->extractJson($text);
        if ($repaired !== null) {
            $context->current = $repaired;

            return new ScanResult(
                scanner: self::NAME,
                valid: true,
                riskScore: 0.2,
                sanitizedText: $repaired,
                detections: [new Detection('FORMAT_REPAIRED', 0, 0, 0.2, self::NAME)],
                action: Action::Sanitize,
            );
        }

        return new ScanResult(
            scanner: self::NAME,
            valid: false,
            riskScore: 1.0,
            sanitizedText: $text,
            detections: [new Detection('FORMAT_INVALID', 0, 0, 1.0, self::NAME)],
            action: Action::Block,
        );
    }

    private function isValidJson(string $text): bool
    {
        $trimmed = trim($text);
        if ($trimmed === '') {
            return false;
        }

        // Require a structured root (object/array): a bare scalar like "5" or
        // "true" is technically JSON but not what a structured-output consumer wants.
        if ($trimmed[0] !== '{' && $trimmed[0] !== '[') {
            return false;
        }

        json_decode($trimmed, true);

        return json_last_error() === JSON_ERROR_NONE;
    }

    /**
     * Extract the first balanced JSON object/array from prose or code fences.
     */
    private function extractJson(string $text): ?string
    {
        if (preg_match('/[{\[]/', $text, $m, PREG_OFFSET_CAPTURE) !== 1) {
            return null;
        }

        $start = (int) $m[0][1];
        $open = $text[$start];
        $close = $open === '{' ? '}' : ']';

        $depth = 0;
        $inString = false;
        $escaped = false;
        $length = strlen($text);

        for ($i = $start; $i < $length; $i++) {
            $char = $text[$i];

            if ($inString) {
                if ($escaped) {
                    $escaped = false;
                } elseif ($char === '\\') {
                    $escaped = true;
                } elseif ($char === '"') {
                    $inString = false;
                }

                continue;
            }

            if ($char === '"') {
                $inString = true;
            } elseif ($char === $open) {
                $depth++;
            } elseif ($char === $close) {
                $depth--;
                if ($depth === 0) {
                    $candidate = substr($text, $start, $i - $start + 1);

                    return $this->isValidJson($candidate) ? $candidate : null;
                }
            }
        }

        return null;
    }

    public function name(): string
    {
        return self::NAME;
    }
}
