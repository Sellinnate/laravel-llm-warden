<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Detectors\Pii;

use Closure;
use Sellinnate\Warden\Contracts\Detector;
use Sellinnate\Warden\Support\ScanContext;
use Sellinnate\Warden\ValueObjects\Detection;

/**
 * A regex-based PII detector with an optional checksum validator and optional
 * context-word boosting. Detect-only (Presidio Analyzer model).
 *
 * - If a validator is set, a candidate that fails the checksum is dropped
 *   entirely (so only true positives are emitted at high confidence).
 * - If no validator is set, the base score is used (regex-only entities like
 *   EMAIL/IP), optionally boosted when a context word appears nearby.
 */
final class RegexDetector implements Detector
{
    /** @var Closure(string):bool|null */
    private ?Closure $validator;

    /**
     * @param  array<int, string>  $patterns
     * @param  callable(string):bool|null  $validator
     * @param  array<int, string>  $contextWords
     * @param  bool  $requireContext  when true (and no validator), only emit a
     *                                detection if a context word appears nearby — suppresses false positives
     *                                on ambiguous shapes like version strings "1.2.3.4" or bare numbers.
     */
    public function __construct(
        private readonly string $type,
        private readonly array $patterns,
        private readonly float $score = 0.6,
        ?callable $validator = null,
        private readonly float $validScore = 0.99,
        private readonly array $contextWords = [],
        private readonly bool $requireContext = false,
    ) {
        $this->validator = $validator === null ? null : Closure::fromCallable($validator);
    }

    public function detect(string $normalized, ScanContext $context): array
    {
        $detections = [];

        foreach ($this->patterns as $pattern) {
            if (preg_match_all($pattern, $normalized, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER) === false) {
                continue;
            }

            foreach ($matches as $match) {
                $value = $match[0][0];
                $start = (int) $match[0][1];
                $end = $start + strlen($value);

                if ($this->validator !== null) {
                    if (! ($this->validator)($value)) {
                        continue;
                    }
                    $score = $this->validScore;
                } else {
                    $hasContext = $this->hasContextWord($normalized, $start);

                    if ($this->requireContext && ! $hasContext) {
                        continue;
                    }

                    $score = $this->score;
                    if ($hasContext) {
                        $score = min(1.0, $score + 0.2);
                    }
                }

                $detections[] = new Detection(
                    type: $this->type,
                    start: $start,
                    end: $end,
                    score: $score,
                    scanner: 'pii',
                );
            }
        }

        return $detections;
    }

    private function hasContextWord(string $text, int $start): bool
    {
        if ($this->contextWords === []) {
            return false;
        }

        $window = substr($text, max(0, $start - 40), 40);
        foreach ($this->contextWords as $word) {
            if (stripos($window, $word) !== false) {
                return true;
            }
        }

        return false;
    }

    public function type(): string
    {
        return $this->type;
    }
}
