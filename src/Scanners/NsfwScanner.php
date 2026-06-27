<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Scanners;

use Sellinnate\Warden\Contracts\Scanner;
use Sellinnate\Warden\Enums\Action;
use Sellinnate\Warden\Enums\Direction;
use Sellinnate\Warden\Exceptions\DriverException;
use Sellinnate\Warden\Managers\ModerationManager;
use Sellinnate\Warden\Support\Redactor;
use Sellinnate\Warden\Support\ScanContext;
use Sellinnate\Warden\ValueObjects\Detection;
use Sellinnate\Warden\ValueObjects\ScanResult;

/**
 * Content-safety scanner. Combines the deterministic deny-list (mapped to the
 * internal S1–S13 taxonomy) with an optional {@see ModerationDriver} (openai/
 * azure/llama-guard). Runs on both input and output, with policy thresholds.
 */
final class NsfwScanner implements Scanner
{
    public const NAME = 'nsfw';

    private const REDACTION = '[FILTERED]';

    /**
     * @param  array<int, array{category: string, label: string, score: float, patterns: array<int, string>}>  $signatures
     */
    public function __construct(
        private readonly array $signatures,
        private readonly ModerationManager $moderation,
    ) {}

    public function supports(Direction $direction): bool
    {
        return $direction === Direction::Input || $direction === Direction::Output;
    }

    public function scan(ScanContext $context): ScanResult
    {
        $detections = $this->matchDenyList($context->normalized, $context->current);

        $threshold = $context->policy->threshold(self::NAME);
        $action = $context->policy->action(self::NAME, Action::Block);

        // Optional moderation driver: merge its categories. If the endpoint is
        // down we degrade to the deny-list detections rather than discarding them
        // (a moderation outage must never reduce coverage below the offline base).
        try {
            $verdict = $this->moderation->driver()->moderate($context->current);

            foreach ($verdict->categories as $category => $score) {
                if ($score <= 0.0) {
                    continue;
                }

                // Child sexual exploitation (S4) is never acceptable: hard-floor.
                $effective = $category === 'S4' ? 1.0 : min(1.0, $score);

                $detections[] = new Detection(
                    type: 'NSFW_'.$category,
                    start: 0,
                    end: 0,
                    score: $effective,
                    scanner: self::NAME,
                    context: ['source' => $verdict->driver],
                );
            }

            // Honour the provider's own flag (it uses per-category calibration we
            // can't reproduce with one threshold) by flooring risk to the threshold.
            if ($verdict->flagged) {
                $detections[] = new Detection(
                    type: 'NSFW_FLAGGED',
                    start: 0,
                    end: 0,
                    score: max($threshold, $verdict->maxScore()),
                    scanner: self::NAME,
                    context: ['source' => $verdict->driver, 'signal' => 'provider_flagged'],
                );
            }
        } catch (DriverException $e) {
            $context->addSignal('moderation_unavailable');
        }

        $risk = 0.0;
        foreach ($detections as $d) {
            $risk = max($risk, $d->score);
        }

        $flagged = $risk >= $threshold;

        $sanitized = $context->current;
        $valid = true;

        if ($flagged) {
            if ($action === Action::Block) {
                $valid = false;
            } elseif ($action === Action::Sanitize) {
                $sanitized = $this->redact($context->current, $detections);
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

    /**
     * @return array<int, Detection>
     */
    private function matchDenyList(string $normalized, string $current): array
    {
        $detections = [];

        foreach ($this->signatures as $rule) {
            foreach ($rule['patterns'] as $pattern) {
                // Match against the current (delivered) text first for accurate
                // spans; fall back to the normalized view for obfuscated hits.
                if (preg_match_all($pattern, $current, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER)) {
                    foreach ($matches as $match) {
                        $start = (int) $match[0][1];
                        $detections[] = new Detection(
                            type: 'NSFW_'.$rule['category'],
                            start: $start,
                            end: $start + strlen($match[0][0]),
                            score: $rule['score'],
                            scanner: self::NAME,
                            context: ['label' => $rule['label']],
                        );
                    }

                    continue;
                }

                if (preg_match($pattern, $normalized) === 1) {
                    $detections[] = new Detection(
                        type: 'NSFW_'.$rule['category'],
                        start: 0,
                        end: 0,
                        score: $rule['score'],
                        scanner: self::NAME,
                        context: ['label' => $rule['label'], 'source' => 'normalized'],
                    );
                }
            }
        }

        return $detections;
    }

    /**
     * @param  array<int, Detection>  $detections
     */
    private function redact(string $text, array $detections): string
    {
        $spans = [];
        foreach ($detections as $d) {
            if ($d->length() > 0) {
                $spans[] = [$d->start, $d->end, self::REDACTION];
            }
        }

        return Redactor::apply($text, $spans);
    }

    public function name(): string
    {
        return self::NAME;
    }
}
