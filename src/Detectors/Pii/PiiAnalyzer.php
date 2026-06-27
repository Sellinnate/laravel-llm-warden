<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Detectors\Pii;

use Sellinnate\Warden\Contracts\Detector;
use Sellinnate\Warden\Support\ScanContext;
use Sellinnate\Warden\ValueObjects\Detection;

/**
 * Orchestrates a registry of PII {@see Detector}s and merges their results with
 * Presidio's overlap rules:
 *  - full overlap (same span)  → keep the higher score;
 *  - containment               → keep the longer span;
 *  - partial intersection      → keep both.
 *
 * Detect-only: returns Detection[] sorted by start offset.
 */
final class PiiAnalyzer
{
    /** @var array<int, Detector> */
    private array $detectors;

    /**
     * @param  array<int, Detector>  $detectors
     */
    public function __construct(array $detectors)
    {
        $this->detectors = $detectors;
    }

    public function add(Detector $detector): void
    {
        $this->detectors[] = $detector;
    }

    /**
     * @return array<int, Detection>
     */
    public function analyze(string $text, ScanContext $context): array
    {
        $detections = [];
        foreach ($this->detectors as $detector) {
            foreach ($detector->detect($text, $context) as $detection) {
                $detections[] = $detection;
            }
        }

        return $this->resolveOverlaps($detections);
    }

    /**
     * @param  array<int, Detection>  $detections
     * @return array<int, Detection>
     */
    private function resolveOverlaps(array $detections): array
    {
        // Higher score first, then longer span first, so the "winner" of a
        // full-overlap / containment conflict is kept and the loser dropped.
        usort($detections, static function (Detection $a, Detection $b): int {
            return [$b->score, $b->length()] <=> [$a->score, $a->length()];
        });

        $kept = [];
        foreach ($detections as $candidate) {
            foreach ($kept as $k) {
                // Drop only when a kept detection fully contains the candidate
                // (covers same-span and containment). Partial overlaps coexist.
                if ($k->contains($candidate)) {
                    continue 2;
                }
            }
            $kept[] = $candidate;
        }

        usort($kept, static fn (Detection $a, Detection $b): int => $a->start <=> $b->start);

        return $kept;
    }
}
