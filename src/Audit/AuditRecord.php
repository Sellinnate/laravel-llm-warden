<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Audit;

use Sellinnate\Warden\Enums\Direction;
use Sellinnate\Warden\ValueObjects\Detection;
use Sellinnate\Warden\ValueObjects\Verdict;

/**
 * A redacted, serializable audit record. It never contains the raw text or the
 * raw value of any detection — only types, scores, scanners and an integrity
 * hash — so the guardrail itself can never become a leak source.
 */
final readonly class AuditRecord
{
    /**
     * @param  array<int, array{type: string, scanner: string, score: float}>  $detections
     */
    public function __construct(
        public string $direction,
        public bool $valid,
        public float $riskScore,
        public string $severity,
        public array $detections,
        public string $textHash,
        public bool $storeRaw = false,
        public ?string $raw = null,
    ) {}

    public static function fromVerdict(Verdict $verdict, Direction $direction, bool $storeRaw = false): self
    {
        $detections = array_map(
            static fn (Detection $d): array => [
                'type' => $d->type,
                'scanner' => $d->scanner,
                'score' => $d->score,
            ],
            $verdict->detections(),
        );

        return new self(
            direction: $direction->value,
            valid: $verdict->valid,
            riskScore: $verdict->riskScore,
            severity: $verdict->severity->name,
            detections: $detections,
            textHash: hash('xxh128', $verdict->originalText),
            storeRaw: $storeRaw,
            raw: $storeRaw ? $verdict->originalText : null,
        );
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        $data = [
            'direction' => $this->direction,
            'valid' => $this->valid,
            'risk_score' => $this->riskScore,
            'severity' => $this->severity,
            'detections' => $this->detections,
            'text_hash' => $this->textHash,
        ];

        if ($this->storeRaw) {
            $data['raw'] = $this->raw;
        }

        return $data;
    }
}
