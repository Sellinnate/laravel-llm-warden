<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Scanners;

use Sellinnate\Warden\Contracts\Scanner;
use Sellinnate\Warden\Enums\Action;
use Sellinnate\Warden\Enums\Direction;
use Sellinnate\Warden\Support\Entropy;
use Sellinnate\Warden\Support\Redactor;
use Sellinnate\Warden\Support\ScanContext;
use Sellinnate\Warden\ValueObjects\Detection;
use Sellinnate\Warden\ValueObjects\ScanResult;

/**
 * Secret / credential scanner (OWASP LLM02). Runs high-signal patterns against
 * the delivered text (so spans map byte-accurately for redaction), gates the
 * generic catch-all on Shannon entropy, and also inspects decoded base64/hex
 * payloads for obfuscated secrets.
 *
 * Default action: block on input/retrieval (a secret in a prompt is almost
 * always a mistake to stop), redact on output.
 */
final class SecretScanner implements Scanner
{
    public const NAME = 'secret';

    private const REDACTION = '[REDACTED_SECRET]';

    /**
     * @param  array<int, array{type: string, score: float, pattern: string, group?: int, entropy?: bool}>  $patterns
     */
    public function __construct(
        private readonly array $patterns,
        private readonly float $entropyThreshold = 3.5,
    ) {}

    public function supports(Direction $direction): bool
    {
        return true;
    }

    public function scan(ScanContext $context): ScanResult
    {
        $detections = array_values(array_filter(
            $this->detect($context->current),
            static fn ($d): bool => ! $context->isTrustedSpan($d->start, $d->end),
        ));

        // Detection-only pass over decoded payloads (obfuscated secrets). These
        // get a zero-length span so they force a block but are never "redacted".
        foreach ($context->decodedPayloads as $payload) {
            if ($this->detect($payload) !== []) {
                $detections[] = new Detection('SECRET_ENCODED', 0, 0, 0.9, self::NAME, ['source' => 'decoded']);
                break;
            }
        }

        $default = $context->direction === Direction::Output ? Action::Sanitize : Action::Block;
        $action = $context->policy->action(self::NAME, $default);

        $risk = 0.0;
        foreach ($detections as $d) {
            $risk = max($risk, $d->score);
        }

        $sanitized = $context->current;
        $valid = true;

        // An encoded (zero-length) secret can't be redacted in place — if one is
        // present we must block, even under a Sanitize policy, or it would ship.
        $hasUnredactable = false;
        foreach ($detections as $d) {
            if ($d->length() === 0) {
                $hasUnredactable = true;
                break;
            }
        }

        if ($detections !== []) {
            if ($action === Action::Block || ($action === Action::Sanitize && $hasUnredactable)) {
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
    private function detect(string $text): array
    {
        $detections = [];

        foreach ($this->patterns as $rule) {
            if (preg_match_all($rule['pattern'], $text, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER) === false) {
                continue;
            }

            $group = $rule['group'] ?? 0;
            $entropyGated = $rule['entropy'] ?? false;

            foreach ($matches as $match) {
                // Use the captured value (for the span) but always block out the
                // whole match region so the key= prefix is redacted too.
                $valuePart = $match[$group] ?? $match[0];
                $value = $valuePart[0];

                if ($entropyGated && Entropy::shannon($value) < $this->entropyThreshold) {
                    continue;
                }

                $start = (int) $match[0][1];
                $end = $start + strlen($match[0][0]);

                $detections[] = new Detection(
                    type: $rule['type'],
                    start: $start,
                    end: $end,
                    score: $rule['score'],
                    scanner: self::NAME,
                    context: ['evidence' => $this->maskEvidence($value)],
                );
            }
        }

        return $this->dedupe($detections);
    }

    /**
     * Drop fully-overlapping detections, keeping the higher score.
     *
     * @param  array<int, Detection>  $detections
     * @return array<int, Detection>
     */
    private function dedupe(array $detections): array
    {
        usort($detections, static fn (Detection $a, Detection $b): int => $b->score <=> $a->score);

        $kept = [];
        foreach ($detections as $d) {
            foreach ($kept as $k) {
                if ($d->overlaps($k)) {
                    continue 2;
                }
            }
            $kept[] = $d;
        }

        usort($kept, static fn (Detection $a, Detection $b): int => $a->start <=> $b->start);

        return $kept;
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

    /**
     * Never log a raw secret: keep only a short, partially-masked fingerprint.
     */
    private function maskEvidence(string $value): string
    {
        $len = strlen($value);
        if ($len <= 6) {
            return str_repeat('*', $len);
        }

        return substr($value, 0, 3).str_repeat('*', min(6, $len - 3));
    }

    public function name(): string
    {
        return self::NAME;
    }
}
