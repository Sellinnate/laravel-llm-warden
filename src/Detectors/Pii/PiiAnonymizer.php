<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Detectors\Pii;

use Sellinnate\Warden\Support\Redactor;
use Sellinnate\Warden\Support\Vault;
use Sellinnate\Warden\ValueObjects\Detection;
use Sellinnate\Warden\ValueObjects\OperatorConfig;
use Sellinnate\Warden\ValueObjects\SanitizationResult;

/**
 * Applies a per-entity operator to detected PII (Presidio Anonymizer model):
 * replace / redact / mask / hash / encrypt / keep / custom. The `encrypt`
 * operator is reversible — it stores the original in the per-request {@see Vault}
 * and emits a stable placeholder, so the output side can de-anonymize it.
 */
final class PiiAnonymizer
{
    public function __construct(
        private readonly string $hashSalt = '',
    ) {}

    /**
     * @param  array<int, Detection>  $detections
     * @param  callable(string $type): OperatorConfig  $resolveOperator
     */
    public function anonymize(string $text, array $detections, callable $resolveOperator, Vault $vault): SanitizationResult
    {
        $spans = [];
        $applied = [];

        foreach ($detections as $detection) {
            $op = $resolveOperator($detection->type);
            $original = substr($text, $detection->start, $detection->length());

            $replacement = $this->operate($detection->type, $original, $op, $vault);

            if ($replacement === null) {
                continue; // keep operator: leave the text untouched
            }

            $spans[] = [$detection->start, $detection->end, $replacement];
            $applied[] = $detection;
        }

        return new SanitizationResult(Redactor::apply($text, $spans), $applied);
    }

    private function operate(string $type, string $value, OperatorConfig $op, Vault $vault): ?string
    {
        return match ($op->operator) {
            'keep' => null,
            'redact' => '',
            'replace' => "<{$type}>",
            'mask' => $this->mask($value, $op),
            'hash' => $this->hash($value),
            'encrypt' => $vault->store($type, $value),
            'custom' => $this->custom($value, $op),
            default => "<{$type}>",
        };
    }

    /**
     * Keyed (HMAC-SHA256) hash for referential integrity. Refuses to run with an
     * empty salt: an unsalted truncated hash of low-cardinality PII (phone, CF)
     * is trivially reversible, so we fail loudly rather than emit weak output.
     */
    private function hash(string $value): string
    {
        if ($this->hashSalt === '') {
            throw new \RuntimeException(
                'The PII `hash` operator requires a non-empty salt. Set warden.pii.hash_salt.',
            );
        }

        return substr(hash_hmac('sha256', $value, $this->hashSalt), 0, 32);
    }

    private function mask(string $value, OperatorConfig $op): string
    {
        $length = strlen($value);
        $chars = max(0, min($length, (int) $op->param('chars', $length)));
        $maskChar = (string) $op->param('char', '*');
        $maskChar = $maskChar === '' ? '*' : $maskChar[0];
        $fromEnd = (bool) $op->param('from_end', false);

        $mask = str_repeat($maskChar, $chars);
        $keep = $length - $chars;

        return $fromEnd
            ? substr($value, 0, $keep).$mask
            : $mask.substr($value, $chars);
    }

    private function custom(string $value, OperatorConfig $op): string
    {
        $callback = $op->param('callback');

        if (is_callable($callback)) {
            return (string) $callback($value);
        }

        return $value;
    }
}
