<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Rules;

use Closure;
use Illuminate\Contracts\Validation\ValidationRule;
use Sellinnate\Warden\Enums\Direction;
use Sellinnate\Warden\Guard;
use Sellinnate\Warden\Policies\PolicyRepository;
use Sellinnate\Warden\ValueObjects\Detection;

/**
 * Validation rule: fails when the value contains personal data. Validation rules
 * cannot mutate input, so this rule *rejects* PII; to accept-and-redact, use the
 * Warden facade / middleware instead.
 *
 *   'bio' => ['nullable', 'string', new NoPii],
 *   'bio' => ['nullable', 'string', new NoPii(only: ['IT_FISCAL_CODE', 'IBAN'])],
 */
final class NoPii implements ValidationRule
{
    /**
     * @param  array<int, string>  $only  restrict the rule to these entity types (empty = all)
     */
    public function __construct(
        private readonly array $only = [],
        private readonly ?string $policy = null,
    ) {}

    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        if (! is_string($value) || $value === '') {
            return;
        }

        $verdict = app(Guard::class)->run(
            Direction::Input,
            $value,
            app(PolicyRepository::class)->get($this->policy)->only(['normalize', 'pii']),
        );

        $piiResult = $verdict->result('pii');
        $found = $this->relevant($piiResult === null ? [] : $piiResult->detections);

        if ($found !== []) {
            $fail('warden::messages.pii')->translate();
        }
    }

    /**
     * @param  array<int, Detection>  $detections
     * @return array<int, Detection>
     */
    private function relevant(array $detections): array
    {
        if ($this->only === []) {
            return $detections;
        }

        return array_values(array_filter(
            $detections,
            fn ($d): bool => in_array($d->type, $this->only, true),
        ));
    }
}
