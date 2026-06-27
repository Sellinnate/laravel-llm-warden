<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Rules;

use Closure;
use Illuminate\Contracts\Validation\ValidationRule;
use Sellinnate\Warden\Enums\Direction;
use Sellinnate\Warden\Guard;
use Sellinnate\Warden\Policies\PolicyRepository;

/**
 * Validation rule: fails when the value looks like a prompt-injection / jailbreak
 * attempt. Hooks into Laravel's native 422 / error-bag flow.
 *
 *   'prompt' => ['required', 'string', new NoPromptInjection],
 */
final class NoPromptInjection implements ValidationRule
{
    public function __construct(
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
            app(PolicyRepository::class)->get($this->policy)->only(['normalize', 'injection']),
        );

        if ($verdict->hasDetectionType('PROMPT_INJECTION') && $verdict->blocked()) {
            $fail('warden::messages.injection')->translate();
        }
    }
}
