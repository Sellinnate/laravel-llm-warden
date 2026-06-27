<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Rules;

use Closure;
use Illuminate\Contracts\Validation\ValidationRule;
use Sellinnate\Warden\Guard;

/**
 * General-purpose validation rule: fails when the full input pipeline of the
 * given policy would block the value (injection, secret, NSFW, …).
 *
 *   'message' => ['required', 'string', new Clean('strict')],
 */
final class Clean implements ValidationRule
{
    public function __construct(
        private readonly ?string $policy = null,
    ) {}

    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        if (! is_string($value) || $value === '') {
            return;
        }

        if (app(Guard::class)->inspect($value, $this->policy)->blocked()) {
            $fail('warden::messages.blocked')->translate();
        }
    }
}
