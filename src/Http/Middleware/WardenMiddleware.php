<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;
use Sellinnate\Warden\Enums\Direction;
use Sellinnate\Warden\Guard;
use Sellinnate\Warden\Policies\Policy;
use Sellinnate\Warden\Policies\PolicyRepository;
use Sellinnate\Warden\ValueObjects\Verdict;
use Symfony\Component\HttpFoundation\Response;

/**
 * HTTP middleware that sanitizes/inspects request input (or the response) before
 * it reaches the controller (or the client).
 *
 *   Route::post('/chat', ChatController::class)->middleware('warden:input,strict');
 *
 * On input it recursively scans every string field (including nested arrays such
 * as the OpenAI `messages[]` shape): blocked fields raise a 422 via the native
 * validation flow; allowed fields are replaced with their sanitized text. The
 * per-field verdicts (keyed by dot-path) are exposed via $request->wardenVerdict().
 */
final class WardenMiddleware
{
    public function __construct(
        private readonly Guard $guard,
        private readonly PolicyRepository $policies,
    ) {}

    public function handle(Request $request, Closure $next, string $direction = 'input', ?string $policy = null): Response
    {
        if ($direction === 'output') {
            return $this->handleOutput($request, $next, $policy);
        }

        return $this->handleInput($request, $next, $policy);
    }

    private function handleInput(Request $request, Closure $next, ?string $policy): Response
    {
        $policyObject = $this->policies->get($policy);

        $errors = [];
        $verdicts = [];

        $sanitized = $this->sanitizeInput($request->all(), '', $policyObject, $errors, $verdicts);

        $request->replace($sanitized);
        $request->attributes->set('warden', $verdicts);

        if ($errors !== []) {
            throw ValidationException::withMessages($errors);
        }

        return $next($request);
    }

    /**
     * @param  array<mixed>  $input
     * @param  array<string, array<int, string>>  $errors
     * @param  array<string, Verdict>  $verdicts
     * @return array<mixed>
     */
    private function sanitizeInput(array $input, string $prefix, Policy $policy, array &$errors, array &$verdicts): array
    {
        foreach ($input as $key => $value) {
            $path = $prefix === '' ? (string) $key : $prefix.'.'.$key;

            if (is_array($value)) {
                $input[$key] = $this->sanitizeInput($value, $path, $policy, $errors, $verdicts);

                continue;
            }

            if (! is_string($value) || $value === '') {
                continue;
            }

            $verdict = $this->guard->run(Direction::Input, $value, $policy);
            $verdicts[$path] = $verdict;

            if ($verdict->blocked()) {
                $errors[$path] = [(string) trans('warden::messages.blocked', ['attribute' => $path])];

                continue;
            }

            $input[$key] = $verdict->sanitizedText;
        }

        return $input;
    }

    private function handleOutput(Request $request, Closure $next, ?string $policy): Response
    {
        /** @var Response $response */
        $response = $next($request);

        $content = $response->getContent();
        if (! is_string($content) || $content === '') {
            return $response;
        }

        $policyName = $policy;

        // JSON-aware: scan each string value, not the serialized envelope.
        $decoded = json_decode($content, true);
        if (is_array($decoded)) {
            $blocked = false;
            $clean = $this->sanitizeOutputArray($decoded, $policyName, $blocked);

            if ($blocked) {
                return $this->blockOutput($response);
            }

            $response->setContent((string) json_encode($clean));

            return $response;
        }

        $verdict = $this->guard->inspectOutput($content, null, $policyName);

        if ($verdict->blocked()) {
            return $this->blockOutput($response);
        }

        $response->setContent($verdict->sanitizedText);

        return $response;
    }

    /**
     * @param  array<mixed>  $data
     * @return array<mixed>
     */
    private function sanitizeOutputArray(array $data, ?string $policy, bool &$blocked): array
    {
        foreach ($data as $key => $value) {
            if (is_array($value)) {
                $data[$key] = $this->sanitizeOutputArray($value, $policy, $blocked);

                continue;
            }

            if (! is_string($value) || $value === '') {
                continue;
            }

            $verdict = $this->guard->inspectOutput($value, null, $policy);

            if ($verdict->blocked()) {
                $blocked = true;

                return $data;
            }

            $data[$key] = $verdict->sanitizedText;
        }

        return $data;
    }

    private function blockOutput(Response $response): Response
    {
        $response->setContent((string) json_encode(['error' => 'output_blocked']));
        $response->setStatusCode(Response::HTTP_UNPROCESSABLE_ENTITY);
        $response->headers->set('Content-Type', 'application/json');

        return $response;
    }
}
