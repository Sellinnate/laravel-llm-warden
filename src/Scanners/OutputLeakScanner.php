<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Scanners;

use Sellinnate\Warden\Contracts\Scanner;
use Sellinnate\Warden\Enums\Action;
use Sellinnate\Warden\Enums\Direction;
use Sellinnate\Warden\Support\ScanContext;
use Sellinnate\Warden\ValueObjects\Detection;
use Sellinnate\Warden\ValueObjects\ScanResult;

/**
 * Output-only scanner that detects system-prompt leakage (OWASP LLM07):
 *
 *  - a **canary token** seeded into the system prompt reappearing in the output
 *    is unambiguous proof the model leaked its instructions → block;
 *  - a verbatim **echo** of a long contiguous slice of the configured system
 *    prompt → likely leak → block.
 *
 * PII/secret leak on output is handled by the dedicated secret/PII scanners.
 */
final class OutputLeakScanner implements Scanner
{
    public const NAME = 'output-leak';

    private const ECHO_WINDOW = 60;

    public function __construct(
        private readonly ?string $canary = null,
        private readonly ?string $systemPrompt = null,
    ) {}

    public function supports(Direction $direction): bool
    {
        return $direction === Direction::Output;
    }

    public function scan(ScanContext $context): ScanResult
    {
        $text = $context->current;
        $detections = [];

        // Compare with whitespace removed so a canary the model splits with
        // spaces/newlines ("CANARY 7f 3a") still trips the check.
        $despaced = self::despace($text);

        if ($this->canary !== null && $this->canary !== '') {
            $pos = strpos($text, $this->canary);
            $leaked = $pos !== false || str_contains($despaced, self::despace($this->canary));

            if ($leaked) {
                $detections[] = new Detection(
                    type: 'SYSTEM_PROMPT_CANARY',
                    start: $pos === false ? 0 : $pos,
                    end: ($pos === false ? 0 : $pos) + strlen($this->canary),
                    score: 1.0,
                    scanner: self::NAME,
                    context: ['signal' => 'canary_leak'],
                );
            }
        }

        if ($this->systemPrompt !== null && $this->echoesSystemPrompt($text)) {
            $detections[] = new Detection(
                type: 'SYSTEM_PROMPT_ECHO',
                start: 0,
                end: 0,
                score: 0.9,
                scanner: self::NAME,
                context: ['signal' => 'system_prompt_echo'],
            );
        }

        $action = $context->policy->action(self::NAME, Action::Block);
        $risk = 0.0;
        foreach ($detections as $d) {
            $risk = max($risk, $d->score);
        }

        $valid = ! ($detections !== [] && $action === Action::Block);

        return new ScanResult(
            scanner: self::NAME,
            valid: $valid,
            riskScore: $risk,
            sanitizedText: $context->current,
            detections: $detections,
            action: $action,
        );
    }

    /**
     * True if any contiguous ECHO_WINDOW-char slice of the system prompt appears
     * verbatim in the output.
     */
    private function echoesSystemPrompt(string $text): bool
    {
        $prompt = self::despace($this->systemPrompt ?? '');
        $haystack = self::despace($text);

        if (strlen($prompt) < self::ECHO_WINDOW) {
            return $prompt !== '' && str_contains($haystack, $prompt);
        }

        $limit = strlen($prompt) - self::ECHO_WINDOW;
        for ($i = 0; $i <= $limit; $i += self::ECHO_WINDOW) {
            $slice = substr($prompt, $i, self::ECHO_WINDOW);
            if (str_contains($haystack, $slice)) {
                return true;
            }
        }

        return false;
    }

    private static function despace(string $value): string
    {
        return (string) preg_replace('/\s+/u', '', $value);
    }

    public function name(): string
    {
        return self::NAME;
    }
}
