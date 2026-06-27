<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Drivers\Injection;

use Sellinnate\Warden\Contracts\InjectionDriver;
use Sellinnate\Warden\Support\ScanContext;
use Sellinnate\Warden\ValueObjects\InjectionVerdict;

/**
 * The default, offline injection detector: high-signal signature deny-list +
 * structural heuristics (many-shot, payload-splitting) + the Unicode obfuscation
 * signals already surfaced by the NormalizeScanner.
 *
 * Scores combine probabilistically (1 - ∏(1 - sᵢ)) so multiple weak signals add
 * up without ever exceeding 1.0. Designed for high precision; novel paraphrased
 * jailbreaks are out of deterministic scope.
 */
final class DeterministicInjectionDriver implements InjectionDriver
{
    /**
     * @var array<int, array{type: string, score: float, patterns: array<int, string>}>
     */
    private array $signatures;

    /**
     * Weight added per obfuscation signal raised during normalization.
     *
     * @var array<string, float>
     */
    private const SIGNAL_WEIGHTS = [
        'has_invisible' => 0.35,
        'has_bidi' => 0.35,
        'mixed_script' => 0.3,
        'has_combining_marks' => 0.25,
        'decoded_layers' => 0.2,
        'has_confusables' => 0.15,
    ];

    /**
     * @param  array<int, array{type: string, score: float, patterns: array<int, string>}>  $signatures
     */
    public function __construct(array $signatures)
    {
        $this->signatures = $signatures;
    }

    public function evaluate(string $normalized, ScanContext $context): InjectionVerdict
    {
        $scores = [];
        $signals = [];

        foreach ($this->signatures as $signature) {
            foreach ($signature['patterns'] as $pattern) {
                if (preg_match($pattern, $normalized) === 1) {
                    $scores[] = $signature['score'];
                    $signals[] = $signature['type'];
                    break; // one match per signature type is enough
                }
            }
        }

        // Obfuscation signals from the normalizer: meaningful mostly when there's
        // already a textual signal, but a strong invisible/bidi channel alone is
        // suspicious. Cap their standalone contribution.
        foreach (self::SIGNAL_WEIGHTS as $signal => $weight) {
            if ($context->signal($signal) !== null) {
                $scores[] = $weight;
                $signals[] = "obfuscation:{$signal}";
            }
        }

        if (($shots = $this->manyShotScore($normalized)) > 0.0) {
            $scores[] = $shots;
            $signals[] = 'heuristic:many_shot';
        }

        if ($this->looksLikePayloadSplitting($normalized)) {
            $scores[] = 0.4;
            $signals[] = 'heuristic:payload_splitting';
        }

        return new InjectionVerdict(
            score: $this->combine($scores),
            signals: array_values(array_unique($signals)),
            driver: $this->name(),
        );
    }

    /**
     * Many-shot jailbreak: a wall of fake conversational turns priming the model
     * to comply. Score scales with the number of turn-like markers.
     */
    private function manyShotScore(string $text): float
    {
        $count = preg_match_all('/^\s*(?:user|assistant|system|human|ai|q|a)\s*[:>\-]/im', $text);

        if ($count === false || $count < 6) {
            return 0.0;
        }

        return min(0.6, 0.1 + ($count - 6) * 0.05);
    }

    /**
     * Payload splitting / token smuggling: assembling a forbidden instruction
     * from fragments. Low-resolution heuristic.
     */
    private function looksLikePayloadSplitting(string $text): bool
    {
        if (preg_match('/\b(?:combine|concatenate|assemble)\b[^.\n]{0,25}\b(?:letters|characters|chars|words|fragments|parts|pieces|strings|tokens|syllables)\b/iu', $text) === 1) {
            return true;
        }

        // Many short quoted/assigned fragments joined with +.
        return preg_match_all('/["\'][^"\']{1,4}["\']\s*\+/', $text) >= 4;
    }

    /**
     * Probabilistic OR of independent signals: 1 - ∏(1 - sᵢ), clamped to [0,1].
     *
     * @param  array<int, float>  $scores
     */
    private function combine(array $scores): float
    {
        $product = 1.0;
        foreach ($scores as $score) {
            $product *= (1.0 - max(0.0, min(1.0, $score)));
        }

        return round(1.0 - $product, 4);
    }

    public function name(): string
    {
        return 'deterministic';
    }
}
