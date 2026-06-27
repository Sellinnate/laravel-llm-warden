<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Drivers\Moderation;

use Illuminate\Support\Facades\Http;
use Sellinnate\Warden\Contracts\ModerationDriver;
use Sellinnate\Warden\Exceptions\DriverException;
use Sellinnate\Warden\ValueObjects\ModerationVerdict;
use Throwable;

/**
 * OpenAI moderation driver (`omni-moderation-latest`). Maps OpenAI's 13 sub-flags
 * onto Warden's internal S1–S13 taxonomy. BYOK; egress only to OpenAI.
 */
final class OpenAiModerationDriver implements ModerationDriver
{
    /**
     * OpenAI category => internal taxonomy code. Multiple OpenAI flags can map
     * to the same internal category (max score wins).
     *
     * @var array<string, string>
     */
    private const MAP = [
        'hate' => 'S10',
        'hate/threatening' => 'S10',
        'harassment' => 'S10',
        'harassment/threatening' => 'S10',
        'self-harm' => 'S11',
        'self-harm/intent' => 'S11',
        'self-harm/instructions' => 'S11',
        'sexual' => 'S12',
        'sexual/minors' => 'S4',
        'violence' => 'S1',
        'violence/graphic' => 'S1',
        'illicit' => 'S2',
        'illicit/violent' => 'S2',
    ];

    public function __construct(
        private readonly string $apiKey,
        private readonly string $model = 'omni-moderation-latest',
        private readonly string $endpoint = 'https://api.openai.com/v1/moderations',
        private readonly int $timeout = 5,
    ) {}

    public function moderate(string $text): ModerationVerdict
    {
        try {
            $response = Http::withToken($this->apiKey)
                ->timeout($this->timeout)
                ->retry(2, 200, throw: false)
                ->post($this->endpoint, ['model' => $this->model, 'input' => $text]);
        } catch (Throwable $e) {
            throw new DriverException('OpenAI moderation request failed: '.$e->getMessage(), 0, $e);
        }

        if ($response->failed()) {
            throw new DriverException('OpenAI moderation returned HTTP '.$response->status());
        }

        /** @var array<string, float> $scores */
        $scores = (array) $response->json('results.0.category_scores', []);
        $flagged = (bool) $response->json('results.0.flagged', false);

        $categories = [];
        foreach ($scores as $openaiCategory => $score) {
            $internal = self::MAP[$openaiCategory] ?? null;
            if ($internal === null) {
                continue;
            }
            $categories[$internal] = max($categories[$internal] ?? 0.0, (float) $score);
        }

        return new ModerationVerdict($flagged, $categories, 'openai');
    }

    public function name(): string
    {
        return 'openai';
    }
}
