<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Drivers\Moderation;

use Illuminate\Support\Facades\Http;
use Sellinnate\Warden\Contracts\ModerationDriver;
use Sellinnate\Warden\Exceptions\DriverException;
use Sellinnate\Warden\ValueObjects\ModerationVerdict;
use Throwable;

/**
 * Azure AI Content Safety driver. Maps Azure's 4 categories (severity 0–7) onto
 * the internal taxonomy, normalizing severity to a 0–1 score. BYOK.
 */
final class AzureContentSafetyDriver implements ModerationDriver
{
    /**
     * Azure category => internal taxonomy code.
     *
     * @var array<string, string>
     */
    private const MAP = [
        'Hate' => 'S10',
        'Sexual' => 'S12',
        'Violence' => 'S1',
        'SelfHarm' => 'S11',
    ];

    public function __construct(
        private readonly string $apiKey,
        private readonly string $endpoint,
        private readonly int $timeout = 5,
        private readonly float $flagThreshold = 0.5,
    ) {}

    public function moderate(string $text): ModerationVerdict
    {
        $url = rtrim($this->endpoint, '/').'/contentsafety/text:analyze?api-version=2024-09-01';

        try {
            $response = Http::withHeaders(['Ocp-Apim-Subscription-Key' => $this->apiKey])
                ->timeout($this->timeout)
                ->retry(2, 200, throw: false)
                ->post($url, ['text' => $text]);
        } catch (Throwable $e) {
            throw new DriverException('Azure Content Safety request failed: '.$e->getMessage(), 0, $e);
        }

        if ($response->failed()) {
            throw new DriverException('Azure Content Safety returned HTTP '.$response->status());
        }

        /** @var array<int, array{category?: string, severity?: int|float}> $analysis */
        $analysis = (array) $response->json('categoriesAnalysis', []);

        $categories = [];
        foreach ($analysis as $entry) {
            $internal = self::MAP[$entry['category'] ?? ''] ?? null;
            if ($internal === null) {
                continue;
            }
            // Azure severity is 0–7; normalize to 0–1.
            $score = min(1.0, ((float) ($entry['severity'] ?? 0)) / 7.0);
            $categories[$internal] = max($categories[$internal] ?? 0.0, $score);
        }

        $flagged = $categories !== [] && max($categories) >= $this->flagThreshold;

        return new ModerationVerdict($flagged, $categories, 'azure');
    }

    public function name(): string
    {
        return 'azure';
    }
}
