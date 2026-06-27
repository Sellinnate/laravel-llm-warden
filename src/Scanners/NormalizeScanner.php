<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Scanners;

use Sellinnate\Warden\Contracts\Normalizer;
use Sellinnate\Warden\Contracts\Scanner;
use Sellinnate\Warden\Enums\Action;
use Sellinnate\Warden\Enums\Direction;
use Sellinnate\Warden\Support\Normalizers\BidiStripper;
use Sellinnate\Warden\Support\Normalizers\ConfusableFolder;
use Sellinnate\Warden\Support\Normalizers\InvisibleStripper;
use Sellinnate\Warden\Support\Normalizers\LeetDecoder;
use Sellinnate\Warden\Support\Normalizers\MarkStripper;
use Sellinnate\Warden\Support\Normalizers\RecursiveDecoder;
use Sellinnate\Warden\Support\Normalizers\SpacingCollapser;
use Sellinnate\Warden\Support\Normalizers\UnicodeNormalizer;
use Sellinnate\Warden\Support\ScanContext;
use Sellinnate\Warden\ValueObjects\ScanResult;

/**
 * Always-first scanner on every direction. Produces two views of the text:
 *
 *  - The **delivered** view ({@see ScanContext::$current}): only genuinely
 *    unwanted characters are removed (invisibles, bidi controls). Safe to ship.
 *  - The **detection** view ({@see ScanContext::$normalized}): the delivered
 *    view plus aggressive, lossy transforms (NFKC, confusable folding, combining-
 *    mark stripping, de-leet, spacing collapse) used by detection-only scanners.
 *
 * Decoding is handled out-of-band: base64/hex runs are extracted from the
 * *delivered* (pre-de-leet) text — so the payload is still valid — then each
 * decoded payload is itself pushed through the full detection chain and appended
 * to the detection view. This ordering is deliberate: running de-leet first
 * would corrupt the base64 and silently disable the decode channel.
 */
final class NormalizeScanner implements Scanner
{
    public const NAME = 'normalize';

    /** @var array<int, Normalizer> applied to the delivered text */
    private array $deliverableChain;

    /** @var array<int, Normalizer> applied (after the deliverable chain) to build the detection view */
    private array $detectionChain;

    private ?RecursiveDecoder $decoder;

    /**
     * @param  array<string, mixed>  $config
     */
    public function __construct(array $config = [])
    {
        $enabled = static fn (string $key, bool $default = true): bool => (bool) ($config[$key] ?? $default);

        $this->deliverableChain = array_values(array_filter([
            $enabled('strip_invisible') ? new InvisibleStripper : null,
            $enabled('strip_bidi') ? new BidiStripper : null,
        ]));

        /** @var array<array-key, string> $deleetMap */
        $deleetMap = is_array($config['deleet_map'] ?? null) ? $config['deleet_map'] : [];

        $this->detectionChain = array_values(array_filter([
            $enabled('nfkc') ? new UnicodeNormalizer : null,
            $enabled('confusables') ? new ConfusableFolder : null,
            $enabled('strip_marks') ? new MarkStripper : null,
            // Spacing collapse runs *before* de-leet so spaced leet ("1 g n 0 r e")
            // is first joined ("1gn0re") and then de-leeted ("ignore").
            $enabled('collapse_spacing') ? new SpacingCollapser : null,
            $enabled('deleet') ? new LeetDecoder($deleetMap) : null,
        ]));

        $this->decoder = $enabled('decode_base64')
            ? new RecursiveDecoder((int) ($config['max_decode_depth'] ?? 3))
            : null;
    }

    public function supports(Direction $direction): bool
    {
        return true;
    }

    public function scan(ScanContext $context): ScanResult
    {
        $delivered = $context->current;
        foreach ($this->deliverableChain as $normalizer) {
            $delivered = $normalizer->normalize($delivered, $context);
        }

        $detection = $this->applyDetectionChain($delivered, $context);

        // Out-of-band decode pass on the intact delivered text, then re-normalize
        // each decoded payload so obfuscation *inside* an encoding is still caught.
        if ($this->decoder !== null) {
            $this->decoder->collect($delivered, $context);

            foreach ($context->decodedPayloads as $payload) {
                $detection .= ' '.$this->applyDetectionChain($payload, $context);
            }
        }

        $context->current = $delivered;
        $context->normalized = $detection;

        return new ScanResult(
            scanner: self::NAME,
            valid: true,
            riskScore: 0.0,
            sanitizedText: $delivered,
            detections: [],
            action: Action::Sanitize,
        );
    }

    private function applyDetectionChain(string $text, ScanContext $context): string
    {
        foreach ($this->detectionChain as $normalizer) {
            $text = $normalizer->normalize($text, $context);
        }

        return $text;
    }

    public function name(): string
    {
        return self::NAME;
    }
}
