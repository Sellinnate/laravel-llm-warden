<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Support\Normalizers;

use Sellinnate\Warden\Contracts\Normalizer;
use Sellinnate\Warden\Support\ScanContext;

/**
 * Detects long base64 / hex runs, decodes them, and re-queues the decoded
 * payload for scanning. Encoded instructions ("decode this and follow it") and
 * obfuscated secrets are a real channel; this is the single decode pass reused
 * by injection and secret detection.
 *
 * Decoded content is appended to the returned (normalized) view so detection-
 * only scanners see it, and pushed onto {@see ScanContext::$decodedPayloads}
 * for scanners that need the raw decoded text. Recursion depth and total output
 * size are bounded to prevent decode-bomb DoS.
 */
final class RecursiveDecoder implements Normalizer
{
    private const MIN_RUN = 16;

    private const MAX_TOTAL_DECODED = 64_000;

    /** Skip runs longer than this to bound per-candidate decode allocation. */
    private const MAX_CANDIDATE = 96_000;

    public function __construct(
        private readonly int $maxDepth = 3,
    ) {}

    public function normalize(string $text, ScanContext $context): string
    {
        $decoded = $this->collect($text, $context);

        if ($decoded === []) {
            return $text;
        }

        return $text.' '.implode(' ', $decoded);
    }

    /**
     * Extract, decode and (recursively) re-decode base64/hex runs, pushing each
     * decoded payload onto {@see ScanContext::$decodedPayloads}. Returns the
     * decoded payloads found this call.
     *
     * @return array<int, string>
     */
    public function collect(string $text, ScanContext $context): array
    {
        if ($text === '') {
            return [];
        }

        $budget = self::MAX_TOTAL_DECODED;
        $decoded = $this->decodeLayer($text, $context, $this->maxDepth, $budget);

        if ($decoded !== []) {
            $context->addSignal('decoded_layers', count($decoded));
        }

        return $decoded;
    }

    /**
     * @param  int  $budget  remaining byte budget (passed by reference)
     * @return array<int, string> decoded payloads found at this layer and below
     */
    private function decodeLayer(string $text, ScanContext $context, int $depth, int &$budget): array
    {
        if ($depth <= 0 || $budget <= 0) {
            return [];
        }

        $found = [];

        foreach ($this->extractRuns($text) as $candidate) {
            if (strlen($candidate) > self::MAX_CANDIDATE) {
                continue;
            }

            $plain = $this->tryDecode($candidate);

            if ($plain === null || $plain === '' || $plain === $candidate) {
                continue;
            }

            if (strlen($plain) > $budget) {
                $plain = substr($plain, 0, $budget);
            }

            $budget -= strlen($plain);
            $context->decodedPayloads[] = $plain;
            $found[] = $plain;

            // Re-scan the decoded payload for further nested encodings.
            foreach ($this->decodeLayer($plain, $context, $depth - 1, $budget) as $nested) {
                $found[] = $nested;
            }

            if ($budget <= 0) {
                break;
            }
        }

        return $found;
    }

    /**
     * @return array<int, string> candidate base64/hex runs
     */
    private function extractRuns(string $text): array
    {
        $runs = [];

        if (preg_match_all('/[A-Za-z0-9+\/]{'.self::MIN_RUN.',}={0,2}/', $text, $b64)) {
            foreach ($b64[0] as $run) {
                $runs[] = $run;
            }
        }

        // Hex runs, with an optional 0x prefix stripped so hex2bin can consume them.
        if (preg_match_all('/\b(?:0x)?([0-9a-fA-F]{'.self::MIN_RUN.',})\b/', $text, $hex)) {
            foreach ($hex[1] as $run) {
                $runs[] = $run;
            }
        }

        return array_unique($runs);
    }

    private function tryDecode(string $candidate): ?string
    {
        // Hex first (stricter charset): even length, pure hex digits.
        if (strlen($candidate) % 2 === 0 && preg_match('/^[0-9a-fA-F]+$/', $candidate) === 1) {
            $bin = @hex2bin($candidate);
            if ($bin !== false && $this->isMostlyPrintable($bin)) {
                return $bin;
            }
        }

        if (preg_match('/^[A-Za-z0-9+\/]+={0,2}$/', $candidate) === 1) {
            $bin = base64_decode($candidate, true);
            if ($bin !== false && $bin !== '' && $this->isMostlyPrintable($bin)) {
                return $bin;
            }
        }

        return null;
    }

    /**
     * Reject binary blobs: only treat a decode as meaningful if it's mostly
     * printable text (so we don't surface random bytes as "decoded content").
     */
    private function isMostlyPrintable(string $bin): bool
    {
        $len = strlen($bin);
        if ($len === 0) {
            return false;
        }

        $printable = 0;
        for ($i = 0; $i < $len; $i++) {
            $o = ord($bin[$i]);
            if ($o === 9 || $o === 10 || $o === 13 || ($o >= 32 && $o <= 126) || $o >= 128) {
                $printable++;
            }
        }

        return ($printable / $len) >= 0.85 && mb_check_encoding($bin, 'UTF-8');
    }

    public function name(): string
    {
        return 'decode';
    }
}
