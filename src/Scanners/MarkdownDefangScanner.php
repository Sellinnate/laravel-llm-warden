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
 * Output-only scanner that neutralises data-exfiltration channels in rendered
 * LLM output (OWASP LLM05): auto-loading images and off-domain links can smuggle
 * data out via their URL the moment the output is rendered.
 *
 * Covers the channels an attacker actually reaches: inline markdown images/links,
 * reference-style definitions, raw HTML `<img>`/`<a>`, and angle-bracket
 * autolinks. URLs are classified by host against an allow-list; protocol-relative
 * (`//host`) and non-http(s) schemes (`data:`, `javascript:`, `mailto:`) are
 * always defanged.
 *
 * NOTE: this is a defensive transform over common renderer behaviour, not a full
 * HTML sanitizer. Treat LLM output as untrusted and additionally escape/sanitize
 * at render time for your specific renderer.
 */
final class MarkdownDefangScanner implements Scanner
{
    public const NAME = 'markdown-defang';

    /**
     * @param  array<int, string>  $allowedDomains
     */
    public function __construct(
        private readonly array $allowedDomains = [],
    ) {}

    public function supports(Direction $direction): bool
    {
        return $direction === Direction::Output;
    }

    public function scan(ScanContext $context): ScanResult
    {
        $detections = [];
        $text = $context->current;

        // 1. Inline markdown images: ![alt](url) — alt may contain escaped brackets.
        $text = preg_replace_callback(
            '/!\[((?:[^\]\\\\]|\\\\.)*)\]\(\s*<?([^)\s>]+)>?(?:\s+"[^"]*")?\s*\)/',
            function (array $m) use (&$detections): string {
                if ($this->isAllowed($m[2])) {
                    return $m[0];
                }
                $detections[] = $this->detect('MARKDOWN_IMAGE_EXFIL', $m[2]);

                return $m[1] === '' ? '[image removed]' : "[image: {$m[1]}]";
            },
            $text,
        ) ?? $text;

        // 2. Inline markdown links: [text](url)
        $text = preg_replace_callback(
            '/\[((?:[^\]\\\\]|\\\\.)*)\]\(\s*<?([^)\s>]+)>?(?:\s+"[^"]*")?\s*\)/',
            function (array $m) use (&$detections): string {
                if ($this->isAllowed($m[2])) {
                    return $m[0];
                }
                $detections[] = $this->detect('MARKDOWN_LINK_EXFIL', $m[2]);

                return $m[1];
            },
            $text,
        ) ?? $text;

        // 3. Reference-style definitions: [label]: url  (renders ![x][label]/[x][label])
        $text = preg_replace_callback(
            '/^([ ]{0,3}\[[^\]]+\]:[ \t]*)<?([^\s>]+)>?(.*)$/im',
            function (array $m) use (&$detections): string {
                if ($this->isAllowed($m[2])) {
                    return $m[0];
                }
                $detections[] = $this->detect('MARKDOWN_REF_EXFIL', $m[2]);

                return $m[1].'about:blank'.$m[3];
            },
            $text,
        ) ?? $text;

        // 4. Raw HTML images: <img ... src="url" ...>
        $text = preg_replace_callback(
            '/<img\b[^>]*?\bsrc\s*=\s*["\']?([^"\'>\s]+)["\']?[^>]*>/i',
            function (array $m) use (&$detections): string {
                if ($this->isAllowed($m[1])) {
                    return $m[0];
                }
                $detections[] = $this->detect('HTML_IMAGE_EXFIL', $m[1]);

                return '[image removed]';
            },
            $text,
        ) ?? $text;

        // 5. Raw HTML anchors: <a ... href="url" ...> — strip the off-domain href.
        $text = preg_replace_callback(
            '/<a\b([^>]*?)\bhref\s*=\s*["\']?([^"\'>\s]+)["\']?([^>]*)>/i',
            function (array $m) use (&$detections): string {
                if ($this->isAllowed($m[2])) {
                    return $m[0];
                }
                $detections[] = $this->detect('HTML_LINK_EXFIL', $m[2]);

                return '<a>';
            },
            $text,
        ) ?? $text;

        // 6. Angle-bracket autolinks: <http://host/...>
        $text = preg_replace_callback(
            '/<((?:https?:)?\/\/[^>\s]+)>/i',
            function (array $m) use (&$detections): string {
                if ($this->isAllowed($m[1])) {
                    return $m[0];
                }
                $detections[] = $this->detect('AUTOLINK_EXFIL', $m[1]);

                return $this->defangScheme($m[1]);
            },
            $text,
        ) ?? $text;

        $context->current = $text;

        return new ScanResult(
            scanner: self::NAME,
            valid: true,
            riskScore: $detections === [] ? 0.0 : 0.6,
            sanitizedText: $text,
            detections: $detections,
            action: Action::Sanitize,
        );
    }

    private function detect(string $type, string $url): Detection
    {
        return new Detection(
            type: $type,
            start: 0,
            end: 0,
            score: 0.6,
            scanner: self::NAME,
            context: ['host' => $this->host($url)],
        );
    }

    private function isAllowed(string $url): bool
    {
        $url = trim($url);

        if ($url === '' || str_starts_with($url, '#')) {
            return true;
        }

        // Protocol-relative ("//host/…") renders as an active cross-origin URL.
        if (str_starts_with($url, '//')) {
            return false;
        }

        $hasScheme = preg_match('#^[a-z][a-z0-9+.\-]*:#i', $url) === 1;

        // Scheme-less and not protocol-relative => same-origin relative path: safe.
        if (! $hasScheme) {
            return true;
        }

        $scheme = strtolower((string) parse_url($url, PHP_URL_SCHEME));
        if ($scheme !== 'http' && $scheme !== 'https') {
            return false; // data:, mailto:, javascript:, etc.
        }

        $host = $this->host($url);
        if ($host === null) {
            return false;
        }

        foreach ($this->allowedDomains as $allowed) {
            $allowed = ltrim(strtolower($allowed), '.');
            if ($host === $allowed || str_ends_with($host, '.'.$allowed)) {
                return true;
            }
        }

        return false;
    }

    private function host(string $url): ?string
    {
        $host = parse_url($url, PHP_URL_HOST);

        return is_string($host) ? strtolower($host) : null;
    }

    private function defangScheme(string $url): string
    {
        return (string) preg_replace('#^https?#i', 'hxxp', $url);
    }

    public function name(): string
    {
        return self::NAME;
    }
}
