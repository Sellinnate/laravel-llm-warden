<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Support;

use Illuminate\Contracts\Cache\Repository as Cache;
use Sellinnate\Warden\Enums\Direction;
use Sellinnate\Warden\ValueObjects\Verdict;

/**
 * Memoizes verdicts on a hash of the (policy, direction, text). Repeated inputs —
 * very common in chatbots — collapse to a lookup, which also zeroes out paid
 * driver calls.
 *
 * Verdicts that produced a Vault (reversible PII) are NOT cached: the Vault is
 * per-request and must never be shared between requests.
 */
final class VerdictCache
{
    public function __construct(
        private readonly Cache $cache,
        private readonly int $ttl = 3600,
        private readonly string $prefix = 'warden',
    ) {}

    public function key(string $policyName, Direction $direction, string $text): string
    {
        return $this->prefix.':'.$policyName.':'.$direction->value.':'.hash('xxh128', $text);
    }

    public function get(string $key): ?Verdict
    {
        $cached = $this->cache->get($key);

        return $cached instanceof Verdict ? $cached : null;
    }

    public function put(string $key, Verdict $verdict): void
    {
        // Never cache a verdict carrying a per-request Vault.
        if ($verdict->vault !== null) {
            return;
        }

        // Store a cache-safe copy: no raw original text, no per-detection evidence
        // — so the cache never becomes a leak source.
        $this->cache->put($key, $verdict->forCache(), $this->ttl);
    }
}
