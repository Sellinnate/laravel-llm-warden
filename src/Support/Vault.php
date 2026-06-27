<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Support;

/**
 * Per-request store of the pseudonymization map (placeholder => original value).
 *
 * Used by reversible operators (encrypt/replace-reversible): PII is replaced
 * with a stable placeholder on input, the original kept here, then restored on
 * the output side by the DeanonymizeScanner. A Vault is NEVER shared between
 * requests or tenants.
 */
final class Vault
{
    /** @var array<string, string> placeholder => original value */
    private array $entries = [];

    /** @var array<string, string> original value => placeholder (for de-dup / referential integrity) */
    private array $reverse = [];

    /** @var array<string, int> per-type running counter */
    private array $counters = [];

    /**
     * Store an original value and return a stable placeholder for it.
     * Identical values of the same type collapse to the same placeholder.
     */
    public function store(string $type, string $value): string
    {
        $key = $type."\0".$value;

        if (isset($this->reverse[$key])) {
            return $this->reverse[$key];
        }

        $this->counters[$type] = ($this->counters[$type] ?? 0) + 1;
        $placeholder = sprintf('<%s_%d>', $type, $this->counters[$type]);

        $this->entries[$placeholder] = $value;
        $this->reverse[$key] = $placeholder;

        return $placeholder;
    }

    public function has(string $placeholder): bool
    {
        return isset($this->entries[$placeholder]);
    }

    public function get(string $placeholder): ?string
    {
        return $this->entries[$placeholder] ?? null;
    }

    public function isEmpty(): bool
    {
        return $this->entries === [];
    }

    /**
     * Replace every known placeholder in $text with its original value.
     *
     * Single-pass: a restored value that happens to contain another placeholder
     * string is NOT re-expanded (which would leak an unrelated field's value),
     * because each source position is visited exactly once.
     */
    public function restore(string $text): string
    {
        if ($this->entries === []) {
            return $text;
        }

        return preg_replace_callback(
            '/<[A-Z][A-Z0-9_]*_\d+>/',
            fn (array $m): string => $this->entries[$m[0]] ?? $m[0],
            $text,
        ) ?? $text;
    }

    /**
     * @return array<string, string>
     */
    public function all(): array
    {
        return $this->entries;
    }
}
