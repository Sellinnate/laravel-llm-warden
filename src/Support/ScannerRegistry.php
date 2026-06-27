<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Support;

use Closure;
use Illuminate\Contracts\Container\Container;
use Sellinnate\Warden\Contracts\Scanner;
use Sellinnate\Warden\Exceptions\UnknownScannerException;

/**
 * Maps stable scanner names (used in policies/config) to their implementations,
 * resolving them from the container so each scanner gets full dependency
 * injection. Third-party scanners register here without touching the core.
 */
final class ScannerRegistry
{
    /** @var array<string, class-string<Scanner>|Closure(Container):Scanner> */
    private array $bindings = [];

    public function __construct(
        private readonly Container $container,
    ) {}

    /**
     * @param  class-string<Scanner>|Closure(Container):Scanner  $resolver
     */
    public function register(string $name, string|Closure $resolver): void
    {
        $this->bindings[$name] = $resolver;
    }

    public function has(string $name): bool
    {
        return isset($this->bindings[$name]);
    }

    /**
     * @return array<int, string>
     */
    public function names(): array
    {
        return array_keys($this->bindings);
    }

    public function resolve(string $name): Scanner
    {
        if (! isset($this->bindings[$name])) {
            throw new UnknownScannerException("No scanner registered for name [{$name}].");
        }

        $resolver = $this->bindings[$name];

        $scanner = $resolver instanceof Closure
            ? $resolver($this->container)
            : $this->container->make($resolver);

        if (! $scanner instanceof Scanner) {
            throw new UnknownScannerException("Scanner [{$name}] does not implement the Scanner contract.");
        }

        return $scanner;
    }

    /**
     * Resolve an ordered list of names, silently skipping ones that aren't
     * registered (e.g. optional scanners not installed in this build).
     *
     * @param  array<int, string>  $names
     * @return array<int, Scanner>
     */
    public function resolveMany(array $names): array
    {
        $scanners = [];

        foreach ($names as $name) {
            if ($this->has($name)) {
                $scanners[] = $this->resolve($name);
            }
        }

        return $scanners;
    }
}
