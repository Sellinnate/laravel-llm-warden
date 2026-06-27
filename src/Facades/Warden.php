<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Facades;

use Closure;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Facades\Facade;
use Sellinnate\Warden\Guard;
use Sellinnate\Warden\Policies\PolicyBuilder;
use Sellinnate\Warden\Policies\PolicyRepository;

/**
 * @method static \Sellinnate\Warden\ValueObjects\Verdict inspect(string $text, ?string $policy = null)
 * @method static \Sellinnate\Warden\ValueObjects\Verdict sanitize(string $text, ?string $policy = null)
 * @method static \Sellinnate\Warden\ValueObjects\Verdict inspectOutput(string $text, ?\Sellinnate\Warden\Support\Vault $vault = null, ?string $policy = null)
 * @method static \Sellinnate\Warden\ValueObjects\Verdict inspectRetrieval(string $text, ?string $policy = null)
 * @method static \Sellinnate\Warden\Support\PendingScan for(\Sellinnate\Warden\Enums\Direction $direction)
 * @method static \Sellinnate\Warden\ValueObjects\Verdict run(\Sellinnate\Warden\Enums\Direction $direction, string $text, \Sellinnate\Warden\Policies\Policy $policy, ?\Sellinnate\Warden\Support\Vault $vault = null)
 *
 * @see Guard
 */
final class Warden extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return 'warden';
    }

    /**
     * Register a custom policy profile.
     *
     * @param  Closure(PolicyBuilder):PolicyBuilder  $definition
     */
    public static function definePolicy(string $name, Closure $definition): void
    {
        /** @var Application $app */
        $app = self::getFacadeApplication();

        $app->make(PolicyRepository::class)->define($name, $definition);
    }
}
