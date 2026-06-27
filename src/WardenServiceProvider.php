<?php

declare(strict_types=1);

namespace Sellinnate\Warden;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;
use Sellinnate\Warden\Policies\PolicyRepository;
use Sellinnate\Warden\Scanners\NormalizeScanner;
use Sellinnate\Warden\Support\ScannerRegistry;

final class WardenServiceProvider extends ServiceProvider
{
    /**
     * Built-in scanner name => class. Registered only if the class exists in the
     * current build, so optional/phased scanners light up automatically.
     *
     * @var array<string, class-string>
     */
    private const SCANNERS = [
        'normalize' => NormalizeScanner::class,
    ];

    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/warden.php', 'warden');

        $this->app->singleton(PolicyRepository::class, function (Container $app): PolicyRepository {
            /** @var Repository $config */
            $config = $app->make('config');

            return new PolicyRepository((string) $config->get('warden.default_policy', 'balanced'));
        });

        $this->app->singleton(ScannerRegistry::class, function (Container $app): ScannerRegistry {
            $registry = new ScannerRegistry($app);

            foreach (self::SCANNERS as $name => $class) {
                if (class_exists($class)) {
                    $registry->register($name, $class);
                }
            }

            return $registry;
        });

        $this->app->singleton(NormalizeScanner::class, function (Container $app): NormalizeScanner {
            /** @var Repository $config */
            $config = $app->make('config');

            /** @var array<string, mixed> $normalizeConfig */
            $normalizeConfig = (array) $config->get('warden.normalize', []);

            return new NormalizeScanner($normalizeConfig);
        });

        $this->app->singleton(Guard::class, function (Container $app): Guard {
            /** @var Repository $config */
            $config = $app->make('config');

            return new Guard(
                $app->make(ScannerRegistry::class),
                $app->make(PolicyRepository::class),
                $app->bound(Dispatcher::class) ? $app->make(Dispatcher::class) : null,
                (int) $config->get('warden.max_input_bytes', 50_000),
            );
        });

        $this->app->alias(Guard::class, 'warden');
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../config/warden.php' => $this->configPath('warden.php'),
            ], 'warden-config');

            $this->publishes([
                __DIR__.'/../resources/lang' => $this->langPath('vendor/warden'),
            ], 'warden-lang');
        }

        $this->loadTranslationsFrom(__DIR__.'/../resources/lang', 'warden');
    }

    private function configPath(string $path): string
    {
        /** @var Application $app */
        $app = $this->app;

        return $app->configPath($path);
    }

    private function langPath(string $path): string
    {
        /** @var Application $app */
        $app = $this->app;

        return $app->langPath($path);
    }

    /**
     * @return array<int, string>
     */
    public function provides(): array
    {
        return [Guard::class, 'warden', ScannerRegistry::class, PolicyRepository::class];
    }
}
