<?php

declare(strict_types=1);

namespace Sellinnate\Warden;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Routing\Router;
use Illuminate\Support\ServiceProvider;
use Sellinnate\Warden\Detectors\Pii\DefaultDetectors;
use Sellinnate\Warden\Detectors\Pii\PiiAnalyzer;
use Sellinnate\Warden\Detectors\Pii\PiiAnonymizer;
use Sellinnate\Warden\Http\Middleware\WardenMiddleware;
use Sellinnate\Warden\Managers\InjectionManager;
use Sellinnate\Warden\Managers\ModerationManager;
use Sellinnate\Warden\Policies\PolicyRepository;
use Sellinnate\Warden\Scanners\InjectionScanner;
use Sellinnate\Warden\Scanners\NormalizeScanner;
use Sellinnate\Warden\Scanners\NsfwScanner;
use Sellinnate\Warden\Scanners\PiiScanner;
use Sellinnate\Warden\Scanners\SecretScanner;
use Sellinnate\Warden\Support\ScannerRegistry;
use Sellinnate\Warden\ValueObjects\Verdict;

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
        'injection' => InjectionScanner::class,
        'secret' => SecretScanner::class,
        'pii' => PiiScanner::class,
        'nsfw' => NsfwScanner::class,
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

        $this->app->singleton(
            InjectionManager::class,
            static fn (Container $app): InjectionManager => new InjectionManager($app),
        );

        $this->app->singleton(
            ModerationManager::class,
            static fn (Container $app): ModerationManager => new ModerationManager($app),
        );

        $this->app->singleton(NsfwScanner::class, function (Container $app): NsfwScanner {
            /** @var array<int, array{category: string, label: string, score: float, patterns: array<int, string>}> $signatures */
            $signatures = require __DIR__.'/../resources/denylists/nsfw.php';

            return new NsfwScanner(
                $signatures,
                $app->make(ModerationManager::class),
            );
        });

        $this->app->singleton(NormalizeScanner::class, function (Container $app): NormalizeScanner {
            /** @var Repository $config */
            $config = $app->make('config');

            /** @var array<string, mixed> $normalizeConfig */
            $normalizeConfig = (array) $config->get('warden.normalize', []);

            return new NormalizeScanner($normalizeConfig);
        });

        $this->app->singleton(SecretScanner::class, function (Container $app): SecretScanner {
            /** @var Repository $config */
            $config = $app->make('config');

            /** @var array<int, array{type: string, score: float, pattern: string, group?: int, entropy?: bool}> $patterns */
            $patterns = require __DIR__.'/../resources/denylists/secrets.php';

            /** @var array<int, array{type: string, score: float, pattern: string, group?: int, entropy?: bool}> $custom */
            $custom = (array) $config->get('warden.secret.patterns', []);

            return new SecretScanner(
                array_merge($patterns, $custom),
                (float) $config->get('warden.secret.entropy_threshold', 3.5),
            );
        });

        $this->app->singleton(PiiScanner::class, function (Container $app): PiiScanner {
            /** @var Repository $config */
            $config = $app->make('config');

            $locale = (string) $config->get('warden.pii.locale', 'it');

            /** @var array<string, array<string, mixed>> $operators */
            $operators = (array) $config->get('warden.pii.operators', []);

            return new PiiScanner(
                new PiiAnalyzer(
                    DefaultDetectors::for($locale),
                ),
                new PiiAnonymizer(
                    (string) $config->get('warden.pii.hash_salt', ''),
                ),
                $operators,
            );
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

        $this->registerMiddleware();
        $this->registerRequestMacro();
    }

    private function registerMiddleware(): void
    {
        if ($this->app->bound('router')) {
            /** @var Router $router */
            $router = $this->app->make('router');
            $router->aliasMiddleware('warden', WardenMiddleware::class);
        }
    }

    private function registerRequestMacro(): void
    {
        Request::macro('wardenVerdict', function (?string $field = null) {
            /** @var Request $this */
            /** @var array<string, Verdict> $verdicts */
            $verdicts = $this->attributes->get('warden', []);

            if ($field !== null) {
                return $verdicts[$field] ?? null;
            }

            return $verdicts;
        });
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
