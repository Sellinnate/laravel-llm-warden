<?php

declare(strict_types=1);

namespace Sellinnate\Warden;

use Illuminate\Cache\CacheManager;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Foundation\Console\AboutCommand;
use Illuminate\Http\Request;
use Illuminate\Log\LogManager;
use Illuminate\Routing\Router;
use Illuminate\Support\ServiceProvider;
use Sellinnate\Warden\Audit\LogAuditor;
use Sellinnate\Warden\Console\WardenInstallCommand;
use Sellinnate\Warden\Console\WardenTestCommand;
use Sellinnate\Warden\Contracts\Auditor;
use Sellinnate\Warden\Detectors\Pii\DefaultDetectors;
use Sellinnate\Warden\Detectors\Pii\PiiAnalyzer;
use Sellinnate\Warden\Detectors\Pii\PiiAnonymizer;
use Sellinnate\Warden\Enums\FailMode;
use Sellinnate\Warden\Http\Middleware\WardenMiddleware;
use Sellinnate\Warden\Managers\InjectionManager;
use Sellinnate\Warden\Managers\ModerationManager;
use Sellinnate\Warden\Policies\PolicyRepository;
use Sellinnate\Warden\Scanners\DeanonymizeScanner;
use Sellinnate\Warden\Scanners\FormatScanner;
use Sellinnate\Warden\Scanners\InjectionScanner;
use Sellinnate\Warden\Scanners\MarkdownDefangScanner;
use Sellinnate\Warden\Scanners\NormalizeScanner;
use Sellinnate\Warden\Scanners\NsfwScanner;
use Sellinnate\Warden\Scanners\OutputLeakScanner;
use Sellinnate\Warden\Scanners\PiiScanner;
use Sellinnate\Warden\Scanners\SecretScanner;
use Sellinnate\Warden\Support\ScannerRegistry;
use Sellinnate\Warden\Support\VerdictCache;
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
        'deanonymize' => DeanonymizeScanner::class,
        'output-leak' => OutputLeakScanner::class,
        'markdown-defang' => MarkdownDefangScanner::class,
        'format' => FormatScanner::class,
    ];

    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/warden.php', 'warden');

        self::registerBindings($this->app);
    }

    /**
     * Register all Warden service bindings on a container. Reused by Guard::make().
     */
    public static function registerBindings(Container $app): void
    {
        $app->singleton(PolicyRepository::class, function (Container $app): PolicyRepository {
            /** @var Repository $config */
            $config = $app->make('config');

            /** @var array<string, mixed> $failModeConfig */
            $failModeConfig = (array) $config->get('warden.fail_mode', []);
            $overrides = [];
            foreach ($failModeConfig as $scanner => $mode) {
                $overrides[$scanner] = FailMode::fromString(is_string($mode) ? $mode : null);
            }

            return new PolicyRepository(
                (string) $config->get('warden.default_policy', 'balanced'),
                $overrides,
            );
        });

        $app->singleton(ScannerRegistry::class, function (Container $app): ScannerRegistry {
            $registry = new ScannerRegistry($app);

            foreach (self::SCANNERS as $name => $class) {
                if (class_exists($class)) {
                    $registry->register($name, $class);
                }
            }

            return $registry;
        });

        $app->singleton(
            InjectionManager::class,
            static fn (Container $app): InjectionManager => new InjectionManager($app),
        );

        $app->singleton(
            ModerationManager::class,
            static fn (Container $app): ModerationManager => new ModerationManager($app),
        );

        $app->singleton(NsfwScanner::class, function (Container $app): NsfwScanner {
            /** @var array<int, array{category: string, label: string, score: float, patterns: array<int, string>}> $signatures */
            $signatures = require __DIR__.'/../resources/denylists/nsfw.php';

            return new NsfwScanner(
                $signatures,
                $app->make(ModerationManager::class),
            );
        });

        $app->singleton(NormalizeScanner::class, function (Container $app): NormalizeScanner {
            /** @var Repository $config */
            $config = $app->make('config');

            /** @var array<string, mixed> $normalizeConfig */
            $normalizeConfig = (array) $config->get('warden.normalize', []);

            return new NormalizeScanner($normalizeConfig);
        });

        $app->singleton(SecretScanner::class, function (Container $app): SecretScanner {
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

        $app->singleton(PiiScanner::class, function (Container $app): PiiScanner {
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

        $app->singleton(OutputLeakScanner::class, function (Container $app): OutputLeakScanner {
            /** @var Repository $config */
            $config = $app->make('config');

            $canary = $config->get('warden.output.canary');
            $systemPrompt = $config->get('warden.output.system_prompt');

            return new OutputLeakScanner(
                is_string($canary) ? $canary : null,
                is_string($systemPrompt) ? $systemPrompt : null,
            );
        });

        $app->singleton(MarkdownDefangScanner::class, function (Container $app): MarkdownDefangScanner {
            /** @var Repository $config */
            $config = $app->make('config');

            /** @var array<int, string> $allowed */
            $allowed = (array) $config->get('warden.output.allowed_domains', []);

            return new MarkdownDefangScanner($allowed);
        });

        $app->singleton(FormatScanner::class, function (Container $app): FormatScanner {
            /** @var Repository $config */
            $config = $app->make('config');

            return new FormatScanner(
                (bool) $config->get('warden.output.require_json', false),
            );
        });

        $app->singleton(Guard::class, function (Container $app): Guard {
            /** @var Repository $config */
            $config = $app->make('config');

            return new Guard(
                $app->make(ScannerRegistry::class),
                $app->make(PolicyRepository::class),
                $app->bound(Dispatcher::class) ? $app->make(Dispatcher::class) : null,
                (int) $config->get('warden.max_input_bytes', 50_000),
                self::makeAuditor($app, $config),
                self::makeVerdictCache($app, $config),
            );
        });

        $app->alias(Guard::class, 'warden');
    }

    private static function makeAuditor(Container $app, Repository $config): ?Auditor
    {
        if (! (bool) $config->get('warden.audit.enabled', true) || $config->get('warden.audit.store') === 'null') {
            return null;
        }

        if ($app->bound(Auditor::class)) {
            return $app->make(Auditor::class);
        }

        if (! $app->bound('log')) {
            return null;
        }

        $channel = $config->get('warden.audit.channel');
        /** @var LogManager $logManager */
        $logManager = $app->make('log');
        $logger = is_string($channel) ? $logManager->channel($channel) : $logManager->getLogger();

        return new LogAuditor($logger, (bool) $config->get('warden.audit.store_raw', false));
    }

    private static function makeVerdictCache(Container $app, Repository $config): ?VerdictCache
    {
        if (! (bool) $config->get('warden.cache.enabled', false) || ! $app->bound('cache')) {
            return null;
        }

        $store = $config->get('warden.cache.store');
        /** @var CacheManager $cacheManager */
        $cacheManager = $app->make('cache');

        return new VerdictCache(
            $cacheManager->store(is_string($store) ? $store : null),
            (int) $config->get('warden.cache.ttl', 3600),
            (string) $config->get('warden.cache.prefix', 'warden'),
        );
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

            $this->commands([
                WardenInstallCommand::class,
                WardenTestCommand::class,
            ]);

            $this->registerAboutCommand();
        }

        $this->loadTranslationsFrom(__DIR__.'/../resources/lang', 'warden');

        $this->registerMiddleware();
        $this->registerRequestMacro();
    }

    private function registerAboutCommand(): void
    {
        if (! class_exists(AboutCommand::class)) {
            return;
        }

        /** @var Repository $config */
        $config = $this->app->make('config');

        AboutCommand::add('Warden', fn (): array => [
            'Default Policy' => (string) $config->get('warden.default_policy', 'balanced'),
            'Injection Driver' => (string) $config->get('warden.injection.driver', 'deterministic'),
            'Moderation Driver' => (string) $config->get('warden.moderation.driver', 'null'),
            'Audit' => $config->get('warden.audit.enabled') ? 'enabled' : 'disabled',
            'Verdict Cache' => $config->get('warden.cache.enabled') ? 'enabled' : 'disabled',
        ]);
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
