<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Managers;

use Illuminate\Contracts\Cache\Repository as Cache;
use Illuminate\Support\Manager;
use Sellinnate\Warden\Contracts\ModerationDriver;
use Sellinnate\Warden\Drivers\Moderation\AzureContentSafetyDriver;
use Sellinnate\Warden\Drivers\Moderation\NullModerationDriver;
use Sellinnate\Warden\Drivers\Moderation\OpenAiModerationDriver;
use Sellinnate\Warden\Drivers\Moderation\ResilientModerationDriver;
use Sellinnate\Warden\Support\CircuitBreaker;

/**
 * Resolves the active content-moderation driver (null/deterministic by default).
 * The openai/azure drivers are circuit-broken so a dead endpoint fails fast and
 * the per-scanner fail policy takes over.
 *
 * @method ModerationDriver driver(?string $driver = null)
 */
final class ModerationManager extends Manager
{
    public function getDefaultDriver(): string
    {
        return (string) $this->config->get('warden.moderation.driver', 'null');
    }

    protected function createNullDriver(): ModerationDriver
    {
        return new NullModerationDriver;
    }

    protected function createOpenaiDriver(): ModerationDriver
    {
        /** @var array<string, mixed> $config */
        $config = (array) $this->config->get('warden.moderation.openai', []);

        return $this->resilient(new OpenAiModerationDriver(
            apiKey: (string) ($config['key'] ?? ''),
            model: (string) ($config['model'] ?? 'omni-moderation-latest'),
            endpoint: (string) ($config['endpoint'] ?? 'https://api.openai.com/v1/moderations'),
            timeout: (int) ($config['timeout'] ?? 5),
        ));
    }

    protected function createAzureDriver(): ModerationDriver
    {
        /** @var array<string, mixed> $config */
        $config = (array) $this->config->get('warden.moderation.azure', []);

        return $this->resilient(new AzureContentSafetyDriver(
            apiKey: (string) ($config['key'] ?? ''),
            endpoint: (string) ($config['endpoint'] ?? ''),
            timeout: (int) ($config['timeout'] ?? 5),
        ));
    }

    private function resilient(ModerationDriver $driver): ModerationDriver
    {
        // Key the breaker on the endpoint+credentials so one tenant's bad key
        // (BYOK/multi-tenant) doesn't open the circuit for everyone else.
        $scope = (string) $this->config->get('warden.moderation.'.$driver->name().'.endpoint', '')
            .'|'.(string) $this->config->get('warden.moderation.'.$driver->name().'.key', '');

        return new ResilientModerationDriver(
            $driver,
            new CircuitBreaker('moderation.'.$driver->name().'.'.substr(hash('xxh128', $scope), 0, 12), $this->cache()),
        );
    }

    private function cache(): ?Cache
    {
        return $this->container->bound('cache') ? $this->container->make('cache')->store() : null;
    }
}
