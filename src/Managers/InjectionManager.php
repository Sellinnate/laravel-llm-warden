<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Managers;

use Illuminate\Contracts\Cache\Repository as Cache;
use Illuminate\Support\Manager;
use Sellinnate\Warden\Contracts\InjectionDriver;
use Sellinnate\Warden\Drivers\Injection\DeterministicInjectionDriver;
use Sellinnate\Warden\Drivers\Injection\LayeredInjectionDriver;
use Sellinnate\Warden\Drivers\Injection\LlmJudgeInjectionDriver;
use Sellinnate\Warden\Support\CircuitBreaker;

/**
 * Resolves the active injection driver (deterministic by default). The AI judge
 * driver is layered on top of the deterministic filter (cheap-first escalation)
 * and circuit-broken. Third-party drivers register via Warden::extendInjection().
 *
 * @method InjectionDriver driver(?string $driver = null)
 */
final class InjectionManager extends Manager
{
    public function getDefaultDriver(): string
    {
        return (string) $this->config->get('warden.injection.driver', 'deterministic');
    }

    protected function createDeterministicDriver(): InjectionDriver
    {
        return new DeterministicInjectionDriver($this->loadSignatures());
    }

    protected function createLlmJudgeDriver(): InjectionDriver
    {
        /** @var array<string, mixed> $config */
        $config = (array) $this->config->get('warden.injection.prism', []);

        $judge = new LlmJudgeInjectionDriver(
            apiKey: (string) ($config['key'] ?? $this->config->get('warden.moderation.openai.key', '')),
            model: (string) ($config['model'] ?? 'gpt-4o-mini'),
            endpoint: (string) ($config['endpoint'] ?? 'https://api.openai.com/v1/chat/completions'),
            timeout: (int) ($config['timeout'] ?? 8),
        );

        $scope = (string) ($config['endpoint'] ?? '').'|'.(string) ($config['key'] ?? '');

        return new LayeredInjectionDriver(
            primary: $this->createDeterministicDriver(),
            secondary: $judge,
            escalateBelow: (float) $this->config->get('warden.injection.escalate_below', 0.5),
            breaker: new CircuitBreaker('injection.llm-judge.'.substr(hash('xxh128', $scope), 0, 12), $this->cache()),
        );
    }

    private function cache(): ?Cache
    {
        return $this->container->bound('cache') ? $this->container->make('cache')->store() : null;
    }

    /**
     * @return array<int, array{type: string, score: float, patterns: array<int, string>}>
     */
    private function loadSignatures(): array
    {
        /** @var array<int, array{type: string, score: float, patterns: array<int, string>}> $builtin */
        $builtin = require __DIR__.'/../../resources/denylists/injection.php';

        /** @var array<int, array{type: string, score: float, patterns: array<int, string>}> $custom */
        $custom = (array) $this->config->get('warden.injection.deterministic.signatures', []);

        return array_merge($builtin, $custom);
    }
}
