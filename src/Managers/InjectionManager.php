<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Managers;

use Illuminate\Support\Manager;
use Sellinnate\Warden\Contracts\InjectionDriver;
use Sellinnate\Warden\Drivers\Injection\DeterministicInjectionDriver;

/**
 * Resolves the active injection driver (deterministic by default). External
 * drivers (prompt-guard, prism-judge, lakera) are added in Phase 3; third-party
 * drivers register at runtime via Warden::extendInjection().
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
