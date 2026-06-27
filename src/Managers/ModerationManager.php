<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Managers;

use Illuminate\Support\Manager;
use Sellinnate\Warden\Contracts\ModerationDriver;
use Sellinnate\Warden\Drivers\Moderation\NullModerationDriver;

/**
 * Resolves the active content-moderation driver (null/deterministic by default).
 * OpenAI / Azure / Llama-Guard drivers are added in Phase 3.
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
}
