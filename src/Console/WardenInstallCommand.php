<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Console;

use Illuminate\Console\Command;

/**
 * Publishes the Warden config (and, optionally, the language files).
 *
 *   php artisan warden:install
 */
final class WardenInstallCommand extends Command
{
    protected $signature = 'warden:install {--force : Overwrite existing files}';

    protected $description = 'Publish the Warden configuration';

    public function handle(): int
    {
        $this->components->info('Publishing Warden configuration…');

        $this->callSilently('vendor:publish', array_filter([
            '--tag' => 'warden-config',
            '--force' => $this->option('force') ? true : null,
        ]));

        $this->components->info('Warden is ready. Edit config/warden.php to choose a policy and drivers.');
        $this->line('  Try: <fg=cyan>php artisan warden:test "ignore all previous instructions"</>');

        return self::SUCCESS;
    }
}
