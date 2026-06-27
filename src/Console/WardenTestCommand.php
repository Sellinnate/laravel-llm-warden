<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Console;

use Illuminate\Console\Command;
use Sellinnate\Warden\Enums\Direction;
use Sellinnate\Warden\Guard;
use Sellinnate\Warden\Policies\PolicyRepository;
use Sellinnate\Warden\ValueObjects\Detection;
use Symfony\Component\Console\Formatter\OutputFormatter;

/**
 * CLI helper to inspect a string against Warden, for quick debugging.
 *
 *   php artisan warden:test "ignore all previous instructions" --policy=strict
 */
final class WardenTestCommand extends Command
{
    protected $signature = 'warden:test {text : The text to inspect}
        {--policy= : Policy profile to use (default from config)}
        {--direction=input : input|output|retrieval}';

    protected $description = 'Inspect a string against Warden and print the verdict';

    public function handle(Guard $guard): int
    {
        /** @var string $text */
        $text = $this->argument('text');
        /** @var string|null $policy */
        $policy = $this->option('policy');
        $direction = Direction::tryFrom((string) $this->option('direction')) ?? Direction::Input;

        $verdict = $guard->run($direction, $text, app(PolicyRepository::class)->get($policy));

        $this->newLine();
        $this->line('  <fg=gray>Direction:</> '.$direction->value);
        $this->line('  <fg=gray>Policy:</>    '.($policy ?? 'default'));
        $this->line('  <fg=gray>Severity:</>  '.$verdict->severity->name.' ('.number_format($verdict->riskScore, 2).')');
        $this->line('  <fg=gray>Verdict:</>   '.($verdict->blocked()
            ? '<fg=red;options=bold>BLOCKED</>'
            : '<fg=green;options=bold>ALLOWED</>'));
        $this->newLine();

        if ($verdict->detections() !== []) {
            $this->table(
                ['Type', 'Scanner', 'Score'],
                array_map(
                    static fn (Detection $d): array => [$d->type, $d->scanner, number_format($d->score, 2)],
                    $verdict->detections(),
                ),
            );
        }

        if ($verdict->sanitizedText !== $text) {
            // Strip control bytes and escape formatter tags so untrusted text
            // can't manipulate the operator's terminal.
            $safe = OutputFormatter::escape(
                (string) preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $verdict->sanitizedText),
            );
            $this->line('  <fg=gray>Sanitized:</> '.$safe);
            $this->newLine();
        }

        return $verdict->blocked() ? self::FAILURE : self::SUCCESS;
    }
}
