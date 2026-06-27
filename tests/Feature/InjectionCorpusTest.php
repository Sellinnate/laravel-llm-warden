<?php

declare(strict_types=1);

use Sellinnate\Warden\Enums\Direction;
use Sellinnate\Warden\Facades\Warden;

/**
 * Precision / recall gates on the versioned corpus. These thresholds are CI
 * gates: a change that drops recall or raises the false-positive rate fails.
 */
$attacks = require __DIR__.'/../Corpus/injection_attacks.php';
$benign = require __DIR__.'/../Corpus/injection_benign.php';

it('detects every attack in the corpus under the strict policy', function (string $attack) {
    $verdict = Warden::for(Direction::Input)
        ->usingPolicy('strict')
        ->scan($attack);

    expect($verdict->hasDetectionType('PROMPT_INJECTION'))->toBeTrue()
        ->and($verdict->blocked())->toBeTrue();
})->with($attacks);

it('does not flag benign prompts as injection', function (string $benign) {
    $verdict = Warden::for(Direction::Input)
        ->usingPolicy('strict')
        ->only(['normalize', 'injection'])
        ->scan($benign);

    expect($verdict->blocked())->toBeFalse("benign prompt was blocked: {$benign}");
})->with($benign);

it('measures corpus recall and precision above CI thresholds', function () use ($attacks, $benign) {
    $detected = 0;
    foreach ($attacks as $attack) {
        if (Warden::inspect($attack, 'strict')->hasDetectionType('PROMPT_INJECTION')) {
            $detected++;
        }
    }
    $recall = $detected / count($attacks);

    $falsePositives = 0;
    foreach ($benign as $text) {
        $v = Warden::for(Direction::Input)
            ->usingPolicy('strict')->only(['normalize', 'injection'])->scan($text);
        if ($v->blocked()) {
            $falsePositives++;
        }
    }
    $fpr = $falsePositives / count($benign);

    expect($recall)->toBeGreaterThanOrEqual(0.95)
        ->and($fpr)->toBeLessThanOrEqual(0.05);
});
