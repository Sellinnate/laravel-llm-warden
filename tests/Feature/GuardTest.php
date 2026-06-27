<?php

declare(strict_types=1);

use Sellinnate\Warden\Enums\Direction;
use Sellinnate\Warden\Exceptions\WardenException;
use Sellinnate\Warden\Facades\Warden;
use Sellinnate\Warden\Guard;
use Sellinnate\Warden\Policies\PolicyBuilder;
use Sellinnate\Warden\Policies\PolicyRepository;

it('resolves the Guard from the container', function () {
    expect(app(Guard::class))->toBeInstanceOf(Guard::class);
    expect(app('warden'))->toBeInstanceOf(Guard::class);
});

it('inspects clean input and returns a valid verdict', function () {
    $verdict = Warden::inspect('Please summarise this article for me.');

    expect($verdict->valid)->toBeTrue()
        ->and($verdict->blocked())->toBeFalse()
        ->and($verdict->severity->name)->toBe('Safe');
});

it('runs normalization on input and strips invisibles', function () {
    $verdict = Warden::sanitize("hel\u{200B}lo");
    expect($verdict->sanitizedText)->toBe('hello');
});

it('resolves built-in policy profiles', function () {
    $repo = app(PolicyRepository::class);

    expect($repo->get('strict')->name)->toBe('strict')
        ->and($repo->get('balanced')->name)->toBe('balanced')
        ->and($repo->get('permissive')->name)->toBe('permissive')
        ->and($repo->get()->name)->toBe('balanced'); // default
});

it('throws on unknown policy', function () {
    app(PolicyRepository::class)->get('does-not-exist');
})->throws(WardenException::class);

it('lets applications define custom policies', function () {
    Warden::definePolicy('mypolicy', fn (PolicyBuilder $p) => $p
        ->inputScanners(['normalize'])
        ->threshold('injection', 0.9)
    );

    $policy = app(PolicyRepository::class)->get('mypolicy');
    expect($policy->inputScanners)->toBe(['normalize'])
        ->and($policy->threshold('injection'))->toBe(0.9);
});

it('exposes the fluent Level-2 API', function () {
    $verdict = Warden::for(Direction::Input)
        ->usingPolicy('balanced')
        ->only(['normalize'])
        ->scan("te\u{200B}st");

    expect($verdict->sanitizedText)->toBe('test');
});

it('skips scanners that are not registered yet', function () {
    // In Phase 0 only `normalize` is registered; balanced references more.
    $verdict = Warden::inspect('hello');
    expect($verdict->results)->toHaveKey('normalize');
});
