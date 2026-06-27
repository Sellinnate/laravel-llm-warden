<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Tests;

use Illuminate\Foundation\Application;
use Orchestra\Testbench\TestCase as Orchestra;
use Sellinnate\Warden\WardenServiceProvider;

abstract class TestCase extends Orchestra
{
    /**
     * @param  Application  $app
     * @return array<int, class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [
            WardenServiceProvider::class,
        ];
    }
}
