<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Exceptions;

/**
 * Thrown when an external driver (moderation/injection) fails or times out. The
 * Guard catches it and applies the per-scanner fail policy (open/closed).
 */
final class DriverException extends WardenException {}
