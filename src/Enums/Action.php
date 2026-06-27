<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Enums;

/**
 * What a scanner is allowed to do with its detections.
 *
 * The action is a *policy* decision, never hard-coded inside a detector
 * (Presidio principle: separate "finding" from "what to do about it").
 */
enum Action: string
{
    /** Only report: record detections, never mutate text nor block. */
    case Detect = 'detect';

    /** Transform the text (redact/mask/encrypt/defang) but let it through. */
    case Sanitize = 'sanitize';

    /** Interrupt the pipeline: the payload is rejected. */
    case Block = 'block';
}
