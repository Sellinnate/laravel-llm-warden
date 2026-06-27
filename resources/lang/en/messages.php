<?php

declare(strict_types=1);

return [
    'injection' => 'The :attribute appears to contain a prompt-injection or jailbreak attempt.',
    'pii' => 'The :attribute contains personal data that is not allowed here.',
    'secret' => 'The :attribute contains a credential or secret that must not be submitted.',
    'unsafe' => 'The :attribute contains content that is not allowed.',
    'blocked' => 'The :attribute was blocked by a content guardrail.',
];
