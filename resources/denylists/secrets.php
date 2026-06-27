<?php

declare(strict_types=1);

/*
 * High-signal secret / credential patterns. Most have a fixed prefix + charset,
 * giving very low false-positive rates. The generic catch-all is gated on
 * Shannon entropy (see SecretScanner) to suppress noise.
 *
 * Each entry: detection `type`, `score`, a `pattern`, an optional `group`
 * (1-based capture group that holds the actual secret value, defaults to whole
 * match) and an optional `entropy` flag (only flag if the group's entropy clears
 * the configured threshold).
 *
 * NOTE: vendors rotate token formats; validate against the live gitleaks ruleset
 * before relying on exact lengths in production.
 */

return [
    ['type' => 'SECRET_PEM_PRIVATE_KEY', 'score' => 0.98, 'pattern' => '/-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/'],
    ['type' => 'SECRET_AWS_ACCESS_KEY', 'score' => 0.97, 'pattern' => '/\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b/'],
    ['type' => 'SECRET_GITHUB_PAT', 'score' => 0.97, 'pattern' => '/\bgithub_pat_[0-9A-Za-z_]{82}\b/'],
    ['type' => 'SECRET_GITHUB_TOKEN', 'score' => 0.96, 'pattern' => '/\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36,}\b/'],
    ['type' => 'SECRET_ANTHROPIC_KEY', 'score' => 0.97, 'pattern' => '/\bsk-ant-[0-9A-Za-z_-]{20,}\b/'],
    ['type' => 'SECRET_OPENAI_KEY', 'score' => 0.96, 'pattern' => '/\bsk-(?!ant-)(?:proj-)?[0-9A-Za-z_-]{20,}\b/'],
    ['type' => 'SECRET_GOOGLE_API_KEY', 'score' => 0.95, 'pattern' => '/\bAIza[0-9A-Za-z_-]{35}\b/'],
    ['type' => 'SECRET_SLACK_TOKEN', 'score' => 0.95, 'pattern' => '/\bxox[baprs]-[0-9A-Za-z-]{10,}\b/'],
    ['type' => 'SECRET_STRIPE_KEY', 'score' => 0.96, 'pattern' => '/\b(?:sk|rk)_live_[0-9A-Za-z]{24,}\b/'],
    ['type' => 'SECRET_SENDGRID_KEY', 'score' => 0.95, 'pattern' => '/\bSG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}\b/'],
    ['type' => 'SECRET_GITLAB_PAT', 'score' => 0.95, 'pattern' => '/\bglpat-[0-9A-Za-z_-]{20}\b/'],
    ['type' => 'SECRET_TWILIO_KEY', 'score' => 0.9, 'pattern' => '/\bSK[0-9a-fA-F]{32}\b/'],
    ['type' => 'SECRET_NPM_TOKEN', 'score' => 0.93, 'pattern' => '/\bnpm_[0-9A-Za-z]{36}\b/'],
    ['type' => 'SECRET_JWT', 'score' => 0.7, 'pattern' => '/\beyJ[0-9A-Za-z_-]{8,}\.eyJ[0-9A-Za-z_-]{8,}\.[0-9A-Za-z_-]{8,}\b/'],

    // Generic catch-all — only flagged when the captured value clears the entropy gate.
    [
        'type' => 'SECRET_GENERIC',
        'score' => 0.6,
        'group' => 1,
        'entropy' => true,
        'pattern' => '/\b(?:api[_-]?key|secret|secret[_-]?key|access[_-]?token|auth[_-]?token|token|password|passwd|pwd|client[_-]?secret)\b["\']?\s*[:=]\s*["\']?([0-9A-Za-z_\-\/+.]{12,})["\']?/i',
    ],
];
