<?php

declare(strict_types=1);

/*
 * Deterministic content-safety signatures mapped to Warden's internal taxonomy
 * (Llama Guard / MLCommons S1–S13). This list is intentionally small, tasteful
 * and intent-based (not a slur dictionary): the deterministic layer is a fast
 * first filter and is acknowledged as fragile — use a moderation driver
 * (openai/azure/llama-guard) for real semantic coverage.
 *
 * Each entry: `category` (S-code), `label`, `score`, and `patterns` (matched
 * case-insensitively against the normalized detection view; IT + EN).
 */

return [
    [
        'category' => 'S1',
        'label' => 'Violent Crimes',
        'score' => 0.8,
        'patterns' => [
            '/\bhow\s+(?:to|do\s+i|can\s+i)\b[^.\n]{0,20}\b(?:kill|murder|stab|strangle|assault|attack)\b[^.\n]{0,20}\b(?:someone|a\s+person|people|him|her|them)\b/iu',
            '/\bcome\s+(?:posso\s+)?(?:uccidere|ammazzare|accoltellare|aggredire)\b[^.\n]{0,20}\b(?:qualcuno|una\s+persona|lo|la)\b/iu',
        ],
    ],
    [
        'category' => 'S9',
        'label' => 'Indiscriminate Weapons',
        'score' => 0.9,
        'patterns' => [
            '/\b(?:how\s+to|build|make|create|synthesize|manufacture)\b[^.\n]{0,25}\b(?:bomb|explosive|ied|nerve\s+agent|chemical\s+weapon|bioweapon|sarin|ricin)\b/iu',
            '/\b(?:come\s+(?:costruire|fabbricare|fare))\b[^.\n]{0,25}\b(?:una\s+bomba|un\s+esplosivo|un\s+ordigno|arma\s+chimica)\b/iu',
        ],
    ],
    [
        'category' => 'S11',
        'label' => 'Suicide & Self-Harm',
        'score' => 0.85,
        'patterns' => [
            '/\bhow\s+(?:to|do\s+i|can\s+i)\b[^.\n]{0,20}\b(?:commit\s+suicide|kill\s+myself|end\s+my\s+life|hurt\s+myself|self[\s\-]?harm)\b/iu',
            '/\bcome\s+(?:posso\s+)?(?:suicidarmi|uccidermi|farla\s+finita|farmi\s+del\s+male)\b/iu',
        ],
    ],
    [
        'category' => 'S4',
        'label' => 'Child Sexual Exploitation',
        'score' => 0.98,
        'patterns' => [
            '/\b(?:child|minor|underage|preteen)\b[^.\n]{0,15}\b(?:porn|sexual|nude|nudes|explicit)\b/iu',
            '/\b(?:porno|materiale\s+sessuale)\b[^.\n]{0,15}\b(?:minor\w+|bambin\w+)\b/iu',
        ],
    ],
    [
        'category' => 'S2',
        'label' => 'Non-Violent Crimes',
        'score' => 0.7,
        'patterns' => [
            '/\bhow\s+(?:to|do\s+i)\b[^.\n]{0,20}\b(?:hack\s+into|steal\s+(?:a\s+)?(?:car|identity|credit\s+card)|launder\s+money|make\s+meth|counterfeit)\b/iu',
            '/\bcome\s+(?:posso\s+)?(?:rubare|riciclare\s+denaro|clonare\s+una\s+carta)\b/iu',
        ],
    ],
];
