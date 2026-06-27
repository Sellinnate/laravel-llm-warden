<?php

declare(strict_types=1);

/*
 * High-signal prompt-injection / jailbreak signatures.
 *
 * Each entry: a detection `type`, a base `score` (0..1 confidence that a match
 * indicates an injection attempt), and the case-insensitive `patterns` matched
 * against the normalized (de-obfuscated) detection view. Italian + English.
 *
 * These are intentionally HIGH precision: they target imperative attack phrasing
 * that almost never occurs in benign prompts. Semantic / paraphrased novel
 * jailbreaks are out of deterministic scope (use an AI driver).
 */

return [
    [
        'type' => 'INSTRUCTION_OVERRIDE',
        'score' => 0.9,
        'patterns' => [
            // ignore/disregard/forget ... (previous|prior|above|all) ... instructions/rules/prompt
            '/\b(?:ignore|disregard|forget|override|bypass|skip)\b[^.\n]{0,40}\b(?:all|any|previous|prior|above|earlier|preceding|the\s+(?:above|previous))\b[^.\n]{0,40}\b(?:instruction|instructions|prompt|prompts|context|rule|rules|direction|directions|guideline|guidelines|message|messages)\b/iu',
            '/\b(?:ignora|ignorare|dimentica|dimenticare|scarta|annulla)\b[^.\n]{0,40}\b(?:tutte|tutti|le|i|precedenti|sopra|prima)\b[^.\n]{0,40}\b(?:istruzion\w+|prompt|regole|indicazion\w+|direttiv\w+|messagg\w+)\b/iu',
            '/\bignore\s+(?:everything|all)\b[^.\n]{0,20}\b(?:above|before|previously)\b/iu',
            // "forget/ignore/disregard everything before/above" with no explicit "instructions" noun
            '/\b(?:forget|ignore|disregard|erase)\b[^.\n]{0,15}\b(?:everything|all|what\s+(?:i|you|was))\b[^.\n]{0,25}\b(?:before|above|prior|previously|preceding|so\s+far|said\s+earlier|up\s+to\s+this\s+point)\b/iu',
            // verb → NOUN → qualifier ordering ("ignore the instructions you were given earlier")
            '/\b(?:ignore|disregard|forget|override|bypass)\b[^.\n]{0,15}\b(?:instruction|instructions|prompt|prompts|rule|rules|guideline|guidelines)\b[^.\n]{0,30}\b(?:earlier|before|above|previously|you\s+(?:were|have)\s+(?:given|been\s+given|received))\b/iu',
            // "from now on you have no restrictions/rules/limits"
            '/\bfrom\s+now\s+on\b[^.\n]{0,30}\b(?:no\s+(?:restrictions|rules|limits|guidelines|filters)|you\s+(?:are|will\s+be)\s+(?:unrestricted|unfiltered|free))\b/iu',
            '/\b(?:d\'?ora\s+in\s+poi|da\s+adesso)\b[^.\n]{0,30}\b(?:nessuna\s+(?:restrizione|regola|limitazione)|sei\s+(?:libero|senza\s+restrizioni))\b/iu',
        ],
    ],
    [
        'type' => 'REFUSAL_SUPPRESSION',
        'score' => 0.85,
        'patterns' => [
            '/\b(?:do\s*not|don\'?t|never|you\s+(?:must|will)\s+not)\b[^.\n]{0,30}\b(?:refuse|decline|warn|apologize|apologise|say\s+(?:you|that\s+you)\s+can\'?t|mention\s+(?:that\s+)?you\s+can\'?t)\b/iu',
            '/\bwithout\b[^.\n]{0,20}\b(?:any\s+)?(?:warning|warnings|disclaimer|disclaimers|caveat|caveats|refusal|moral\s+judgement)\b/iu',
            '/\b(?:non|mai)\b[^.\n]{0,20}\b(?:rifiutare|rifiutarti|avvisare|avvertire|scusarti)\b/iu',
        ],
    ],
    [
        'type' => 'PREFIX_INJECTION',
        'score' => 0.7,
        'patterns' => [
            '/\b(?:start|begin|prefix)\b[^.\n]{0,25}\b(?:your\s+)?(?:response|reply|answer|message)\b[^.\n]{0,15}\bwith\b/iu',
            '/\b(?:respond|reply|answer|begin)\b[^.\n]{0,15}\bwith\b[^.\n]{0,10}["\']?\s*(?:sure|certainly|of\s+course|absolutely|yes)\b/iu',
            '/\b(?:inizia|comincia)\b[^.\n]{0,25}\b(?:la\s+)?(?:risposta|tua\s+risposta)\b[^.\n]{0,15}\bcon\b/iu',
        ],
    ],
    [
        'type' => 'SYSTEM_PROMPT_EXFIL',
        'score' => 0.85,
        'patterns' => [
            '/\b(?:reveal|show|print|repeat|output|display|tell\s+me|reproduce|echo)\b[^.\n]{0,30}\b(?:your\s+)?(?:system\s+prompt|initial\s+(?:prompt|instructions)|original\s+instructions|your\s+(?:instructions|rules|guidelines|prompt))\b/iu',
            '/\brepeat\b[^.\n]{0,20}\b(?:the\s+words\s+above|everything\s+above|text\s+above)\b/iu',
            '/\b(?:mostra|rivela|stampa|ripeti|mostrami)\b[^.\n]{0,30}\b(?:il\s+)?(?:system\s+prompt|prompt\s+(?:di\s+sistema|iniziale)|le\s+tue\s+(?:istruzioni|regole))\b/iu',
        ],
    ],
    [
        'type' => 'PERSONA_JAILBREAK',
        'score' => 0.8,
        'patterns' => [
            '/\b(?:do\s+anything\s+now|developer\s+mode|jailbreak|jailbroken)\b/iu',
            '/\byou\s+are\s+(?:now\s+)?(?:DAN|AIM|STAN|DUDE|an?\s+unfiltered|an?\s+unrestricted)\b/iu',
            '/\bact\s+as\b[^.\n]{0,25}\b(?:unfiltered|unrestricted|amoral|without\s+(?:any\s+)?(?:restrictions|rules|filters|guidelines))\b/iu',
            '/\b(?:pretend|imagine|suppose)\b[^.\n]{0,25}\b(?:you\s+have\s+no\s+(?:rules|restrictions|guidelines)|there\s+are\s+no\s+rules)\b/iu',
            '/\bmodalit[àa]\s+sviluppatore\b/iu',
        ],
    ],
    [
        'type' => 'ENCODED_INSTRUCTION',
        'score' => 0.75,
        'patterns' => [
            '/\b(?:decode|base64|rot13|hex\s*decode|from\s+base64)\b[^.\n]{0,30}\b(?:and|then|e\s+poi)\b[^.\n]{0,20}\b(?:follow|execute|do|run|obey|esegui|segui)\b/iu',
            '/\b(?:decodifica|decifra)\b[^.\n]{0,30}\b(?:ed?\s+esegui|e\s+segui)\b/iu',
        ],
    ],
];
