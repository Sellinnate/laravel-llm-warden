<?php

declare(strict_types=1);

namespace Sellinnate\Warden\Enums;

/**
 * The boundary a scan operates on.
 *
 * - Input:     untrusted user text on its way to the LLM.
 * - Output:    the LLM's response on its way back to the application/user.
 * - Retrieval: untrusted content ingested into the prompt (RAG chunks, tool output,
 *   web pages, emails) — treated as input for indirect-injection purposes.
 */
enum Direction: string
{
    case Input = 'input';
    case Output = 'output';
    case Retrieval = 'retrieval';
}
