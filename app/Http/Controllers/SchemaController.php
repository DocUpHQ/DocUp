<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Config\ConfigParser;
use App\Serving\CachePolicy;
use Illuminate\Http\Response;

/**
 * §8.1.11's first published contract, served.
 *
 * > "The system MUST declare three independently versioned public contracts
 * > — the `.docup.yaml` schema, the `/_/addons` JSON payload, and REST API
 * > v3 — each with its own version field and a two-minor deprecation policy."
 *
 * 🛑 **"Published" is literal, and this is what makes it so.** An editor's
 * YAML language server reads a schema from a URL; an author writing
 * `.docup.yaml` gets completion and in-place errors from the same bytes the
 * build will validate against. A schema that only existed inside the
 * application would be a contract nobody outside it could hold us to.
 *
 * 🛑 **Unauthenticated, and that is correct.** The schema describes the
 * shape of a configuration file and contains nothing about any installation:
 * no hostnames, no tenants, no limits an operator configured. Requiring a
 * session would mean an author's editor could not fetch it, which is the one
 * use this endpoint has.
 */
final class SchemaController extends Controller
{
    public function show(): Response
    {
        $schema = (string) file_get_contents(ConfigParser::schemaPath());

        /*
         * 🛑 The directives come from `CachePolicy`, not from a literal here.
         * §9.3.2 makes one place responsible for deciding public
         * cacheability, and `ArchitectureTest` enforces it — this response is
         * obviously safe to cache publicly, which is exactly the kind of
         * obviously-safe exception that, repeated four times, ends with a
         * private document carrying `public, max-age`.
         */
        return response($schema, 200, [
            'Content-Type' => 'application/schema+json',
            'X-Content-Type-Options' => 'nosniff',
            ...CachePolicy::forPublishedContract()->headers(),
        ]);
    }
}
