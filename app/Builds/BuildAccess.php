<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds;

use App\Auth\OrganisationContext;
use App\Http\Middleware\AuthenticateApiToken;
use App\Models\ApiToken;
use App\Models\Build;
use App\Models\Project;
use App\Support\Uuid;
use Illuminate\Http\Request;

/**
 * Who may read a build, and under which of §8.5.22's two policies.
 *
 * > "Log access MUST be authorised by the same policy as the project, and
 * > build-log visibility for anonymous readers of public projects MUST be
 * > a per-project setting defaulting to **off** (build logs leak paths,
 * > dependency versions and sometimes content)."
 *
 * 🛑 **Two callers, two policies, one answer: the build or null.** A
 * controller that had to ask "was there a token?" and then branch would
 * eventually branch differently in two places. Returning null for every
 * refusal also keeps §8.2.2's rule — "404, never 403" — a property of
 * the call site rather than something each controller remembers.
 *
 * 🛑 **Route-model binding is deliberately NOT used here.** Binding
 * resolves through §8.2.1's global scope, which throws when no tenant has
 * been declared — and the anonymous path has no tenant by definition. So
 * the identifier arrives as a string and the lookup is explicit, inside
 * the narrowest span that can see the row.
 */
final class BuildAccess
{
    /**
     * Resolve a build this request may read, or null.
     *
     * @param  string  $buildId  36-character canonical UUID or 32 hex characters
     */
    public static function resolve(Request $request, string $buildId): ?Build
    {
        $bytes = self::bytes($buildId);

        if ($bytes === null) {
            return null;
        }

        $token = $request->attributes->get(AuthenticateApiToken::ATTRIBUTE);

        if ($token instanceof ApiToken) {
            /*
             * The token declared its organisation in the middleware, so
             * the global scope is already doing the filtering: a build in
             * another tenant simply is not found. Nothing here compares
             * the two, which is §8.9.4's point — the comparison that does
             * not exist cannot be got wrong.
             */
            return Build::query()->whereKey($bytes)->first();
        }

        return self::anonymously($bytes);
    }

    /**
     * 🛑 The anonymous path: public project, setting on, and nothing else.
     *
     * Both conditions, and in that order. A project whose visibility is
     * anything but `public` is refused whatever the setting says — the
     * setting widens access to a project people can already read, it does
     * not grant access to one they cannot.
     */
    private static function anonymously(string $bytes): ?Build
    {
        /** @var Build|null $build */
        $build = app(OrganisationContext::class)->acrossAllOrganisations(
            static fn (): ?Build => Build::query()->whereKey($bytes)->with('projectVersion.project')->first(),
        );

        if (! $build instanceof Build) {
            return null;
        }

        $project = $build->projectVersion?->project;

        if (! $project instanceof Project) {
            return null;
        }

        if ($project->visibility->value !== 'public' || $project->anonymous_build_logs !== true) {
            return null;
        }

        return $build;
    }

    private static function bytes(string $buildId): ?string
    {
        if (preg_match('/^[0-9a-f]{32}$/i', $buildId) === 1) {
            $bytes = hex2bin(strtolower($buildId));

            return $bytes === false ? null : $bytes;
        }

        return Uuid::tryToBytes($buildId);
    }
}
