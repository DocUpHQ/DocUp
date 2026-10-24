<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

use App\Auth\Capability;
use App\Auth\OrganisationContext;
use App\Auth\RoleResolver;
use App\Models\Build;
use App\Models\User;
use Illuminate\Support\Facades\Broadcast;

/*
|------------------------------------------------------------------------------
| Broadcast channel authorisation — §8.5.22's optional WebSocket profile
|------------------------------------------------------------------------------
| 🛑 A private channel is an authorisation boundary, and this is it. §8.5.22
| says log access "MUST be authorised by the same policy as the project", and
| a socket that skipped the check would be a way to read a build log without
| passing the endpoint that enforces it.
|
| 🛑 The channel carries a CURSOR, never a line (see `BuildLogAppended`), so a
| listener who got past this would still have to fetch the page through the
| API and be authorised again. That is deliberate defence in depth, not a
| reason to be relaxed here: a build identifier is itself a fact about an
| installation, and §8.2.2 answers "404, never 403" for exactly that reason.
*/

Broadcast::channel('builds.{buildHex}', function (User $user, string $buildHex): bool {
    if (preg_match('/^[0-9a-f]{32}$/', $buildHex) !== 1) {
        return false;
    }

    $bytes = hex2bin($buildHex);

    if ($bytes === false) {
        return false;
    }

    /*
     * Resolved across organisations and then checked, rather than resolved
     * within the listener's tenant: a user may hold roles in several
     * organisations, and §8.2.1's global scope needs one declared. The
     * capability check below is what actually decides.
     */
    $build = app(OrganisationContext::class)->acrossAllOrganisations(
        static fn (): ?Build => Build::query()->whereKey($bytes)->with('projectVersion.project')->first(),
    );

    if (! $build instanceof Build) {
        return false;
    }

    /*
     * The project, so a project-scoped grant counts. Passing only the
     * organisation would refuse a project maintainer who holds nothing at
     * organisation scope - which is most of them.
     */
    return app(RoleResolver::class)->allows(
        $user,
        Capability::ProjectView,
        $build->projectVersion?->project,
        $build->organisation_id,
    );
});
