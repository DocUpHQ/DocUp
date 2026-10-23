<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Controllers\Serving;

use App\Artifacts\ArtifactStore;
use App\Models\Build;
use App\Models\ProjectVersion;
use App\Support\Uuid;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\DB;

/**
 * `GET /_/provenance/{build}` (§8.5.24).
 *
 * > "The system MUST record `provenance.json` per build — plan digest, image
 * > digest, tool versions, source SHAs, actor — served at
 * > `/_/provenance/{build}`."
 *
 * 🛑 **404 for everything that is not a published build of a project served
 * at this host**, and the host check is the part that matters. There is no
 * ambient tenant on this route — it carries no resolver middleware and no
 * session — so the tenancy question is answered explicitly: the request's
 * host must map to a domain, that domain must mount a project, and the build
 * must belong to a version of that project. Reading the build first and
 * trusting a global scope would have been the version of this that works in
 * development, where one organisation exists.
 *
 * 🛑 §8.2.2: cross-tenant access answers **404, never 403**, because a 403
 * confirms the row exists. The same reasoning covers a build that exists but
 * has not published: its existence is information about work in progress.
 *
 * 🛑 `private, no-store`, never a cache tag. A provenance document names
 * commit SHAs and an actor, and §9.3.2 forbids private content from entering
 * a shared cache. It is read by auditors and supply-chain tooling, not on a
 * hot path, so there is nothing to optimise away.
 */
final class ProvenanceController
{
    public function __construct(private readonly ArtifactStore $store) {}

    /**
     * 🛑 The route is declared inside a `Route::domain('{docupHostLabel}.…')`
     * group, so the host label is the **first** route parameter and Laravel
     * passes route parameters positionally. A signature of
     * `show(Request, string $build)` therefore receives the host label in
     * `$build` — which parsed as "not a UUID" and answered 404 for every
     * request, including the correct ones. Naming the label explicitly is
     * what binds `$build` to the right value.
     *
     * The label itself is never read: §8.9.4 forbids resolving a project from
     * anything but the host and path, and `hostServes()` takes the whole host.
     */
    public function show(Request $request, string $docupHostLabel, string $build): JsonResponse|Response
    {
        $id = Uuid::tryToBytes($build);

        if ($id === null) {
            return $this->notFound();
        }

        /*
         * Without global scopes, then checked against the host. The scope
         * needs an organisation context this route has no way to establish,
         * and silently returning nothing would make every provenance request
         * a 404 for a reason nobody could find.
         */
        $record = Build::withoutGlobalScopes()->whereKey($id)->first();

        if (! $record instanceof Build || $record->state !== 'published') {
            return $this->notFound();
        }

        $version = ProjectVersion::withoutGlobalScopes()
            ->whereKey($record->getRawOriginal('project_version_id'))
            ->first();

        if (! $version instanceof ProjectVersion || ! $this->hostServes($request->getHost(), $version)) {
            return $this->notFound();
        }

        $document = $this->store->get($this->store->prefixFor($id).'/provenance.json');

        if ($document === null) {
            return $this->notFound();
        }

        return response($document, 200, [
            'Content-Type' => 'application/json',
            'Cache-Control' => 'private, no-store',
            'X-Content-Type-Options' => 'nosniff',
        ]);
    }

    /**
     * Does the requested host actually serve this version's project?
     *
     * The whole tenancy check, in one query. A build reachable from any host
     * would make the endpoint a cross-tenant oracle for commit SHAs.
     */
    private function hostServes(string $host, ProjectVersion $version): bool
    {
        return DB::table('domain_mounts')
            ->join('domains', 'domains.id', '=', 'domain_mounts.domain_id')
            ->where('domains.host', strtolower($host))
            ->where('domains.state', 'active')
            ->where('domain_mounts.project_id', $version->getRawOriginal('project_id'))
            ->exists();
    }

    private function notFound(): JsonResponse
    {
        return response()->json(['error' => 'not_found'], 404);
    }
}
