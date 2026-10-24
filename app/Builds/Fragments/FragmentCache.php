<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds\Fragments;

use App\Models\Build;
use App\Support\Uuid;
use Illuminate\Support\Facades\DB;

/**
 * §8.5.19's cache: the only thing that reads or writes the `fragments` table.
 *
 * > "The system MUST cache per-source build output keyed by `fragment_digest
 * > = H(source_digest, env_digest, config_digest, public_env)`, 🛑 **looked
 * > up only within the originating `repository_id`** … A cache hit skips the
 * > environment and build stages entirely — this is what makes a shared API
 * > repository feeding 40 projects affordable. An architecture test MUST
 * > assert that no lookup path omits the repository scope."
 *
 * 🛑 **There is one lookup method and it takes the repository first.** The
 * architecture test asserts that `fragments` appears in no other file, which
 * is how "no lookup path omits the repository scope" is made checkable rather
 * than reviewed: a path that omitted it would have to exist somewhere, and
 * there is nowhere else for it to be. §14.2 names the trap — two
 * organisations with byte-identical sources sharing a fragment would make the
 * cache a cross-tenant file-existence oracle — and §19/38 records that the
 * answer is the repository row rather than an installation-level opt-in.
 *
 * 🛑 **A non-cacheable fragment is recorded, not skipped.** §8.5.19 marks a
 * fragment non-cacheable when the configuration referenced a secret; the row
 * still exists so that the next build can see *that* it is non-cacheable
 * rather than discovering it by building. The row carries no secret and no
 * secret-derived value — {@see FragmentDigest} keeps secrets out of the key
 * entirely.
 */
final class FragmentCache
{
    /**
     * A build whose output can be reused, or null.
     *
     * @param  string  $repositoryId  raw 16 bytes; 🛑 the scope, never optional
     * @param  string  $digest  raw 32 bytes from {@see FragmentDigest::bytes()}
     */
    public function lookup(string $repositoryId, string $digest): ?Build
    {
        $row = DB::table('fragments')
            ->where('repository_id', $repositoryId)
            ->where('fragment_digest', $digest)
            ->where('cacheable', true)
            ->first();

        if ($row === null) {
            return null;
        }

        $buildId = $row->build_id ?? null;

        if (! is_string($buildId)) {
            return null;
        }

        /*
         * 🛑 The build is re-read and re-checked rather than trusted from
         * the fragment row. A fragment whose build was later deleted,
         * superseded or found to have failed must miss: the row is an index
         * into the build table, and an index that outlives its target is the
         * oldest bug in caching.
         */
        $build = Build::query()->whereKey($buildId)->first();

        if (! $build instanceof Build || ! in_array($build->state, ['published', 'success_unpublished'], true)) {
            return null;
        }

        return $build;
    }

    /**
     * Record the fragment this build produced.
     *
     * Idempotent: a rebuilt fragment replaces the row's build and refreshes
     * its clock rather than colliding on the primary key. A build that
     * reproduced an existing fragment byte for byte is the normal case and
     * must not fail on a duplicate.
     */
    public function remember(Build $build, string $repositoryId, string $digest, bool $cacheable): void
    {
        DB::table('fragments')->upsert(
            [[
                'repository_id' => $repositoryId,
                'fragment_digest' => $digest,
                'organisation_id' => $build->organisation_id,
                'build_id' => $build->id,
                'cacheable' => $cacheable,
                'refcount' => 0,
                'last_used_at' => now(),
                'created_at' => now(),
            ]],
            ['repository_id', 'fragment_digest'],
            ['build_id', 'cacheable', 'last_used_at'],
        );
    }

    /**
     * Note that a build was satisfied from a fragment.
     *
     * The refcount and the clock are what §8.8's garbage collection reads:
     * a fragment nothing has used for the retention window and that no build
     * points at is a candidate, and one with a live refcount is not.
     */
    public function recordHit(Build $build, string $repositoryId, string $digest): void
    {
        DB::table('fragments')
            ->where('repository_id', $repositoryId)
            ->where('fragment_digest', $digest)
            ->update([
                'refcount' => DB::raw('refcount + 1'),
                'last_used_at' => now(),
            ]);

        $this->link($build, $repositoryId, $digest, wasHit: true);
    }

    /**
     * Join this build to the fragment it used or created.
     *
     * 🛑 `was_hit` is what proves the exit criterion. "A second identical
     * build hits the fragment cache and skips the build stage, **proven by
     * step rows**" needs two independent records agreeing: a `skipped` step
     * row for `build`, and this row saying the skip was a hit rather than a
     * stage that had nothing to do.
     */
    public function link(Build $build, string $repositoryId, string $digest, bool $wasHit): void
    {
        DB::table('build_fragments')->insertOrIgnore([
            'id' => Uuid::v7(),
            'organisation_id' => $build->organisation_id,
            'build_id' => $build->id,
            'repository_id' => $repositoryId,
            'fragment_digest' => $digest,
            'was_hit' => $wasHit,
            'created_at' => now(),
        ]);
    }
}
