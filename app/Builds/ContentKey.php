<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds;

use App\Models\Component;
use App\Models\ComponentMount;

/**
 * §8.7.9's content key — the one value that makes "build once" true.
 *
 * > "Builds MUST be identified by a content key over `organisation_id`,
 * > `component_id`, `commit_sha`, config digest, builder image, builder
 * > version, and — only when `base_url_mode='injected'` — the mount path;
 * > enforced `UNIQUE`, and satisfied from an existing successful build with
 * > the same key. This is what makes one repository feeding many projects
 * > build **once**."
 *
 * 🛑 **Every input is a property of the COMPONENT, never of a project.**
 * That is the whole content of §8.7.10 — "No project-scoped input ... MUST
 * enter a build container" — expressed as a hash rather than as a rule. If a
 * project id, a project slug, a canonical URL or a branding value were in
 * here, two projects mounting one component would compute two keys and build
 * twice, and the feature this phase exists for would be gone. The opposite
 * mistake is worse and quieter: an input that genuinely changes the output
 * and is NOT in the key means one project serves another project's bytes.
 *
 * 🛑 **The mount path is in the key only under `injected`.** Under
 * `relative` — the default — the build emits root-relative hrefs and the
 * same bytes work at any prefix, so the mount path changes nothing and must
 * not enter. Under `injected` the prefix is baked into the output, so it
 * changes everything and must. §8.7.11 calls the second case out as a loss
 * of cross-project reuse, and this is where that loss happens: a different
 * mount path is a different key is a different build.
 *
 * The key is a hex SHA-256 because `builds.content_key` is `CHAR(64)` under
 * a `UNIQUE` index, and the uniqueness is what enforces the rule — not a
 * `SELECT` first. A check-then-insert would let two concurrent builds of one
 * component both miss and both build, which is precisely the race a
 * monorepo's push across three projects produces.
 */
final readonly class ContentKey
{
    /**
     * 🛑 Versioned, and the version is inside the hash.
     *
     * The day an input is added or removed, every existing key must stop
     * matching — otherwise a build produced under the old definition would
     * satisfy a request computed under the new one, which is the "one
     * project serves another's bytes" failure arriving through an upgrade.
     * Bumping this is how that is made safe, and it costs one full rebuild
     * of everything, once.
     */
    private const SCHEMA = 'docup.content-key/1';

    /**
     * Compute the key for one component build.
     *
     * @param  string  $organisationId  raw 16 bytes
     * @param  string  $componentId  raw 16 bytes
     * @param  string  $commitSha  the pinned commit, per §8.5.1
     * @param  string  $configDigest  the `.docup.yaml` digest
     * @param  string  $envDigest  §8.5.2's, which §8.5.14 makes carry the image digest
     * @param  int  $pipelineVersion  the "builder version" of §8.7.9
     * @param  string|null  $mountPath  🛑 ONLY under `base_url_mode: injected`
     */
    public static function compute(
        string $organisationId,
        string $componentId,
        string $commitSha,
        string $configDigest,
        string $envDigest,
        int $pipelineVersion,
        ?string $mountPath = null,
    ): string {
        return hash('sha256', (string) json_encode([
            'schema' => self::SCHEMA,

            /*
             * 🛑 The organisation is in the key, and §8.5.19 explains why at
             * length for the fragment cache: "two organisations with
             * byte-identical sources can never share a fragment and the
             * cache cannot act as a cross-tenant file-existence oracle". The
             * same argument applies here with more force, because a build is
             * not a cache entry — it is bytes somebody will be served.
             */
            'organisation' => bin2hex($organisationId),
            'component' => bin2hex($componentId),
            'commit' => $commitSha,
            'config_digest' => $configDigest,

            // §8.5.2's env digest already carries the builder image digest
            // (§8.5.14), so "builder image" and the image's own version are
            // both inside this one value rather than listed twice.
            'env_digest' => $envDigest,
            'pipeline_version' => $pipelineVersion,

            /*
             * Null under `relative`, and null is not the empty string: a
             * component mounted at the root under `injected` has a mount
             * path of `''`, and that is a different build from the same
             * component built `relative`. Encoding both as `''` would make
             * them one key and serve prefix-baked HTML at a prefix it was
             * not built for.
             */
            'mount_path' => $mountPath,
        ], JSON_THROW_ON_ERROR));
    }

    /**
     * The mount path to put in the key, or null when it does not belong.
     *
     * 🛑 The MOUNT's mode decides, falling back to the component's default.
     * §8.7.11 makes `base_url_mode` a component declaration and §8.7.9 puts
     * "the mount path" in the key — and the mount path is the mount's, so
     * the two have to be read together or a component whose default is
     * `relative` could never have an `injected` mount at all.
     */
    public static function mountPathFor(?ComponentMount $mount, Component $component): ?string
    {
        if (! $mount instanceof ComponentMount) {
            // No mount yet — a build triggered before the version was
            // composed. The component's default decides, and with no mount
            // path to put in the key the only honest answer under
            // `injected` is the root, which is where a single primary mount
            // sits (§8.7.3).
            return $component->default_base_url_mode === 'injected' ? '' : null;
        }

        $mode = $mount->base_url_mode ?? $component->default_base_url_mode;

        return $mode === 'injected' ? $mount->mount_path : null;
    }
}
