<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Addons;

use App\Access\AccessSurface;
use App\Http\Controllers\Serving\DownloadController;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Serving\OfflineFormat;
use App\Serving\SnapshotVersion;
use App\Serving\VersionUrl;
use App\Versions\VersionOrder;

/**
 * §8.15's version flyout, as the payload carries it.
 *
 * Four requirements meet here:
 *
 * - §8.6.5's **configurable sort**: "The flyout's version order MUST use the
 *   §8.6.4 comparator — `semver` (default), `pep440`, `calver`, `alphabetical`
 *   or an explicit custom order — with a separate per-project toggle for
 *   whether `latest` and `stable` are pinned to the top of the list or sorted
 *   in place." 🛑 Delegated whole to {@see VersionOrder}, which Phase 10 built
 *   and which is also what the dashboard and the API use. A second ordering
 *   here would be the failure §8.6.4 names: "A list ordered one way and a
 *   pointer derived another."
 *
 * - §8.6.11's **cross-version page existence**: "when a reader switches version
 *   and the page is absent, the flyout MUST say so from the per-build file
 *   manifest rather than delivering a bare 404."
 *
 * - §8.6.2's `listed` axis, applied by `VersionOrder::forFlyout()` and nowhere
 *   else on the serving path.
 *
 * - §8.15.11's **offline formats**: "The addons payload MUST include the
 *   offline formats available for the resolved project version with their
 *   `/_/downloads/...` URLs, so the flyout can offer downloads without a second
 *   resolution round trip. Per §8.7.19 the list is per project version, not per
 *   component mount."
 *
 * 🛑 **Access filtering is the caller's, and it has already happened.** §8.12.9
 * makes the flyout one of the surfaces that "MUST be generated from the
 * **authorised** view", and {@see AddonsContext::$rows} carries only the
 * versions §12.3 allowed this reader — asked per version, with
 * {@see AccessSurface::Addons}. This class does no filtering of its
 * own, deliberately: a second filter here would be a second place for the
 * answer to differ from the gate's.
 */
final readonly class Flyout
{
    public function __construct(private VersionOrder $order) {}

    /**
     * The version list, sorted, with page existence and each version's URL.
     *
     * @return list<array{
     *     slug: string,
     *     language: string,
     *     kind: string,
     *     href: string,
     *     current: bool,
     *     page_exists: bool,
     *     channel: string|null
     * }>
     */
    public function versions(AddonsContext $context): array
    {
        $ordered = $this->order->forFlyout($context->project, array_values($context->rows));
        $currentId = $context->version?->id;
        $scheme = $context->mount->versioningScheme();
        $entries = [];

        foreach ($ordered as $row) {
            $version = $this->snapshotFor($context, $row);

            if (! $version instanceof SnapshotVersion) {
                /*
                 * A row the snapshot does not carry. That is not an error: the
                 * snapshot holds the versions of the projects mounted on *this
                 * domain*, and §8.7.19's mount scoping (`version_scope`) can
                 * narrow which of a project's versions a particular mount
                 * exposes. A row the mount does not expose has no URL on this
                 * host, so it is absent rather than linked to nothing.
                 */
                continue;
            }

            $exists = $context->pageExistsIn($version);

            $entries[] = [
                'slug' => $version->slug,
                'language' => $version->language,
                'kind' => (string) $row->kind,
                'href' => VersionUrl::document(
                    $context->mount,
                    $scheme,
                    $version,
                    // §8.6.11: the page where it is, the root where it is not.
                    $exists ? $context->route->remainder : '',
                ),
                'current' => $currentId !== null && $version->id === $currentId,
                'page_exists' => $exists,
                'channel' => $this->channelOf($context->project, $version),
            ];
        }

        return $entries;
    }

    /**
     * §8.15.2's "flyout configuration".
     *
     * 🛑 The sort is **published**, not merely applied. A reader cannot see why
     * `v1.10` sits above `v1.9` unless something says which comparator ran, and
     * an `api_only` consumer rendering its own flyout needs the same answer —
     * §8.15.2 makes this endpoint the only source of it.
     *
     * @return array{comparator: string, pin_channels_to_top: bool}
     */
    public function configuration(Project $project): array
    {
        return [
            'comparator' => (string) $project->version_comparator,
            'pin_channels_to_top' => (bool) $project->pin_channels_to_top,
        ];
    }

    /**
     * §8.15.11's offline formats for the **resolved** version, with their URLs.
     *
     * 🛑 Per project version, never per mount, which is §8.7.19's rule: "only
     * the **primary** component mount MAY emit `pdf`, `epub` and `htmlzip`. Per
     * mount offline downloads would need a distinct URL contract; this is the
     * simpler choice and it is stated so the ambiguity cannot recur."
     *
     * 🛑 And the URL is built from §7.3's `/_/downloads/{language}/{version}/
     * {format}` shape **whatever the project's versioning scheme is**, because
     * that is what {@see DownloadController}
     * answers on — including `single_version`, where a documentation URL
     * carries neither segment.
     *
     * @param  list<string>  $available  the formats the published build emitted
     * @return list<array{format: string, href: string, content_type: string}>
     */
    public function downloads(AddonsContext $context, array $available): array
    {
        $version = $context->version;

        if ($version === null) {
            return [];
        }

        $prefix = VersionUrl::shed($context->mount);
        $downloads = [];

        foreach ($available as $name) {
            $format = OfflineFormat::tryFrom($name);

            if ($format === null) {
                continue;
            }

            $downloads[] = [
                'format' => $format->value,
                'href' => $prefix.'/_/downloads/'.$version->language.'/'.$version->slug.'/'.$format->value,
                'content_type' => $format->contentType(),
            ];
        }

        return $downloads;
    }

    /**
     * Which §8.6.4 channel this version currently resolves to, if either.
     *
     * Carried so the flyout can label the entries §8.6.5's toggle pins to the
     * top. 🛑 Read from the project's **resolved** pointers rather than
     * recomputed, for §8.6.4's reason: the derivation has one home and a second
     * one here could disagree with the pointer the redirect uses.
     */
    private function channelOf(Project $project, SnapshotVersion $version): ?string
    {
        return match ($version->id) {
            $project->resolved_latest_version_id => 'latest',
            $project->resolved_stable_version_id => 'stable',
            default => null,
        };
    }

    /** The snapshot's view of a loaded row, or null when the mount hides it. */
    private function snapshotFor(AddonsContext $context, ProjectVersion $row): ?SnapshotVersion
    {
        foreach ($context->mount->project->versions as $version) {
            if ($version->id === $row->id && $context->mount->exposes($version->slug)) {
                return $version;
            }
        }

        return null;
    }
}
