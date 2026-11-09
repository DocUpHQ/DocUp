<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Addons;

use App\Models\Project;
use App\Models\ProjectVersion;
use App\Serving\HostKind;
use App\Serving\RouteOutcome;
use App\Serving\SnapshotMount;
use App\Serving\SnapshotVersion;
use App\Serving\TranslationNotice;
use App\Versions\PageExistence;

/**
 * Everything one `/_/addons` request resolved to, gathered once.
 *
 * 🛑 **Gathered once, deliberately.** §8.15.2 makes this endpoint the single
 * source of request-scoped data, and that means one request answers nine
 * questions about the same project version — the flyout, the banners, page
 * existence, the canonical URL, the downloads. Each of those needs the version
 * rows and the manifests, and resolving them per question would make the
 * endpoint's cost scale with the number of fields in the payload rather than
 * with the project.
 *
 * So the controller resolves, authorises and loads; everything downstream reads
 * from here and queries nothing. That is the same arrangement §8.9.1 imposes on
 * the resolver, for the same reason: §9.2's budget is per request, not per
 * field.
 */
final readonly class AddonsContext
{
    /**
     * @param  SnapshotVersion|null  $version  null when the reader asked about a
     *                                         path that resolves to no version —
     *                                         a 404 page, or no `path` parameter
     *                                         at all
     * @param  array<string, ProjectVersion>  $rows  every listed version row, keyed
     *                                               by hex id. The rows carry what
     *                                               the snapshot deliberately does
     *                                               not (§8.9.1): `ref_kind`, the
     *                                               pin and the channel pointers
     * @param  array<string, bool>  $pageExists  §8.6.11's answer per version, keyed
     *                                           by hex id. Empty when there is no
     *                                           page to ask about
     * @param  TranslationNotice|null  $notice  §8.6.13's, when the path was a 404
     *                                          in a language the project publishes
     * @param  string  $origin  scheme and host of the request, for absolute URLs
     */
    public function __construct(
        public Project $project,
        public SnapshotMount $mount,
        public ?SnapshotVersion $version,
        public RouteOutcome $route,
        public HostKind $hostKind,
        public array $rows,
        public array $pageExists,
        public ?TranslationNotice $notice,
        public string $origin,
    ) {}

    /** The row behind the served version, or null. */
    public function versionRow(): ?ProjectVersion
    {
        return $this->version === null ? null : ($this->rows[bin2hex($this->version->id)] ?? null);
    }

    /**
     * Whether the page being read exists in that version (§8.6.11).
     *
     * 🛑 Defaults to **false**, not true. {@see PageExistence}
     * records the reasoning: "A version with nothing published answers `false`,
     * not 'unknown'. The three-state answer is tempting and wrong: a flyout
     * showing 'may or may not exist' has told the reader nothing." A version
     * absent from the map is one nothing was asked about, and claiming the page
     * is there would send a reader to a 404.
     */
    public function pageExistsIn(SnapshotVersion $version): bool
    {
        return $this->pageExists[bin2hex($version->id)] ?? false;
    }
}
