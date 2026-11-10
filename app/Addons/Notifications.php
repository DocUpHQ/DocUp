<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Addons;

use App\Serving\HostKind;
use App\Serving\SnapshotVersion;
use App\Serving\TranslationNotice;
use App\Serving\VersionUrl;
use App\Versions\VersionComparator;

/**
 * 🛑 §8.15.6's three banners, evaluated for one request.
 *
 * Each trigger condition is stated on its {@see BannerKind} case; this class is
 * only the evaluation, so the condition and the code that implements it sit one
 * file apart and `NotificationBannerTest` asserts both directions of all three.
 *
 * 🛑 **The per-project toggle is applied here, once, for every kind.** A kind
 * whose trigger fires and whose toggle is off produces nothing — and the check
 * is a single `enabledFor()` pass at the end rather than a guard inside each
 * evaluator, because a kind added later must not be able to skip it by being
 * written without one.
 */
final readonly class Notifications
{
    /**
     * Every banner this request earns, in the order a reader sees them.
     *
     * @return list<Banner>
     */
    public function for(AddonsContext $context): array
    {
        $candidates = array_filter([
            $this->oldVersion($context),
            $this->developmentVersion($context),
            $this->pullRequest($context),
            $this->untranslated($context),
        ]);

        return array_values(array_filter(
            $candidates,
            static fn (Banner $banner): bool => $banner->kind->enabledFor($context->project),
        ));
    }

    /**
     * {@see BannerKind::OldVersion} — the stated trigger, in code.
     *
     * The href is 🛑 **the same page in the default version where it exists**,
     * and the default version's root where it does not. §8.6.11 makes
     * cross-version page existence answerable from the manifest, and sending a
     * reader from the page they are reading to a 404 would be worse than
     * leaving the banner without a link at all.
     */
    private function oldVersion(AddonsContext $context): ?Banner
    {
        $version = $context->version;
        $default = $context->mount->project->defaultVersion();

        if ($version === null || ! $default instanceof SnapshotVersion || $default->id === $version->id) {
            return null;
        }

        /*
         * 🛑 §8.6.4's comparator, and one direction only. See
         * BannerKind::OldVersion for why a date would be wrong and why a reader
         * on a NEWER version must not be told they are behind.
         *
         * Compared on `ref_name` where there is one, falling back to the slug —
         * the same preference {@see \App\Versions\VersionOrder} applies, because
         * §8.6.6's slug derivation replaces the characters a comparator reads.
         */
        $comparator = VersionComparator::fromStored($context->project->version_comparator);

        if ($comparator->compare($this->sortKey($context, $version), $this->sortKey($context, $default)) >= 0) {
            return null;
        }

        return new Banner(
            kind: BannerKind::OldVersion,
            href: VersionUrl::document(
                $context->mount,
                $context->mount->versioningScheme(),
                $default,
                /*
                 * The page where it exists there, the version root where it does
                 * not. §8.6.11: "when a reader switches version and the page is
                 * absent, the flyout MUST say so from the per-build file manifest
                 * rather than delivering a bare 404" — and the same answer serves
                 * this banner's link.
                 */
                $context->pageExistsIn($default) ? $context->route->remainder : '',
            ),
            values: ['version' => $version->slug, 'default' => $default->slug],
        );
    }

    /** {@see BannerKind::DevelopmentVersion} — the stated trigger, in code. */
    private function developmentVersion(AddonsContext $context): ?Banner
    {
        $version = $context->version;
        $latest = $context->project->resolved_latest_version_id;
        $stable = $context->project->resolved_stable_version_id;

        if ($version === null || $latest === null || $latest !== $version->id) {
            return null;
        }

        /*
         * The third clause: no `stable` to send the reader to means no banner.
         * See BannerKind::DevelopmentVersion — a warning with no remedy is one a
         * reader learns to ignore, which is ADR 0002's finding arrived at from
         * the reader's side rather than the operator's.
         */
        if ($stable === null || $stable === $version->id) {
            return null;
        }

        /*
         * The branch clause. A `latest` that resolves to a tag is a release, not
         * a development stream. Read from the loaded row rather than from the
         * snapshot, because `ref_kind` is not a routing fact and §8.9.1 keeps
         * the snapshot to the facts the resolver needs.
         */
        $row = $context->versionRow();

        if ($row === null || $row->ref_kind !== 'branch') {
            return null;
        }

        return new Banner(
            kind: BannerKind::DevelopmentVersion,
            values: ['version' => $version->slug],
        );
    }

    /**
     * {@see BannerKind::PullRequest} — the stated trigger, in code.
     *
     * 🛑 One expression, and that is the point of deciding it from the host:
     * §8.20.1 makes the preview domain the definition of a preview, so there is
     * nothing to infer and nothing for Phase 32 to re-wire.
     */
    private function pullRequest(AddonsContext $context): ?Banner
    {
        return $context->hostKind === HostKind::Preview
            ? new Banner(BannerKind::PullRequest)
            : null;
    }

    /**
     * §8.6.13's banner, carried in the payload so the closed shadow root can
     * render it.
     *
     * Phase 27 recorded this as owed ("§8.6.13's banner inside P28's closed
     * shadow root"). {@see TranslationNotice} already emits the response header
     * an operator or a proxy reads; this is the same fact in the one place a
     * script can read it, because 🛑 a document's own JavaScript cannot read its
     * own response headers and nothing rewrites documentation on the serving
     * path (§4.3/2, §8.9.8).
     */
    private function untranslated(AddonsContext $context): ?Banner
    {
        $notice = $context->notice;

        if (! $notice instanceof TranslationNotice) {
            return null;
        }

        $languages = array_map(
            static fn (array $entry): string => $entry['language'],
            $notice->available,
        );

        return new Banner(
            kind: BannerKind::PageUntranslated,
            href: $notice->available[0]['href'] ?? null,
            values: [
                'requested' => $notice->requestedLanguage,
                'available' => implode(', ', $languages),
                'code' => $notice->code,
            ],
        );
    }

    /** The string the §8.6.4 comparator reads for a version. */
    private function sortKey(AddonsContext $context, SnapshotVersion $version): string
    {
        $row = $context->rows[bin2hex($version->id)] ?? null;

        return $row->ref_name ?? $version->slug;
    }
}
