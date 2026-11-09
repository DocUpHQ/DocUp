<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Addons;

use App\Serving\ManifestReader;
use App\Serving\VersionUrl;

/**
 * 🛑 §8.7.17's per-version cross-reference map, for the payload.
 *
 * > "The addons payload MUST carry the per-version cross-reference map so the
 * > client progressively rewrites visible hrefs for humans, with the 302
 * > remaining the no-JavaScript and AI-agent path."
 *
 * Phase 27 recorded this as owed ("§8.7.17's addons payload does not carry the
 * cross-reference map").
 *
 * ## What the client needs, and why it is a base rather than a table
 *
 * A reference in built HTML is `/_/x/{component}/{path}` (§8.7.16). The final
 * URL is that component's mount root inside the version being read, plus the
 * path — so the map is **one base per component**, not one entry per reference.
 * A per-reference table would be unbounded in the size of the documentation and
 * would have to be regenerated whenever a mount moved; a base changes only when
 * the composition does.
 *
 * It also means an unresolvable reference stays unresolvable at the client:
 * a component absent from this map is one the client leaves alone, so the link
 * still goes to `/_/x/...` and still gets §8.7.16's 404 from the server. 🛑 The
 * rewriter must never invent a target, because §8.7.16's whole argument for a
 * serve-time 302 is that "sending every typo to the home page is how a broken
 * link becomes invisible".
 *
 * ## 🛑 The base and the 302 must agree
 *
 * {@see \App\Http\Controllers\Serving\CrossReferenceController} builds §8.7.16's `Location` from §7.3's parts
 * inline. This builds the same prefix through {@see VersionUrl}, which is where
 * §4.3 puts the one statement of the grammar — and `CrossReferenceMapTest`
 * asserts that base + path is byte-identical to the controller's `Location` for
 * the same reference. The equivalence is asserted rather than assumed because
 * the two are reached by different routes: the client uses this and a crawler
 * uses that, and a divergence would be invisible to whichever one nobody
 * tested.
 */
final readonly class CrossReferenceMap
{
    public function __construct(private ManifestReader $manifests) {}

    /**
     * Component key => the base URL a reference resolves against.
     *
     * Every base ends with a slash, so the client's rewrite is a concatenation
     * and cannot produce `/en/v1guide.html` for a component mounted at the
     * version root.
     *
     * @return array<string, string>
     */
    public function for(AddonsContext $context): array
    {
        $version = $context->version;

        if ($version === null || $version->publishedManifestId === null) {
            return [];
        }

        $scheme = $context->mount->versioningScheme();
        $map = [];

        foreach ($this->manifests->crossReferences($version->publishedManifestId) as $key => $entry) {
            $mountPath = trim($entry['mount_path'], '/');

            $map[(string) $key] = VersionUrl::document(
                $context->mount,
                $scheme,
                $version,
                $mountPath === '' ? '' : $mountPath.'/',
            );
        }

        return $map;
    }
}
