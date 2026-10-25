<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Composition;

/**
 * 🛑 §8.7.5's three fallback modes for `mirror_label`.
 *
 * > "`mirror_label` MUST support fallback modes `newest_semver_lte`, `newest`
 * > and `fail` — this is the answer to contributing repositories releasing on
 * > different cadences: project `v2.3` takes the glossary repository's `v2.0`
 * > because it is the highest label ≤ 2.3. Without it, 'many repos, one
 * > version selector' does not work in practice."
 *
 * The three differ in what they prefer when the exact label is missing, and
 * the difference is a product decision rather than a detail:
 *
 * - {@see self::NewestSemverLte} prefers the newest content that cannot be
 *   from the future. A glossary that stopped at 2.0 keeps serving 2.0 under
 *   project v2.3, which is almost always right and is why §8.7.5 names it
 *   first.
 * - {@see self::Newest} prefers currency. Right for a component with no
 *   release discipline — an internal style guide, say — where "the latest"
 *   is the only meaningful answer and comparing labels is noise.
 * - {@see self::Fail} prefers nothing to something wrong. The mount does not
 *   resolve, and §8.7.20 then makes the publish fail closed if the mount is
 *   required. That is the correct answer for a legal or compliance component
 *   where serving the wrong revision is worse than serving none.
 */
enum MirrorFallback: string
{
    /** The highest label less than or equal to the project version's. */
    case NewestSemverLte = 'newest_semver_lte';

    /** The newest successful build, regardless of label. */
    case Newest = 'newest';

    /** No fallback: the mount does not resolve. */
    case Fail = 'fail';
}
