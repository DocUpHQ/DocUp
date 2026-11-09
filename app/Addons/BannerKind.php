<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Addons;

use App\Models\Project;

/**
 * 🛑 §8.15.6's three notification banners.
 *
 * > "Addons MUST provide: version flyout, search-as-you-type, three
 * > **notification banners** (you are reading an old version / this is the
 * > development version / this is a pull-request build) with stated trigger
 * > conditions and per-project toggles, analytics beacon, and the
 * > cross-reference rewriter. The three banners are the most reader-visible
 * > Read the Docs feature after the flyout."
 *
 * Three cases, each with its **stated trigger condition** — stated here, in the
 * operator documentation generated from this enum, and asserted by
 * `NotificationBannerTest`. §8.15.6 asks for the conditions to be stated and
 * this is where they are, so the documentation cannot drift from the code.
 *
 * 🛑 A fourth value, {@see self::PageUntranslated}, carries §8.6.13's banner —
 * which is a notification by the same mechanism and was recorded as owed by
 * Phase 27 ("§8.6.13's banner inside P28's closed shadow root"). It is **not**
 * one of §8.15.6's three and has no per-project toggle, because §8.6.13 makes
 * it mandatory: "A missing page in a non-default language MUST return 404 plus
 * a notification banner, never a silent fallback". A toggle would be a switch
 * for turning a MUST off.
 */
enum BannerKind: string
{
    /**
     * "You are reading an old version."
     *
     * 🛑 **Trigger:** the served version is not the project's default version
     * (§8.6.14's explicit pointer), the default version is servable, and the
     * served version sorts **older** than it under the project's own §8.6.4
     * comparator.
     *
     * 🛑 The comparator is in the trigger rather than a date, and that is the
     * substance of the condition rather than an implementation note. DocUp has
     * no release-date ordering that holds across all five comparators —
     * `semver`, `pep440`, `calver`, `alphabetical` and an explicit custom order
     * — and §8.6.5 names the alternative's first bug report: "`v1.10` sorting
     * below `v1.9` is the first bug report every new installation receives". A
     * banner that decided "old" by `created_at` would fire on a long-term
     * support branch patched yesterday and stay silent on a two-year-old tag
     * imported last week.
     *
     * 🛑 And the comparison is one-directional on purpose. A reader on a version
     * *newer* than the default — a release candidate — is not reading an old
     * version, and telling them so would send them backwards. They get
     * {@see self::DevelopmentVersion} instead, when that applies.
     */
    case OldVersion = 'addons.old_version';

    /**
     * "This is the development version."
     *
     * 🛑 **Trigger:** the served version is the project's resolved `latest`
     * channel (§8.6.4), it tracks a **branch** rather than a tag, and the
     * project has a resolved `stable` that is a different version.
     *
     * All three clauses are load-bearing. The channel is what makes it "the
     * development version" rather than merely a recent one. The branch check is
     * what stops it firing on a project whose `latest` resolves to a tag,
     * where there is no development stream to warn about. And the third clause
     * is what stops it firing on **every page of every single-version project**
     * — with no `stable` to send the reader to, the banner is an apology with no
     * remedy, and ADR 0002's lesson is that a warning a reader cannot act on is
     * one they learn to ignore.
     */
    case DevelopmentVersion = 'addons.development_version';

    /**
     * "This is a pull-request build."
     *
     * 🛑 **Trigger:** the request arrived on the installation's **preview**
     * host — §8.1.4 requires pull-request previews to "occupy a **third**
     * distinct registrable domain", and §8.20.1 repeats it.
     *
     * 🛑 The host, not a column, and that is a deliberate choice rather than a
     * placeholder for Phase 32. The preview domain *is* the definition of a
     * preview in §8.20.1, so the trigger is correct before Phase 32 creates its
     * first ephemeral version and correct afterwards with nothing to re-wire.
     * A `pull_request` column added here would be schema invented for a phase
     * that has not run, and §8.20.1 would still be the thing that decided the
     * answer.
     */
    case PullRequest = 'addons.pull_request';

    /**
     * §8.6.13's banner: this page is not translated into the language asked for.
     *
     * Not one of §8.15.6's three, and not toggleable — see the enum docblock.
     */
    case PageUntranslated = 'addons.page_untranslated';

    /**
     * Whether this project has this banner switched on (§8.15.6).
     *
     * Asked of the kind rather than branched at the call site, so a banner added
     * later cannot default to "always on" by being forgotten.
     */
    public function enabledFor(Project $project): bool
    {
        return match ($this) {
            self::OldVersion => (bool) $project->notify_old_version,
            self::DevelopmentVersion => (bool) $project->notify_development_version,
            self::PullRequest => (bool) $project->notify_pull_request,

            // §8.6.13 is a MUST with no toggle. See the enum docblock.
            self::PageUntranslated => true,
        };
    }

    /**
     * The `lang/` key the runtime renders.
     *
     * 🛑 A key rather than a sentence, because §8.14.3 makes chrome content
     * structured data — "never free HTML" — and because the reader's language
     * is the documentation's, which the payload knows and the runtime does not
     * have to guess.
     */
    public function translationKey(): string
    {
        return 'addons.banners.'.str_replace('addons.', '', $this->value);
    }

    /**
     * The §8.14.1 `banner.tone` this kind renders as.
     *
     * 🛑 Fixed per kind rather than configurable. `banner.tone` is the token a
     * tenant sets for *their own* announcement; these three are DocUp telling a
     * reader something about the version they are on, and a tenant who could
     * style "this is a pull-request build" as a success notice would be able to
     * make a preview look like a release.
     */
    public function tone(): string
    {
        return match ($this) {
            self::OldVersion, self::PageUntranslated => 'warning',
            self::DevelopmentVersion, self::PullRequest => 'notice',
        };
    }

    /**
     * The three §8.15.6 banners, in the order a reader sees them.
     *
     * @return list<self>
     */
    public static function toggleable(): array
    {
        return [self::OldVersion, self::DevelopmentVersion, self::PullRequest];
    }
}
