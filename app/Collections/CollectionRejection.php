<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Collections;

/**
 * Why a collection write was refused, as a stable identifier.
 *
 * 🛑 §8.1.11 public contract, like every other rejection enum here: these
 * values reach the audit log, the dashboard, the Read the Docs importer's
 * report and an operator's tooling, so renaming one breaks something outside
 * this repository.
 *
 * Every alias refusal below exists because an alias is a **path segment**.
 * §8.2.6 puts a collection at "a URL path prefix on a domain mount", and
 * §17.4 froze §7.3's grammar at the end of Phase 04 — so a collection cannot
 * answer a collision by adding a dimension to the grammar. It has to refuse
 * the name.
 */
enum CollectionRejection: string
{
    /**
     * The alias is not a legal URL segment: wrong characters, too long, or
     * edged with a separator.
     */
    case AliasMalformed = 'collection.alias_malformed';

    /**
     * 🛑 The alias is `_`, `.well-known`, `page` or another segment §7.3 and
     * §8.6.10 have already claimed, **or** it is shaped like a language code.
     *
     * The language-code half is the one worth stating: under
     * `lang_and_version` a language sits in the same path position a bare
     * alias does, so a collection aliased `ja` is unreachable the day the
     * parent gains a Japanese translation — long after the alias was chosen
     * and printed in somebody's documentation. {@see App\Versions\VersionSlug::isReserved()}
     * refuses the same shape for the same reason, and one function answers
     * for both so they cannot drift apart.
     */
    case AliasReserved = 'collection.alias_reserved';

    /**
     * 🛑 The alias is a version slug of the parent project.
     *
     * Refused on the **alias** rather than on the computed prefix, which is
     * stricter than it needs to be under the `/projects/<alias>/` convention
     * and is the point: §8.2.6 makes the convention configurable, so an alias
     * that is only safe under one of them is a trap that fires when an
     * operator changes the column — at which moment the member's URLs and one
     * of the parent's versions become the same path.
     */
    case AliasCollidesWithVersion = 'collection.alias_collides_with_version';

    /** §10.1's `UNIQUE (collection_id, alias)`. */
    case AliasTaken = 'collection.alias_taken';

    /** §10.1's `UNIQUE (collection_id, project_id)`. */
    case AlreadyMember = 'collection.already_member';

    /**
     * 🛑 §4.2: nested collections are out of scope. A collection's parent
     * project may not itself be a member of that collection, which is the
     * one-level version of the same loop.
     */
    case ParentCannotBeMember = 'collection.parent_cannot_be_member';

    /** A collection with no parent project has no domain to mount members under. */
    case ParentMissing = 'collection.parent_missing';

    /** The parent project is not served anywhere, so there is no prefix to extend. */
    case ParentNotMounted = 'collection.parent_not_mounted';

    /**
     * 🛑 The member's prefix would shadow a version of the parent project.
     *
     * Distinct from {@see self::AliasCollidesWithVersion}: that one is about
     * the alias, this one is about the first segment of the whole prefix. A
     * parent with a version slugged `projects` and the default convention
     * produces a mount at `projects/<alias>`, which the resolver matches
     * longest-first and which therefore swallows a path inside that version.
     */
    case PrefixShadowsVersion = 'collection.prefix_shadows_version';

    /** §10.5's `UNIQUE (domain_id, path_prefix)`: something is already there. */
    case PrefixTaken = 'collection.prefix_taken';

    /**
     * 🛑 §8.12.8: "Composition MUST NEVER widen access, **without
     * exception**." A mount whose exposure does not satisfy
     * `narrows(mount_exposure, project.visibility)` is refused **at write
     * time**, which is the only place the refusal is cheap and the only place
     * it is unambiguous — at read time there is no longer a write to refuse.
     */
    case ExposureWidens = 'collection.exposure_widens';

    /** Members of one collection must live in one organisation (§8.2.1). */
    case CrossTenant = 'collection.cross_tenant';

    public function identifier(): string
    {
        return $this->value;
    }
}
