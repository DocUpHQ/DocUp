<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Versions;

/**
 * What a version was discovered from (§8.6.1).
 *
 * 🛑 The distinction is load-bearing in exactly one place and it is an
 * important one: §8.6.4 derives `stable` from "the highest **tag** by the
 * project's configured comparator" and only falls through to branches at
 * step 4. A project that tags releases and keeps a `2.x` maintenance branch
 * must get the tag, and nothing but this column can tell them apart after
 * the slug has been derived — `v2.0.0` and `v2.0.0` slug identically
 * whichever they came from.
 */
enum RefKind: string
{
    case Branch = 'branch';

    case Tag = 'tag';

    /**
     * §10.4's `kind ∈ {channel,release}` for a version from this ref.
     *
     * 🛑 Not the same enum, and the difference is worth stating because the
     * two look alike. `ref_kind` is a fact about git; `kind` is a fact about
     * what the version *means* to a reader — `latest` and `stable` are
     * channels with no ref of their own, and a branch is a channel because
     * it moves. A tag never moves, so it is a release.
     */
    public function versionKind(): string
    {
        return $this === self::Tag ? 'release' : 'channel';
    }
}
