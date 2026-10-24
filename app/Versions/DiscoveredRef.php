<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Versions;

/**
 * One branch or tag, as the ref advertisement reported it.
 *
 * A value object rather than a tuple, because {@see RefSync} and
 * {@see ChannelResolver} both read it and a `[$name, $kind, $sha]` array
 * would be positional in two files.
 *
 * 🛑 **`name` is the short name**, with `refs/heads/` or `refs/tags/`
 * already stripped. The advertisement's framing is the transport's, not the
 * author's: nobody types `refs/tags/v2.0.0`, and a slug derived from the
 * long form would be `refs-tags-v2.0.0`.
 */
final readonly class DiscoveredRef
{
    public function __construct(
        public string $name,
        public RefKind $kind,
        public string $commitSha,
    ) {}

    /**
     * Parse one advertisement entry, or null when it is not a ref we track.
     *
     * 🛑 `^{}` entries are DROPPED. A git advertisement lists an annotated
     * tag twice: once as `refs/tags/v2.0.0` pointing at the tag object, and
     * once as `refs/tags/v2.0.0^{}` pointing at the commit it wraps. Keeping
     * both would create two versions for one tag, whose slugs would differ
     * only by a hash suffix — and the second would win whichever sync ran
     * last.
     *
     * The peeled entry is the more *useful* of the two, because the commit
     * is what a build pins. It is therefore merged into the tag it belongs
     * to by {@see RefSync}, not discarded entirely.
     */
    public static function fromAdvertisement(string $ref, string $sha): ?self
    {
        if (str_starts_with($ref, 'symref=')) {
            return null;
        }

        if (str_starts_with($ref, 'refs/heads/')) {
            return new self(substr($ref, strlen('refs/heads/')), RefKind::Branch, $sha);
        }

        if (str_starts_with($ref, 'refs/tags/')) {
            $name = substr($ref, strlen('refs/tags/'));

            return str_ends_with($name, '^{}')
                ? null
                : new self($name, RefKind::Tag, $sha);
        }

        // `refs/pull/*`, `refs/merge-requests/*`, `refs/notes/*` and
        // whatever a provider invents next. §8.20 owns pull-request previews
        // and gives them their own path; a version is a branch or a tag.
        return null;
    }

    /** The peeled commit of an annotated tag, where the advertisement gave one. */
    public function withCommit(string $commitSha): self
    {
        return new self($this->name, $this->kind, $commitSha);
    }
}
