<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Serving;

/**
 * What the resolver decided, as one value.
 *
 * Three shapes rather than three return types, so a caller cannot handle two of
 * them and forget the third: every branch reads `$kind` and the compiler-visible
 * nullability of the rest follows from it.
 *
 * 🛑 `matchedRule` is required, not decorative. Phase 04's exit criteria include
 * "`X-DocUp-Resolver` names the matched rule", and that header is the only way
 * an operator can tell *why* a request resolved where it did — on a shared
 * domain with several mounts, "it 404s" and "it matched the wrong mount" look
 * identical from outside.
 */
final class RouteOutcome
{
    private function __construct(
        public readonly RouteKind $kind,
        public readonly string $matchedRule,
        public readonly ?RejectionReason $reason = null,
        public readonly ?string $redirectTo = null,
        public readonly ?SnapshotMount $mount = null,
        public readonly ?SnapshotVersion $version = null,
        public readonly string $language = '',
        public readonly string $remainder = '',
    ) {}

    /**
     * The path resolved to a version, with `$remainder` left for the manifest.
     *
     * @param  string  $remainder  component-relative, no leading slash
     */
    public static function resolved(
        string $matchedRule,
        SnapshotMount $mount,
        SnapshotVersion $version,
        string $language,
        string $remainder,
    ): self {
        return new self(
            kind: RouteKind::Resolved,
            matchedRule: $matchedRule,
            mount: $mount,
            version: $version,
            language: $language,
            remainder: $remainder,
        );
    }

    /** §8.9.7: an empty path goes to the default version; a directory gains a slash. */
    public static function redirect(string $matchedRule, string $to): self
    {
        return new self(kind: RouteKind::Redirect, matchedRule: $matchedRule, redirectTo: $to);
    }

    public static function rejected(string $matchedRule, RejectionReason $reason): self
    {
        return new self(kind: RouteKind::Rejected, matchedRule: $matchedRule, reason: $reason);
    }

    /**
     * A rejection that still knows which mount and language it was about.
     *
     * 🛑 §8.6.13 needs this: "A missing page in a non-default language MUST
     * return 404 plus a notification banner." A banner naming the languages
     * the project *does* publish cannot be built from a rejection that
     * dropped which project and which language were asked for — and a caller
     * re-deriving them from the path would be a second reading of §7.3's
     * grammar, which §17.4 froze precisely to prevent.
     *
     * The resolver's **decision** is unchanged by this: same rule, same
     * reason, same status. It reports two facts it had already computed
     * rather than discarding them, so the freeze is untouched.
     */
    public static function rejectedIn(
        string $matchedRule,
        RejectionReason $reason,
        SnapshotMount $mount,
        string $language,
    ): self {
        return new self(
            kind: RouteKind::Rejected,
            matchedRule: $matchedRule,
            reason: $reason,
            mount: $mount,
            language: $language,
        );
    }

    /**
     * The resolution cache key (§8.9.10).
     *
     * 🛑 The epoch is **in the key** rather than purged. §8.9.10: "A failed CDN
     * purge then degrades to stale public HTML for `max-age`, never to wrong
     * routing." Maximum tolerated staleness for this epoch is 0 (§10.8), and
     * putting it in the key is what achieves 0 — a bumped epoch addresses
     * different keys, so there is no window in which a stale entry can be read
     * at all. The epoch is the **project's**, so one project's domain change
     * cannot invalidate every other project's resolution cache.
     *
     * 🛑 **sha256, where §8.9.10 writes `sha1(path)`.** A deliberate,
     * recorded divergence rather than a quiet one — see the amendment proposed
     * in the Phase 04 build-log entry.
     *
     * Two reasons. Pest's `security` preset refuses `sha1`, and CLAUDE.md rule
     * 4 forbids lowering a gate to make a phase pass; exempting the preset to
     * keep the specification's spelling would be exactly that. And the property
     * does matter here, if thinly: two canonical paths colliding on this digest
     * would share one resolution entry, so one page would be served for
     * another's URL on the same host. That is a cache-poisoning primitive, not
     * merely an untidy hash, and it costs nothing to remove — the key is
     * opaque, so its length is irrelevant.
     *
     * The specification's choice was not unreasonable: a host- and
     * epoch-scoped key within the restricted canonical-path charset is a hard
     * target. It is simply not worth defending when the alternative is free.
     */
    public static function cacheKey(int $routingEpoch, string $host, string $path): string
    {
        return 'res:'.$routingEpoch.':'.$host.':'.hash('sha256', $path);
    }

    /** The HTTP status for a rejection, or null when there is nothing to reject. */
    public function status(): ?int
    {
        return $this->reason?->status();
    }
}
