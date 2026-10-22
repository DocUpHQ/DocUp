<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Serving;

use App\Artifacts\RejectionCode;

/**
 * Why the serving edge refused a request, as a stable identifier.
 *
 * 🛑 Stable for the same reason {@see RejectionCode} is: these
 * strings reach `X-DocUp-Resolver`, the access log and an operator's alerting.
 * §8.9.6's whole value is positional — the rejection happens before any cache
 * lookup — so an operator needs to be able to tell, from a log line alone,
 * *which* rejection fired. "400" does not distinguish a traversal attempt from
 * a trailing-slash mistake.
 *
 * The values carry no `contract.` or `rejected.` prefix from §8.19.15's set,
 * and that is deliberate: §8.19.15 classifies **build** failures. A refused
 * request is not a build outcome, and borrowing the vocabulary would put
 * request rejections into the same alert stream as failing builds.
 */
enum RejectionReason: string
{
    // ------------------------------------------------- §8.9.6 path canonicality

    /** The path does not begin with `/`. */
    case PathNotAbsolute = 'path.not_absolute';

    /** An empty segment: `//` anywhere, including a protocol-relative `//host`. */
    case PathEmptySegment = 'path.empty_segment';

    /** A `.` or `..` segment, literal or percent-encoded. */
    case PathDotSegment = 'path.dot_segment';

    /** A NUL, C0/C1 control byte or DEL, raw or percent-encoded. */
    case PathControlByte = 'path.control_byte';

    /** A backslash, which some readers treat as a separator and some do not. */
    case PathBackslash = 'path.backslash';

    /**
     * A byte that is not permitted raw and was not percent-encoded, or a
     * delimiter that may never appear in a path DocUp serves.
     */
    case PathIllegalByte = 'path.illegal_byte';

    /**
     * A percent-escape that is malformed, lowercase, or encodes a byte that did
     * not need encoding.
     *
     * Over-encoding is the interesting case: `%2e` is `.` and `%61` is `a`, and
     * both are byte-different from a canonical path that means the same thing.
     * Accepting them would give one document an unbounded number of URLs, which
     * is a cache-poisoning surface before it is anything else.
     */
    case PathNonCanonicalEscape = 'path.non_canonical_escape';

    /** The decoded path is not well-formed UTF-8. */
    case PathNotUtf8 = 'path.not_utf8';

    /**
     * 🛑 A non-final segment carrying a content extension —
     * `/guide.html/anything.css`.
     *
     * The web-cache-deception shape §9.3.2 names and the two real Read the Docs
     * advisories §3.3 records. A cache keyed on the trailing `.css` stores the
     * private HTML body that the application served for `guide.html`, and the
     * next anonymous request for that URL is handed someone else's private
     * page.
     *
     * Refused structurally rather than by checking whether the file exists,
     * because the check must precede the cache lookup and an existence check
     * cannot: it needs the manifest, which needs resolution. No documentation
     * generator emits a directory named `index.html`, so the cost of this rule
     * is nil and the alternative is a defence that runs too late to matter.
     */
    case PathSuffixConfusion = 'path.suffix_confusion';

    /** The path is longer than the edge will consider. */
    case PathTooLong = 'path.too_long';

    // ------------------------------------------------------- §8.9.3 host order

    /** The `Host` header is syntactically not a hostname. */
    case HostMalformed = 'host.malformed';

    /**
     * 🛑 No domain mount matched, and there is no default project to fall back
     * to (§8.9.3).
     *
     * §8.9.3: "It MUST NEVER fall through to a default project." A fall-through
     * would mean an unconfigured hostname pointed at this installation serves
     * somebody's documentation — which is how a dangling CNAME becomes a
     * subdomain takeover that serves real content.
     */
    case HostNotFound = 'host.not_found';

    /** The host resolved to a domain that is unverified or suspended (§8.10.6). */
    case HostNotServable = 'host.not_servable';

    /** A look-alike or confusable hostname (§8.10.7). */
    case HostConfusable = 'host.confusable';

    // --------------------------------------------------------- §7.3 path steps

    /** The host matched but no mount covers this path prefix. */
    case MountNotFound = 'mount.not_found';

    /** The project's `url_prefix` does not match the path. */
    case ProjectPrefixMismatch = 'project.prefix_mismatch';

    /** The version segment is absent or names no version of this project. */
    case VersionNotFound = 'version.not_found';

    /** The language segment names no language of this project. */
    case LanguageNotFound = 'language.not_found';

    /** The version resolved but has nothing published (§8.8.3). */
    case NothingPublished = 'version.not_published';

    /** The file is not in the published manifest (§8.4.18). */
    case FileNotFound = 'file.not_found';

    /** A reserved first segment used as a mount (§7.3). */
    case ReservedSegment = 'path.reserved_segment';

    /**
     * The HTTP status this reason answers with.
     *
     * 🛑 Asked of the reason rather than decided at the call site, so a reason
     * added later cannot default to the wrong one. The split matters: §8.9.6
     * requires **400** for a non-canonical path, because the request is
     * malformed and the answer must not depend on whether anything exists
     * there — a 404 would leak existence through timing and through the 404
     * chain's own behaviour.
     */
    public function status(): int
    {
        return match ($this) {
            self::PathNotAbsolute,
            self::PathEmptySegment,
            self::PathDotSegment,
            self::PathControlByte,
            self::PathBackslash,
            self::PathIllegalByte,
            self::PathNonCanonicalEscape,
            self::PathNotUtf8,
            self::PathSuffixConfusion,
            self::PathTooLong,
            self::HostMalformed => 400,

            self::HostNotFound,
            self::HostNotServable,
            self::HostConfusable,
            self::MountNotFound,
            self::ProjectPrefixMismatch,
            self::VersionNotFound,
            self::LanguageNotFound,
            self::NothingPublished,
            self::FileNotFound,
            self::ReservedSegment => 404,
        };
    }

    /**
     * Whether this rejection fired before resolution, i.e. before any cache
     * could have been consulted.
     *
     * 🛑 Exists so a test can assert §8.9.6's *position* rather than only its
     * outcome. The requirement says the rejection must happen "before any cache
     * lookup or resolution", and "its position in the pipeline is the whole of
     * its value" — a 400 returned after a cache lookup satisfies the status code
     * and none of the requirement.
     */
    public function precedesResolution(): bool
    {
        return $this->status() === 400;
    }
}
