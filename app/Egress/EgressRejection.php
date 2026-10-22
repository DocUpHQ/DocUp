<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Egress;

/**
 * Stable identifiers for every §8.3.9 refusal.
 *
 * 🛑 **Stable**, in the §8.19.15 sense that `App\Artifacts\RejectionCode`
 * already establishes: these strings reach operator alerts, the API and
 * runbooks, so they are added to and never edited.
 *
 * 🛑 **Distinct**, because Phase 05's exit criteria require it and because a
 * single `egress.denied` would be actively harmful. The five vectors the phase
 * must refuse — an `ext::` transport, a `file://` URL, the cloud metadata
 * address, a DNS-rebind target and a redirect into private space — are five
 * different controls. Collapsing them into one identifier would let four of
 * them rot undetected behind the one that still works, and the test that
 * asserted "it was refused" would stay green throughout.
 */
enum EgressRejection: string
{
    // ----------------------------------------------------------- URL shape

    /** The URL did not parse, or carried no host. */
    case MalformedUrl = 'egress.malformed_url';

    /** A scheme outside the allowlist. `file:`, `gopher:`, `dict:`, `ext:`. */
    case SchemeNotAllowed = 'egress.scheme_not_allowed';

    /**
     * `https://user:token@host/` — userinfo in the URL.
     *
     * Refused rather than stripped. A credential in a URL is written to every
     * proxy log, every `Referer` and every exception trace between here and the
     * origin, and §8.3.3 forbids a credential leaving storage by any route but
     * the one that was designed for it. Stripping it silently would also hide
     * from the operator that they pasted a token into a field that stores its
     * contents in plain text.
     */
    case CredentialsInUrl = 'egress.credentials_in_url';

    /** A port outside the allowlist. */
    case PortNotAllowed = 'egress.port_not_allowed';

    // -------------------------------------------------------------- naming

    /** The host has no address records, or resolution failed. */
    case HostNotResolvable = 'egress.host_not_resolvable';

    /**
     * 🛑 The resolver returned a **different** address set on re-resolution.
     *
     * This is the rebind control, and it is separate from the address controls
     * below on purpose. Resolve-then-pin already makes the second answer
     * unusable — we connect to the address we validated. But a name whose
     * answer changes between two lookups milliseconds apart is either hostile
     * or broken, and in both cases we want the *name* refused rather than a
     * request quietly served from the first address. A TTL of 0 is the setup
     * for this attack and is recorded on the rejection, but the detection does
     * not depend on the TTL: a hostile resolver is free to lie about it.
     */
    case DnsRebindDetected = 'egress.dns_rebind_detected';

    // ---------------------------------------------------- address controls

    case LoopbackAddressDenied = 'egress.loopback_address_denied';
    case PrivateAddressDenied = 'egress.private_address_denied';
    case LinkLocalAddressDenied = 'egress.link_local_address_denied';
    case MetadataAddressDenied = 'egress.metadata_address_denied';
    case UniqueLocalAddressDenied = 'egress.unique_local_address_denied';
    case UnspecifiedAddressDenied = 'egress.unspecified_address_denied';
    case ReservedAddressDenied = 'egress.reserved_address_denied';

    // -------------------------------------------------------------- answer

    /**
     * A 3xx with a `Location`.
     *
     * 🛑 Refused on the **status**, before the target is examined. §8.3.9 says
     * "disabled redirects", and the reason the check is not "follow it and
     * re-run the address policy" is that re-validation after the fact is the
     * exact shape of every SSRF bypass ever written: the second request is made
     * by a layer that has forgotten the first one's constraints. The target is
     * recorded for the operator's benefit and is never fetched.
     */
    case RedirectRefused = 'egress.redirect_refused';

    /** The body exceeded the §8.3.9 cap and the transfer was aborted mid-flight. */
    case ResponseTooLarge = 'egress.response_too_large';

    /** The §8.3.9 timeout elapsed. */
    case Timeout = 'egress.timeout';

    /** Connection refused, TLS failure, or anything else the transport reports. */
    case TransportFailure = 'egress.transport_failure';

    /** A short operator-facing sentence. UI strings live in message files (§9.4). */
    public function reason(): string
    {
        return match ($this) {
            self::MalformedUrl => 'the URL could not be parsed or named no host',
            self::SchemeNotAllowed => 'the URL scheme is not in the egress allowlist',
            self::CredentialsInUrl => 'the URL embedded a credential',
            self::PortNotAllowed => 'the port is not in the egress allowlist',
            self::HostNotResolvable => 'the host has no address records',
            self::DnsRebindDetected => 'the host resolved to a different address set on re-resolution',
            self::LoopbackAddressDenied => 'the host resolved to a loopback address',
            self::PrivateAddressDenied => 'the host resolved to a private address',
            self::LinkLocalAddressDenied => 'the host resolved to a link-local address',
            self::MetadataAddressDenied => 'the host resolved to a cloud metadata address',
            self::UniqueLocalAddressDenied => 'the host resolved to a unique local address',
            self::UnspecifiedAddressDenied => 'the host resolved to the unspecified address',
            self::ReservedAddressDenied => 'the host resolved to a reserved address',
            self::RedirectRefused => 'the response was a redirect, which egress never follows',
            self::ResponseTooLarge => 'the response exceeded the egress size cap',
            self::Timeout => 'the request exceeded the egress timeout',
            self::TransportFailure => 'the request could not be completed',
        };
    }
}
