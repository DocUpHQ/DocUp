<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Source;

use App\Egress\AddressClass;
use App\Egress\EgressRejection;

/**
 * Stable identifiers for every §8.3.4 refusal of a repository URL.
 *
 * 🛑 Phase 05's exit criteria name five vectors and require them to be refused
 * **with distinct errors**: `ext::sh -c id`, `file:///etc/passwd`, a
 * `169.254.169.254` host, a TTL-0 DNS-rebind target and an HTTP redirect to a
 * private address. The distinctness is the requirement, not a nicety. One
 * generic `git_url.rejected` would satisfy a careless test while hiding which
 * of five independent controls actually fired — and the day one of them
 * regresses, the suite stays green because another one caught the input.
 *
 * These are a separate vocabulary from `App\Egress\EgressRejection` even where
 * they share an implementation, because they are read by different people. An
 * author pasting a repository URL into the dashboard needs to be told what is
 * wrong with **their URL**; an operator reading an egress audit line needs to
 * be told what the outbound policy refused. {@see fromEgress()} is the one
 * place the two are mapped, so the implementation stays single.
 */
enum SourceRejection: string
{
    // ------------------------------------------------------ transport shape

    /**
     * 🛑 `ext::sh -c id` — git's remote-helper syntax, and remote code
     * execution.
     *
     * `<transport>::<address>` tells git to run `git-remote-<transport>`.
     * `ext` runs the rest of the line as a **shell command**, as the author of
     * the repository URL field, not of the repository. This is why §8.3.4
     * requires `protocol.allow=never` with explicit per-protocol allowances
     * rather than a deny list: a deny list has to know every helper name, and
     * git ships new ones.
     */
    case RemoteHelperForbidden = 'git_url.remote_helper_forbidden';

    /**
     * 🛑 `file:///etc/passwd`, and any bare local path.
     *
     * Local file disclosure. A `file://` clone copies whatever the fetch
     * process can read into a repository the author can then publish, and the
     * fetch process runs as DocUp. Distinct from the helper case above because
     * the two are different capabilities — one is execution, one is
     * disclosure — and an operator triaging an alert needs to know which.
     */
    case LocalPathForbidden = 'git_url.local_path_forbidden';

    /** `git://`, `http://`, `ftp://` — anything but `https://` and `ssh://` (§8.3.4). */
    case SchemeNotAllowed = 'git_url.scheme_not_allowed';

    /** The URL would not parse, or named no host. */
    case Malformed = 'git_url.malformed';

    /**
     * `https://user:token@host/repo.git`.
     *
     * Refused, not stripped: §8.3.3 keeps credentials in the vault, and
     * §8.5.7 supplies them to git through a file descriptor precisely so they
     * never appear in a remote URL. A token pasted here is already in the
     * operator's shell history and will be in every proxy log the clone
     * traverses, so the right answer is to tell them, not to quietly tidy it.
     */
    case CredentialsInUrl = 'git_url.credentials_in_url';

    /** A non-ASCII host. Punycode is accepted; §8.10.7's confusable rules are Phase 18. */
    case NonAsciiHost = 'git_url.non_ascii_host';

    /** A port outside the allowlist, where the operator has configured one. */
    case PortNotAllowed = 'git_url.port_not_allowed';

    // ----------------------------------------------------- address controls

    case HostNotResolvable = 'git_url.host_not_resolvable';
    case LoopbackAddressDenied = 'git_url.loopback_address_denied';
    case PrivateAddressDenied = 'git_url.private_address_denied';
    case LinkLocalAddressDenied = 'git_url.link_local_address_denied';

    /** 🛑 `169.254.169.254`. Its own identifier; see {@see AddressClass::Metadata}. */
    case MetadataAddressDenied = 'git_url.metadata_address_denied';

    case UniqueLocalAddressDenied = 'git_url.unique_local_address_denied';
    case UnspecifiedAddressDenied = 'git_url.unspecified_address_denied';
    case ReservedAddressDenied = 'git_url.reserved_address_denied';

    /** 🛑 A TTL-0 name that answers publicly once and privately the next time. */
    case DnsRebindDetected = 'git_url.dns_rebind_detected';

    /** 🛑 A 3xx during the reachability probe. §8.3.4: redirects are disabled. */
    case RedirectRefused = 'git_url.redirect_refused';

    /** The probe timed out, the TLS handshake failed, or the host refused the connection. */
    case Unreachable = 'git_url.unreachable';

    /** The probe's answer exceeded the §8.3.9 cap. */
    case ResponseTooLarge = 'git_url.response_too_large';

    // -------------------------------------------------------- git behaviour

    /**
     * 🛑 §8.3.5: submodules are cloned **non-recursively and only on explicit
     * per-repository opt-in** (CVE-2025-48384, CVE-2023-22490).
     */
    case SubmoduleRecursionForbidden = 'git_url.submodule_recursion_forbidden';

    /**
     * The one place the egress vocabulary is translated into this one.
     *
     * Exhaustive by construction: a new `EgressRejection` case that nobody
     * maps here fails to compile the match, which is the point.
     */
    public static function fromEgress(EgressRejection $rejection): self
    {
        return match ($rejection) {
            EgressRejection::MalformedUrl => self::Malformed,
            EgressRejection::SchemeNotAllowed => self::SchemeNotAllowed,
            EgressRejection::CredentialsInUrl => self::CredentialsInUrl,
            EgressRejection::PortNotAllowed => self::PortNotAllowed,
            EgressRejection::HostNotResolvable => self::HostNotResolvable,
            EgressRejection::DnsRebindDetected => self::DnsRebindDetected,
            EgressRejection::LoopbackAddressDenied => self::LoopbackAddressDenied,
            EgressRejection::PrivateAddressDenied => self::PrivateAddressDenied,
            EgressRejection::LinkLocalAddressDenied => self::LinkLocalAddressDenied,
            EgressRejection::MetadataAddressDenied => self::MetadataAddressDenied,
            EgressRejection::UniqueLocalAddressDenied => self::UniqueLocalAddressDenied,
            EgressRejection::UnspecifiedAddressDenied => self::UnspecifiedAddressDenied,
            EgressRejection::ReservedAddressDenied => self::ReservedAddressDenied,
            EgressRejection::RedirectRefused => self::RedirectRefused,
            EgressRejection::ResponseTooLarge => self::ResponseTooLarge,
            EgressRejection::Timeout, EgressRejection::TransportFailure => self::Unreachable,
        };
    }
}
