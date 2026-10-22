<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Serving;

/**
 * §8.9.3's host resolution order, decided purely.
 *
 * §8.9.3: "Host resolution order MUST be: exact verified custom domain →
 * single-label default subdomain → preview host (split on the **last** `--`) →
 * look-alike rejection → **hard 404**. 🛑 It MUST NEVER fall through to a
 * default project."
 *
 * 🛑 §8.9.4 is why this class takes a hostname and nothing else: "The project
 * MUST be resolved **solely** from the TLS server name or `Host` header plus
 * the path. No request header MUST act as a project, version or tenant
 * selector, in any environment. This is the GHSA-mp38-vprc-7hf5 class." A
 * matcher that could read a header would be one `if` away from that advisory,
 * so it cannot see one.
 *
 * **On "look-alike rejection".** It is not a separate pass here, and that is
 * deliberate rather than an omission. The three matching rules are each exact —
 * an exact hostname, exactly one label under the apex, exactly the preview apex
 * — so a look-alike produces no candidate and falls to the hard 404 by
 * construction. Corpus case `host-001`, `docs.example.com.evil.net`, does not
 * end with the apex; `host-002`, `evildocs.example.com`, is a single label and
 * therefore a *legitimate* question whose answer is "no such project". The
 * confusable rejection §8.10.7 asks for — mixed-script homoglyphs, corpus
 * `host-004` and `host-005` — is a save-time check in Phase 18, because a
 * homoglyph host must never become a row, not merely fail to resolve.
 */
final class HostMatcher
{
    /** The longest a DNS name can be. Anything longer is not a hostname. */
    private const MAX_HOST_BYTES = 253;

    /**
     * Every way this hostname could resolve, in §8.9.3's order.
     *
     * @param  string  $host  the `Host` header or TLS server name, as it arrived
     * @param  string|null  $docsApex  `DOCUP_DOCS_APEX`, or null when unset
     * @param  string|null  $previewApex  `DOCUP_PREVIEW_APEX`, or null when unset
     * @return list<HostCandidate> empty when the hostname is malformed or
     *                             matches nothing — never a default
     */
    public static function candidates(string $host, ?string $docsApex, ?string $previewApex): array
    {
        $host = self::normalise($host);

        if ($host === null) {
            return [];
        }

        /*
         * Always a candidate, and always first. A verified custom domain
         * outranks every pattern match, because somebody proved control of it
         * (§8.10.4) and proof beats shape.
         *
         * It is offered even when the host sits under the documentation apex:
         * an operator may legitimately verify `docs.example.com` as a custom
         * domain on an installation whose apex is `example.com`, and refusing
         * to look would make that configuration unserveable for no reason.
         */
        $candidates = [new HostCandidate(HostKind::Custom, $host)];

        $subdomain = self::singleLabelUnder($host, $docsApex);

        if ($subdomain !== null) {
            $candidates[] = new HostCandidate(HostKind::DefaultSubdomain, $host, projectSlug: $subdomain);
        }

        $preview = self::singleLabelUnder($host, $previewApex);

        if ($preview !== null) {
            [$projectSlug, $versionSlug] = self::splitPreviewLabel($preview);

            if ($versionSlug !== null) {
                $candidates[] = new HostCandidate(
                    HostKind::Preview,
                    $host,
                    projectSlug: $projectSlug,
                    versionSlug: $versionSlug,
                );
            }
        }

        return $candidates;
    }

    /**
     * Lowercase the hostname, drop a port and a single trailing dot, and refuse
     * anything that is not a hostname.
     *
     * Returns null rather than throwing, because a malformed `Host` is an
     * ordinary hostile request and §8.9.3 answers it with a status, not an
     * exception.
     */
    public static function normalise(string $host): ?string
    {
        /*
         * A port is not part of the name, and it arrives on a `Host` header for
         * any non-default port — including in every local development setup.
         *
         * 🛑 Stripped only when what follows the colon is actually a port.
         * An earlier version took everything before the first colon
         * unconditionally, which turned `Host: https://evil.com` into the
         * perfectly valid hostname `https`. Nothing is called `https`, so it
         * resolved to a 404 and looked fine — but a parser that silently
         * extracts a different name from a malformed header is one rule change
         * away from extracting a useful one. A malformed `Host` must be
         * malformed, not reinterpreted.
         */
        $colon = strpos($host, ':');

        if ($colon !== false) {
            $port = substr($host, $colon + 1);

            if ($port === '' || preg_match('/^[0-9]{1,5}$/', $port) !== 1) {
                return null;
            }

            $host = substr($host, 0, $colon);
        }

        // The root label. `example.com.` and `example.com` are the same name,
        // and accepting both spellings without normalising would make them two
        // cache keys.
        $host = rtrim($host, '.');
        $host = strtolower($host);

        if ($host === '' || strlen($host) > self::MAX_HOST_BYTES) {
            return null;
        }

        /*
         * 🛑 A-labels only: letters, digits, hyphen and dot. A hostname
         * reaching here is already punycode, because that is what a resolver
         * and a TLS handshake carry — so a raw non-ASCII byte is not an
         * internationalised domain name, it is something trying to be compared
         * under a different normalisation than the one `domains.host` stores
         * (that column is `ascii_bin` for the same reason).
         *
         * No label may be empty or start or end with a hyphen, which also
         * refuses the `..` and leading-dot shapes.
         */
        if (preg_match('/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/', $host) !== 1) {
            return null;
        }

        foreach (explode('.', $host) as $label) {
            if (strlen($label) > 63) {
                return null;
            }
        }

        return $host;
    }

    /**
     * The single label under an apex, or null.
     *
     * 🛑 **Single**, which is the whole of the check. `a.b.docs.example.com`
     * must not resolve as project `a.b`, because a wildcard certificate covers
     * one label and a nested name is either a misconfiguration or somebody
     * probing for one. Corpus case `host-002` is the same rule from the other
     * side: `evildocs.example.com` IS a single label, so it is a legitimate
     * question — and the answer is that no project is called `evildocs`.
     */
    private static function singleLabelUnder(string $host, ?string $apex): ?string
    {
        if ($apex === null) {
            return null;
        }

        $apex = self::normalise($apex);

        if ($apex === null) {
            return null;
        }

        $suffix = '.'.$apex;

        if (! str_ends_with($host, $suffix)) {
            return null;
        }

        $label = substr($host, 0, -strlen($suffix));

        if ($label === '' || str_contains($label, '.')) {
            return null;
        }

        return $label;
    }

    /**
     * Split a preview label into project and version on the **last** `--`.
     *
     * 🛑 The last, not the first, and corpus case `host-006` exists to hold
     * this: `project--version--extra` is project `project--version` and version
     * `extra`. Splitting on the first `--` would give project `project` and
     * version `version--extra`, which resolves to a different project — so a
     * repository whose name contains `--` would have its previews served from
     * somebody else's documentation. Version slugs are generated by §8.6.6's
     * function from a ref name, so they are the component that cannot be
     * chosen to contain a separator; project slugs are chosen by people.
     *
     * @return array{0: string, 1: string|null} project slug, version slug
     */
    private static function splitPreviewLabel(string $label): array
    {
        $at = strrpos($label, '--');

        if ($at === false || $at === 0) {
            // No separator, or nothing before it. Not a preview host.
            return [$label, null];
        }

        $version = substr($label, $at + 2);

        if ($version === '') {
            return [$label, null];
        }

        return [substr($label, 0, $at), $version];
    }
}
