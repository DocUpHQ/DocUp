<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Tls;

use App\Domains\Hostname;

/**
 * 🛑 §8.10.12's validation, which exists to prevent one unrecoverable
 * configuration.
 *
 * > "The permission endpoint's own URL MUST NOT be HTTPS on any hostname the
 * > installation serves. That configuration is a startup deadlock and MUST
 * > be a validation error."
 *
 * **The deadlock, spelled out**, because "startup deadlock" understates it.
 * The proxy cannot complete a handshake for a hostname until it holds a
 * certificate for it. It cannot obtain one until the permission endpoint
 * answers. If the endpoint is HTTPS on a hostname this installation serves,
 * reaching it requires completing a handshake for that hostname — which
 * requires a certificate — which requires the endpoint. Nothing resolves it
 * from inside: the installation comes up with no TLS on any hostname, and
 * the only symptom is handshake failures with nothing in any log explaining
 * why, because the request that would have been logged never arrives.
 *
 * 🛑 **Refused at validation, not discovered at first handshake**, which is
 * exactly what §19's exit criterion asks for. The check runs at boot, so the
 * installation refuses to start rather than starting into a state it cannot
 * leave.
 */
final class PermissionEndpoint
{
    /**
     * @throws CertificateRefused when the configured endpoint is a deadlock
     */
    public static function assertUsable(string $url): void
    {
        $parts = parse_url($url);

        if ($parts === false || ! isset($parts['scheme'], $parts['host'])) {
            throw CertificateRefused::of(
                CertificateRejection::PermissionEndpointDeadlock,
                'the permission endpoint is not a URL: '.$url,
            );
        }

        if (strtolower((string) $parts['scheme']) !== 'https') {
            return;
        }

        $host = self::normalise((string) $parts['host']);

        /*
         * 🛑 Loopback is the one HTTPS form that is not a deadlock, because
         * the proxy reaches it without SNI resolution and without a
         * certificate this installation had to obtain. It is still a
         * needless round trip through TLS to the same process, which is why
         * §8.10.11 says "plaintext" — but it is not the unrecoverable
         * configuration this check exists for, and refusing it would be
         * refusing something that works.
         */
        if (self::isLoopback($host)) {
            return;
        }

        /*
         * 🛑 The test is "a hostname the installation serves", which is
         * wider than "equals the docs apex": a name **under** a served apex
         * is served too, by the wildcard, and would deadlock identically.
         */
        if (WildcardZones::covers($host)) {
            throw CertificateRefused::of(
                CertificateRejection::PermissionEndpointDeadlock,
                'https://'.$host.' is a hostname this installation serves; the proxy cannot reach it before it has a certificate, and it cannot have one before this endpoint answers',
            );
        }
    }

    /** Whether the configured endpoint is usable, without throwing. */
    public static function usable(string $url): bool
    {
        try {
            self::assertUsable($url);

            return true;
        } catch (CertificateRefused) {
            return false;
        }
    }

    private static function normalise(string $host): string
    {
        try {
            return Hostname::normalise($host);
        } catch (\Throwable) {
            return strtolower(trim($host, '.[]'));
        }
    }

    private static function isLoopback(string $host): bool
    {
        if ($host === 'localhost') {
            return true;
        }

        $packed = @inet_pton($host);

        if ($packed === false) {
            return false;
        }

        return str_starts_with($host, '127.') || $packed === inet_pton('::1');
    }
}
