<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Support;

/**
 * The origin separation invariant (SPEC 8.1.4, 8.1.5).
 *
 * 🛑 Built documentation is attacker-controlled HTML and JavaScript by design:
 * Sphinx evaluates conf.py as Python and build.commands is a shell. On a shared
 * registrable domain that JavaScript can toss cookies at the dashboard,
 * Clear-Site-Data spans every tenant on the domain, and Laravel's TrustHosts
 * default trusts subdomains of APP_URL. There is no safe configuration in that
 * shape, so the application refuses to boot rather than pretend.
 *
 * The sole exception is DOCUP_UNSAFE_SINGLE_ORIGIN (SPEC 8.1.5), which trades
 * the invariant for a mechanically degraded mode: every project forced public,
 * private sharing and tenant CSS disabled, and an audited acknowledgement.
 * A hard refusal with no escape hatch loses the evaluator and invites operators
 * to patch the check out of the source, which is strictly worse.
 */
final class Origins
{
    /**
     * Multi-label public suffixes that a naive "last two labels" rule gets wrong.
     *
     * This is a deliberately small list, not a Public Suffix List implementation.
     * Getting it wrong is safe in one direction only: treating two genuinely
     * different registrable domains as the same would refuse a valid boot
     * (annoying, visible, reported), whereas treating one domain as two would
     * silently permit the shared-origin shape this class exists to prevent. The
     * list therefore errs toward finding MORE separation-relevant labels.
     *
     * `docup:doctor` reports when a configured host's suffix is not covered here,
     * so the gap is surfaced rather than assumed away.
     *
     * @var list<string>
     */
    private const MULTI_LABEL_SUFFIXES = [
        'co.uk', 'org.uk', 'me.uk', 'ac.uk', 'gov.uk', 'net.uk', 'sch.uk',
        'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
        'co.nz', 'net.nz', 'org.nz', 'govt.nz',
        'co.za', 'org.za', 'net.za',
        'com.br', 'com.mx', 'com.ar', 'com.sg', 'com.hk', 'com.tr', 'com.cn',
        'co.jp', 'or.jp', 'ne.jp', 'go.jp',
        'co.in', 'net.in', 'org.in', 'gov.in',
        'github.io', 'gitlab.io', 'pages.dev', 'workers.dev', 'netlify.app',
        'vercel.app', 'readthedocs.io', 'readthedocs.build',
    ];

    /**
     * The registrable domain (eTLD+1) for a host.
     *
     * Returns the host unchanged when it has too few labels to reduce, which
     * covers `localhost` and bare container names in development.
     */
    public static function registrable(string $host): string
    {
        $host = self::normalise($host);

        if ($host === '' || filter_var($host, FILTER_VALIDATE_IP) !== false) {
            return $host;
        }

        $labels = explode('.', $host);
        $count = count($labels);

        if ($count < 2) {
            return $host;
        }

        $lastTwo = implode('.', array_slice($labels, -2));

        if (in_array($lastTwo, self::MULTI_LABEL_SUFFIXES, true) && $count >= 3) {
            return implode('.', array_slice($labels, -3));
        }

        return $lastTwo;
    }

    /** Lowercase, strip any scheme, port, path, userinfo and trailing dot. */
    public static function normalise(string $host): string
    {
        $host = trim($host);

        if (str_contains($host, '//')) {
            $host = (string) parse_url($host, PHP_URL_HOST);
        }

        $host = strtolower($host);
        $host = preg_replace('#[/?].*$#', '', $host) ?? $host;
        $host = preg_replace('#^.*@#', '', $host) ?? $host;
        $host = preg_replace('#:\d+$#', '', $host) ?? $host;

        return rtrim($host, '.');
    }

    public static function shareRegistrableDomain(string $a, string $b): bool
    {
        $a = self::registrable($a);
        $b = self::registrable($b);

        return $a !== '' && $a === $b;
    }

    /**
     * Assert the invariant, or throw.
     *
     * @throws \RuntimeException when the dashboard and documentation origins share
     *                           a registrable domain and the unsafe flag is unset
     */
    public static function assert(?string $app, ?string $docs, ?string $preview, bool $unsafeSingleOrigin): void
    {
        if ($unsafeSingleOrigin) {
            return;   // SPEC 8.1.5: degraded mode, asserted elsewhere and audited
        }

        if ($app === null || $app === '' || $docs === null || $docs === '') {
            throw new \RuntimeException(
                'DOCUP_APP_HOST and DOCUP_DOCS_APEX must both be set (SPEC 8.1.4). '
                .'Set DOCUP_UNSAFE_SINGLE_ORIGIN=true only if you accept the degraded, '
                .'public-only mode described in SPEC 8.1.5.'
            );
        }

        if (self::shareRegistrableDomain($app, $docs)) {
            throw new \RuntimeException(sprintf(
                'The dashboard (%s) and documentation (%s) origins share the registrable '
                .'domain "%s". Built documentation is attacker-controlled JavaScript, so a '
                .'shared registrable domain lets it reach the dashboard session (SPEC 8.1.4). '
                .'Use two distinct registrable domains, or set '
                .'DOCUP_UNSAFE_SINGLE_ORIGIN=true to accept the degraded public-only mode '
                .'(SPEC 8.1.5).',
                self::normalise($app),
                self::normalise($docs),
                self::registrable($app),
            ));
        }

        // Previews are optional: SPEC 8.1.4 says they auto-disable rather than
        // fail when unconfigured. But a preview origin that collides is a
        // misconfiguration, not a degradation, so it is still fatal.
        if ($preview !== null && $preview !== '') {
            foreach (['dashboard' => $app, 'documentation' => $docs] as $label => $other) {
                if (self::shareRegistrableDomain($preview, $other)) {
                    throw new \RuntimeException(sprintf(
                        'The pull-request preview origin (%s) shares the registrable domain '
                        .'"%s" with the %s origin. Previews serve untrusted fork output and '
                        .'need their own registrable domain (SPEC 8.1.4, 8.20.1). Unset '
                        .'DOCUP_PREVIEW_APEX to disable previews instead.',
                        self::normalise($preview),
                        self::registrable($preview),
                        $label,
                    ));
                }
            }
        }
    }

    /** True when previews are available: a third distinct registrable domain. */
    public static function previewsEnabled(): bool
    {
        $preview = config('docup.origins.preview');

        return is_string($preview) && $preview !== '';
    }
}
