<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Egress;

/**
 * The one outbound HTTP client (§8.3.9).
 *
 * > "The system MUST route every outbound request derived from user-supplied
 * > configuration — repository probing, OIDC discovery, JWKS, SAML metadata,
 * > LDAP hosts, outgoing webhooks — through **one** `HardenedEgressClient`
 * > with a scheme allowlist, resolve-then-pin connection, disabled redirects,
 * > denial of private/loopback/link-local/metadata addresses, a 5-second
 * > timeout and a 256 KiB response cap. One class, sole call site,
 * > architecture-tested."
 *
 * 🛑 The reason the specification asks for one class rather than a convention
 * is the same reason §8.8.2 asks it of `ArtifactIngestor`: a second outbound
 * path is not a duplication bug but an **unvalidated** one. It gets written in
 * a hurry, for a webhook or an avatar fetch, by somebody who did not know this
 * class existed — and it is the one the attacker uses. The architecture test
 * that proves no such path exists is in `tests/Arch/ArchitectureTest.php`.
 *
 * The order of the checks below is itself load-bearing, and it is the order
 * §8.3.9 lists them in:
 *
 *   1. parse, and refuse a URL that embeds a credential;
 *   2. scheme, then port, from the allowlist;
 *   3. resolve, classify **every** address, detect rebinding, pin;
 *   4. connect to the pinned address with the original `Host`;
 *   5. refuse a 3xx rather than following it;
 *   6. stop at the byte cap, mid-transfer.
 *
 * Nothing after step 3 can reach an address step 3 refused, and nothing in
 * step 5 ever becomes a second request.
 */
final readonly class HardenedEgressClient
{
    public function __construct(
        private AddressGuard $guard,
        private Transport $transport,
        private EgressOptions $options,
    ) {}

    /**
     * @param  array<string, string>  $headers
     *
     * @throws EgressRefused
     */
    public function get(string $url, array $headers = []): EgressResponse
    {
        return $this->request('GET', $url, $headers);
    }

    /**
     * @param  array<string, string>  $headers
     *
     * @throws EgressRefused
     */
    public function head(string $url, array $headers = []): EgressResponse
    {
        return $this->request('HEAD', $url, $headers);
    }

    /**
     * @param  array<string, string>  $headers
     *
     * @throws EgressRefused
     */
    public function request(string $method, string $url, array $headers = []): EgressResponse
    {
        $parts = $this->parse($url);

        $scheme = strtolower((string) ($parts['scheme'] ?? ''));
        $host = (string) ($parts['host'] ?? '');

        /*
         * 🛑 Before the scheme check, because a URL carrying a credential is a
         * finding whatever its scheme is, and reporting "bad scheme" for
         * `ftp://user:token@host` would tell the operator to fix the wrong
         * half of a line that has just leaked a token into their clipboard.
         */
        if (isset($parts['user']) || isset($parts['pass'])) {
            throw new EgressRefused(EgressRejection::CredentialsInUrl, $host === '' ? null : $host);
        }

        /*
         * 🛑 Before the empty-host check, and the ordering is the same lesson
         * `RepositoryUrl::parse()` records. `file:///etc/passwd` parses to a
         * scheme and a path with **no host**, so a host check placed first
         * reports `malformed_url` — which refuses the input and loses the
         * finding. The operator is then told to fix a typo rather than that
         * something asked the application to read the local disk.
         */
        if (! $this->options->permitsScheme($scheme)) {
            throw new EgressRefused(
                EgressRejection::SchemeNotAllowed,
                $host === '' ? null : $host,
                ['scheme' => $scheme],
            );
        }

        if ($host === '') {
            throw new EgressRefused(EgressRejection::MalformedUrl);
        }

        $port = isset($parts['port']) ? (int) $parts['port'] : $this->defaultPort($scheme);

        if (! $this->options->permitsPort($port)) {
            throw new EgressRefused(EgressRejection::PortNotAllowed, $host, ['port' => $port]);
        }

        $inspection = $this->guard->inspect($host, $this->options->enforceAddressPolicy);

        if ($inspection->rejection !== null) {
            throw new EgressRefused($inspection->rejection, $host, $inspection->context());
        }

        $response = $this->transport->send(
            $method,
            $url,
            $this->hostForPin($host),
            $port,
            (string) $inspection->pinnedAddress,
            $headers,
            $this->options,
        );

        if ($response->status >= 300 && $response->status < 400 && $response->header('location') !== null) {
            /*
             * 🛑 The target is recorded and never fetched. §8.3.9 says
             * redirects are disabled, and the reason it is a refusal rather
             * than "follow it and re-check" is that re-validation after the
             * fact is the shape of every SSRF bypass: the second request is
             * made by a layer that has forgotten the first one's constraints.
             *
             * `location` is recorded as the host only. The full Location is
             * attacker-controlled and heads for a log.
             */
            throw new EgressRefused(EgressRejection::RedirectRefused, $host, [
                'status' => $response->status,
                'location_host' => $this->hostOf((string) $response->header('location')),
            ]);
        }

        return $response;
    }

    /**
     * @return array<string, int|string>
     *
     * @throws EgressRefused
     */
    private function parse(string $url): array
    {
        /*
         * A control character or whitespace anywhere in the URL is refused
         * before parsing. `parse_url` tolerates several of them and PHP's own
         * HTTP stack has historically disagreed with it about where the host
         * ends — which is request smuggling, with the attacker choosing the
         * host.
         */
        if (preg_match('/[\x00-\x20\x7f]/', $url) === 1) {
            throw new EgressRefused(EgressRejection::MalformedUrl);
        }

        $parts = parse_url($url);

        if ($parts === false || ! isset($parts['scheme'])) {
            throw new EgressRefused(EgressRejection::MalformedUrl);
        }

        return $parts;
    }

    private function defaultPort(string $scheme): int
    {
        return $scheme === 'http' ? 80 : 443;
    }

    /** `CURLOPT_RESOLVE` wants the IPv6 host bracketed, exactly as the URL has it. */
    private function hostForPin(string $host): string
    {
        return str_contains($host, ':') && ! str_starts_with($host, '[') ? '['.$host.']' : $host;
    }

    /** The host of an untrusted `Location`, or null when it has none. */
    private function hostOf(string $location): ?string
    {
        $host = parse_url($location, PHP_URL_HOST);

        return is_string($host) ? $host : null;
    }
}
