<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Egress;

/**
 * One outbound TLS handshake, for §8.10.17's prober.
 *
 * 🛑 **Why this lives in `App\Egress` and not in `App\Tls`.** §8.3.9 and
 * `ArchitectureTest::test_only_the_egress_namespace_makes_outbound_requests`
 * say that only this namespace opens a connection that leaves the host, and
 * a probe is such a connection. Putting it anywhere else would mean either
 * a second outbound path — "not a duplication bug but an **unvalidated**
 * one" — or an architecture test weakened to admit it. So it sits beside
 * {@see HardenedEgressClient}, shares {@see AddressGuard}, and gets the same
 * resolve-then-pin treatment.
 *
 * It is not the HTTP client because it wants the one thing that client
 * deliberately hides: the peer's certificate. §8.10.17 asks for "expiry,
 * issuer and error", and none of those are in a response body.
 *
 * 🛑 **Two passes, and the second is what makes the result useful.** A
 * verifying handshake answers "trusted" or "not trusted" and nothing else,
 * so an expired certificate and a certificate for the wrong name produce
 * the same opaque OpenSSL error. The second pass connects without
 * verification purely to read what was actually served, so the record says
 * "expired four days ago" rather than "certificate verify failed" — the
 * difference between an operator who knows what to fix and one who has to
 * reach for `openssl s_client`. The second pass never decides anything: a
 * host that failed the first pass is reported as failed, whatever the
 * second pass saw.
 */
final readonly class TlsHandshakeProbe implements TlsHandshake
{
    public function __construct(
        private AddressGuard $guard,
        private int $timeoutSeconds = 5,
    ) {}

    /**
     * Handshake with a hostname and report what it presented.
     *
     * @return array{trusted: bool, error: string|null, certificate: array<array-key, mixed>|null}
     */
    public function probe(string $host, int $port = 443): array
    {
        $inspection = $this->guard->inspect($host);

        if ($inspection->rejection !== null) {
            return ['trusted' => false, 'error' => $inspection->rejection->value, 'certificate' => null];
        }

        $address = (string) $inspection->pinnedAddress;

        [$trusted, $error] = $this->connect($host, $address, $port, verify: true);

        /*
         * The observing pass runs either way. On success it is where the
         * expiry and issuer come from; on failure it is the diagnosis. Its
         * own failure is not reported — the first pass has already said
         * what happened.
         */
        [, , $certificate] = $this->connect($host, $address, $port, verify: false);

        return ['trusted' => $trusted, 'error' => $error, 'certificate' => $this->parse($certificate)];
    }

    /**
     * @return array{0: bool, 1: string|null, 2: \OpenSSLCertificate|null}
     */
    private function connect(string $host, string $address, int $port, bool $verify): array
    {
        $context = stream_context_create(['ssl' => [
            /*
             * 🛑 `peer_name` is the hostname and the connection goes to the
             * pinned address, exactly as `PinnedCurlTransport` does it with
             * `CURLOPT_RESOLVE`. Connecting to the hostname instead would
             * resolve a second time, which is the rebinding window the
             * guard exists to close.
             */
            'peer_name' => $host,
            'verify_peer' => $verify,
            'verify_peer_name' => $verify,
            'capture_peer_cert' => true,
            'SNI_enabled' => true,
            'allow_self_signed' => false,
            'disable_compression' => true,
        ]]);

        $errno = 0;
        $error = '';

        $socket = @stream_socket_client(
            'ssl://'.$this->bracket($address).':'.$port,
            $errno,
            $error,
            $this->timeoutSeconds,
            STREAM_CLIENT_CONNECT,
            $context,
        );

        /*
         * 🛑 Read from the context, not the socket, and read it whether or
         * not the connection succeeded. `stream_context_get_options` is the
         * only way PHP surfaces a captured peer certificate, and on a
         * verification failure the socket is already false while the
         * certificate is sitting in the context — which is precisely the
         * case the observing pass exists for.
         */
        $captured = stream_context_get_options($context)['ssl']['peer_certificate'] ?? null;
        $certificate = $captured instanceof \OpenSSLCertificate ? $captured : null;

        if ($socket === false) {
            $reported = (string) $error;

            return [false, self::tidy($reported !== '' ? $reported : 'connection failed ('.$errno.')'), $certificate];
        }

        fclose($socket);

        return [true, null, $certificate];
    }

    /**
     * @return array<array-key, mixed>|null
     */
    private function parse(?\OpenSSLCertificate $certificate): ?array
    {
        if ($certificate === null) {
            return null;
        }

        $parsed = openssl_x509_parse($certificate);

        if ($parsed === false) {
            return null;
        }

        $der = '';
        openssl_x509_export($certificate, $der, false);

        $parsed['docup_fingerprint'] = hash('sha256', $der);

        return $parsed;
    }

    private function bracket(string $address): string
    {
        return str_contains($address, ':') ? '['.$address.']' : $address;
    }

    /** OpenSSL errors arrive multi-line and prefixed; the column is 255 bytes. */
    private static function tidy(string $error): string
    {
        return substr(trim(preg_replace('/\s+/', ' ', $error) ?? $error), 0, 255);
    }
}
