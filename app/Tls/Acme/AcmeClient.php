<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Tls\Acme;

use App\Egress\EgressRefused;
use App\Egress\EgressResponse;
use App\Egress\HardenedEgressClient;
use App\Tls\CertificateRefused;
use App\Tls\CertificateRejection;
use App\Tls\Csr;

/**
 * An RFC 8555 client, over the one hardened egress path (§8.3.9, §8.10.14).
 *
 * 🛑 **Hand-written rather than a dependency, and the reason is §8.3.9.**
 * Every published PHP ACME client brings its own HTTP stack — Guzzle, cURL,
 * `file_get_contents` — and none of them can be made to resolve-then-pin,
 * refuse a 3xx or stop at a byte cap. Adopting one would mean a second
 * outbound path, which §8.3.9 calls "not a duplication bug but an
 * **unvalidated** one", and the architecture test that keeps that true would
 * have to be weakened to admit it. The protocol itself is nine requests and
 * one signature format; the hardening is the part that is hard to get right,
 * and it already exists.
 *
 * Scope is deliberately `http-01` only. `dns-01` needs a provider API per
 * registrar, which §4.2 puts out of scope, and §8.10.10's wildcard — the one
 * case that genuinely requires `dns-01` — is obtained by the operator and
 * supplied to the installation rather than issued by it.
 */
final class AcmeClient
{
    /**
     * How long to wait for a CA to validate and finalise.
     *
     * Deliberately short: this runs inside a queued job, and a CA that has
     * not answered in half a minute is a CA having an outage, which is a
     * retry rather than a longer wait.
     */
    private const MAX_POLLS = 15;

    private const POLL_MICROSECONDS = 2_000_000;

    /**
     * 🛑 Required, not polite. Pebble refuses **every** request without one
     * with `urn:ietf:params:acme:error:malformed` and "All requests MUST
     * include a User-Agent header", and Let's Encrypt uses it to reach the
     * operator of a client that is misbehaving before it blocks them. RFC
     * 8555 §6.1 asks for it; a CA treating "asks for" as "requires" is
     * within its rights and at least one does.
     *
     * This was found by running against a real server. A stubbed ACME
     * exchange would have been green, and the first operator to point an
     * installation at a strict directory would have had every issuance fail
     * with a message about a malformed request.
     */
    private const USER_AGENT = 'DocUp/acme';

    /**
     * The directory document, fetched once.
     *
     * 🛑 This is why the class is not `readonly`, and the reason is the
     * nonce. Every POST needs a fresh `Replay-Nonce`, every nonce needs the
     * `newNonce` URL, and that URL exists only in the directory — so a
     * client that re-fetched the directory per nonce would make three
     * requests for every one the protocol describes. The document is
     * immutable for the life of a directory; holding it is caching, not
     * state.
     *
     * @var array<array-key, mixed>|null
     */
    private ?array $directory = null;

    public function __construct(
        private readonly HardenedEgressClient $egress,
        private readonly AcmeChallenges $challenges,
        private readonly Jws $jws,
        private readonly string $directoryUrl,
        private readonly ?string $accountUrl = null,
        private readonly ?\Closure $sleep = null,
    ) {}

    /**
     * Register, or recover, this key's account, returning its URL.
     *
     * 🛑 `onlyReturnExisting` is **not** sent. RFC 8555 §7.3 makes
     * `newAccount` idempotent for a key that already has an account — it
     * answers 200 with the existing URL rather than 201 — so one unguarded
     * call covers both cases. Branching on "do we think we are registered?"
     * would make a lost `account_url` column unrecoverable without operator
     * intervention.
     *
     * @throws CertificateRefused
     */
    public function register(?string $contact): string
    {
        $directory = $this->directory();

        $payload = ['termsOfServiceAgreed' => true];

        if ($contact !== null && $contact !== '') {
            $payload['contact'] = ['mailto:'.$contact];
        }

        $response = $this->send($this->endpoint($directory, 'newAccount'), $payload, kid: null);

        $location = $response->header('location');

        if ($location === null || $location === '') {
            throw CertificateRefused::of(CertificateRejection::AcmeUnreadable, 'newAccount returned no Location');
        }

        return $location;
    }

    /**
     * Obtain a certificate for one hostname.
     *
     * @return array{0: string, 1: string} the PEM chain and its private key
     *
     * @throws CertificateRefused
     */
    public function certificate(string $host): array
    {
        if ($this->accountUrl === null) {
            throw CertificateRefused::of(CertificateRejection::NoAcmeAccount, 'the account is not registered');
        }

        $directory = $this->directory();

        $order = $this->post(
            $this->endpoint($directory, 'newOrder'),
            ['identifiers' => [['type' => 'dns', 'value' => $host]]],
        );

        $orderUrl = $order->header('location');
        $body = $this->decode($order);

        if ($orderUrl === null) {
            throw CertificateRefused::of(CertificateRejection::AcmeUnreadable, 'newOrder returned no Location');
        }

        foreach ($this->stringList($body, 'authorizations') as $authorization) {
            $this->satisfy($authorization);
        }

        $key = Csr::key();

        $finalised = $this->post(
            $this->stringAt($body, 'finalize'),
            ['csr' => Jws::base64url(Csr::der($host, $key))],
        );

        $order = $this->awaitOrder($orderUrl, $this->decode($finalised));

        $chain = $this->post($this->stringAt($order, 'certificate'), null);

        $private = '';
        openssl_pkey_export($key, $private);

        return [$chain->body, $private];
    }

    /**
     * Publish the `http-01` response, tell the CA to look, and wait.
     *
     * @throws CertificateRefused
     */
    private function satisfy(string $authorizationUrl): void
    {
        $authorization = $this->decode($this->post($authorizationUrl, null));

        if (($authorization['status'] ?? null) === 'valid') {
            return;         // Already satisfied: §8.10.10's authorization reuse.
        }

        $challenge = $this->httpChallenge($authorization);
        $token = $this->stringAt($challenge, 'token');

        $this->challenges->publish($token, $this->jws->keyAuthorization($token));

        try {
            /*
             * An empty JSON object, not a POST-as-GET: RFC 8555 §7.5.1 says
             * `{}` is what tells the server to begin validation, and a null
             * payload here would read the challenge without triggering it,
             * so the poll below would spin until it gave up.
             */
            $this->post($this->stringAt($challenge, 'url'), []);

            for ($poll = 0; $poll < self::MAX_POLLS; $poll++) {
                $authorization = $this->decode($this->post($authorizationUrl, null));
                $status = $authorization['status'] ?? null;

                if ($status === 'valid') {
                    return;
                }

                if (in_array($status, ['invalid', 'revoked', 'deactivated', 'expired'], true)) {
                    throw CertificateRefused::of(
                        CertificateRejection::AcmeRefused,
                        'authorization '.$status.': '.$this->problemOf($authorization),
                    );
                }

                $this->pause();
            }

            throw CertificateRefused::of(CertificateRejection::AcmeRefused, 'the authorization never became valid');
        } finally {
            /*
             * 🛑 Withdrawn whatever happened. A key authorization left in the
             * cache after a failed order is an answer this installation would
             * keep giving to anybody who asked for that path — harmless in
             * itself, since the token is single-use at the CA, but it is
             * live state outliving the thing that justified it, and that is
             * how a cache becomes an oracle.
             */
            $this->challenges->withdraw($token);
        }
    }

    /**
     * @param  array<array-key, mixed>  $order
     * @return array<array-key, mixed>
     *
     * @throws CertificateRefused
     */
    private function awaitOrder(string $orderUrl, array $order): array
    {
        for ($poll = 0; $poll < self::MAX_POLLS; $poll++) {
            $status = $order['status'] ?? null;

            if ($status === 'valid') {
                return $order;
            }

            if ($status === 'invalid') {
                throw CertificateRefused::of(CertificateRejection::AcmeRefused, 'order invalid: '.$this->problemOf($order));
            }

            $this->pause();
            $order = $this->decode($this->post($orderUrl, null));
        }

        throw CertificateRefused::of(CertificateRejection::AcmeRefused, 'the order never became valid');
    }

    /**
     * @param  array<array-key, mixed>  $authorization
     * @return array<array-key, mixed>
     *
     * @throws CertificateRefused
     */
    private function httpChallenge(array $authorization): array
    {
        $challenges = $authorization['challenges'] ?? null;

        foreach (is_array($challenges) ? $challenges : [] as $challenge) {
            if (is_array($challenge) && ($challenge['type'] ?? null) === 'http-01') {
                return $challenge;
            }
        }

        throw CertificateRefused::of(
            CertificateRejection::AcmeRefused,
            'the directory offered no http-01 challenge',
        );
    }

    /**
     * @return array<array-key, mixed>
     *
     * @throws CertificateRefused
     */
    private function directory(): array
    {
        if ($this->directory !== null) {
            return $this->directory;
        }

        try {
            $response = $this->egress->get($this->directoryUrl, [
                'Accept' => 'application/json',
                'User-Agent' => self::USER_AGENT,
            ]);
        } catch (EgressRefused $refused) {
            throw CertificateRefused::of(CertificateRejection::AcmeUnreadable, $refused->getMessage());
        }

        return $this->directory = $this->decode($response);
    }

    /**
     * 🛑 A nonce per request, fetched fresh rather than carried.
     *
     * RFC 8555 §6.5 lets a server hand back a `Replay-Nonce` on every
     * response, and a client that reused one would be fast and occasionally
     * wrong — the server may expire a nonce at any time, and a stale one
     * fails the request with `badNonce` rather than retrying. One HEAD per
     * POST costs a round trip to a host we are already talking to, and makes
     * the failure mode impossible rather than rare.
     *
     * @throws CertificateRefused
     */
    private function nonce(): string
    {
        $directory = $this->directory();

        try {
            $response = $this->egress->head(
                $this->endpoint($directory, 'newNonce'),
                ['User-Agent' => self::USER_AGENT],
            );
        } catch (EgressRefused $refused) {
            throw CertificateRefused::of(CertificateRejection::AcmeUnreadable, $refused->getMessage());
        }

        $nonce = $response->header('replay-nonce');

        if ($nonce === null || $nonce === '') {
            throw CertificateRefused::of(CertificateRejection::AcmeUnreadable, 'newNonce returned no Replay-Nonce');
        }

        return $nonce;
    }

    /**
     * A signed request on behalf of the registered account.
     *
     * @param  array<string, mixed>|null  $payload  null for POST-as-GET
     *
     * @throws CertificateRefused
     */
    private function post(string $url, ?array $payload): EgressResponse
    {
        return $this->send($url, $payload, $this->accountUrl);
    }

    /**
     * 🛑 The one place `kid` is chosen, so that exactly one request in the
     * whole exchange — `newAccount`, which has no account to refer to yet —
     * carries an inline JWK, and every other one carries the account URL. A
     * client that sent both would be told `malformed`, with no indication of
     * which field was wrong.
     *
     * @param  array<string, mixed>|null  $payload  null for POST-as-GET
     *
     * @throws CertificateRefused
     */
    private function send(string $url, ?array $payload, ?string $kid): EgressResponse
    {
        /*
         * 🛑 One retry, and only for `badNonce`.
         *
         * RFC 8555 §6.5 says a server MAY reject any nonce at any time and
         * that a client SHOULD retry with a fresh one — Let's Encrypt does
         * it when a nonce has expired, and Pebble does it at random
         * precisely so that clients which skip this are caught in testing.
         * A client without the retry works almost always, which is the
         * worst failure rate: it fails for one operator, once, and is
         * unreproducible.
         *
         * Exactly one retry: a second `badNonce` with a nonce fetched
         * seconds earlier is a server that is not issuing usable nonces,
         * and looping would turn that into a hot loop against a CA.
         */
        for ($attempt = 0; ; $attempt++) {
            $signed = $this->jws->sign($url, $this->nonce(), $payload, $kid);

            try {
                $response = $this->egress->post($url, $signed, [
                    'Content-Type' => 'application/jose+json',
                    'Accept' => 'application/json',
                    'User-Agent' => self::USER_AGENT,
                ]);
            } catch (EgressRefused $refused) {
                throw CertificateRefused::of(CertificateRejection::AcmeUnreadable, $refused->getMessage());
            }

            if ($response->status < 400) {
                return $response;
            }

            $problem = $response->json() ?? [];

            if ($attempt === 0 && ($problem['type'] ?? null) === 'urn:ietf:params:acme:error:badNonce') {
                continue;
            }

            throw CertificateRefused::of(
                CertificateRejection::AcmeRefused,
                $url.' answered '.$response->status.': '.$this->problemOf($problem),
            );
        }
    }

    /**
     * @return array<array-key, mixed>
     *
     * @throws CertificateRefused
     */
    private function decode(EgressResponse $response): array
    {
        $decoded = $response->json();

        if ($decoded === null) {
            throw CertificateRefused::of(CertificateRejection::AcmeUnreadable, 'the response was not JSON');
        }

        return $decoded;
    }

    /**
     * @param  array<array-key, mixed>  $directory
     *
     * @throws CertificateRefused
     */
    private function endpoint(array $directory, string $name): string
    {
        return $this->stringAt($directory, $name);
    }

    /**
     * @param  array<array-key, mixed>  $document
     *
     * @throws CertificateRefused
     */
    private function stringAt(array $document, string $key): string
    {
        $value = $document[$key] ?? null;

        if (! is_string($value) || $value === '') {
            throw CertificateRefused::of(CertificateRejection::AcmeUnreadable, 'missing "'.$key.'"');
        }

        return $value;
    }

    /**
     * @param  array<array-key, mixed>  $document
     * @return list<string>
     */
    private function stringList(array $document, string $key): array
    {
        $values = $document[$key] ?? null;
        $strings = [];

        foreach (is_array($values) ? $values : [] as $value) {
            if (is_string($value) && $value !== '') {
                $strings[] = $value;
            }
        }

        return $strings;
    }

    /**
     * RFC 7807, as an ACME server sends it, flattened to one line for a log.
     *
     * @param  array<array-key, mixed>  $document
     */
    private function problemOf(array $document): string
    {
        $problem = $document['error'] ?? $document;
        $problem = is_array($problem) ? $problem : [];

        $parts = [];

        foreach (['type', 'detail'] as $field) {
            $value = $problem[$field] ?? null;

            if (is_string($value) && $value !== '') {
                $parts[] = $value;
            }
        }

        return $parts === [] ? 'no problem document' : substr(implode(' — ', $parts), 0, 400);
    }

    private function pause(): void
    {
        ($this->sleep ?? static fn (int $microseconds) => usleep($microseconds))(self::POLL_MICROSECONDS);
    }
}
