<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Edge;

use App\Http\Middleware\TrustEdgeProxies;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Symfony\Component\HttpFoundation\Response;
use Tests\TestCase;

/**
 * 🛑 §8.9.4 and §17's Phase 26b criterion: "A spoofed `X-Forwarded-For` beyond
 * the trusted hop count is ignored."
 *
 * ## 🛑 Why this criterion was vacuous before Phase 26b
 *
 * Nothing configured trusted proxies, so `X-Forwarded-For` was ignored
 * **always** — the criterion held, and held for the wrong reason. The cost was
 * on the other side: `$request->ip()` returned the edge container's address,
 * so §8.12.17's `ip_allowlist` gate compared the **edge's** address against
 * the operator's allowlist. Either it matched nothing, or an operator debugging
 * that read the address out of their logs, allowlisted it, and made the gate
 * satisfied for every reader on the internet.
 *
 * So this file asserts both halves, and the second is what makes the first mean
 * anything: a spoofed header from an **untrusted** hop is ignored, **and** a
 * genuine header from a **trusted** one is honoured.
 *
 * ## 🛑 And the header that must never be honoured
 *
 * `X-Forwarded-Host` is excluded from the trusted set, and
 * {@see self::test_a_forwarded_host_never_selects_the_project()} is the reason
 * this file exists at all. §8.9.4: "No request header MUST act as a project,
 * version or tenant selector, in any environment. This is the
 * GHSA-mp38-vprc-7hf5 class." The project is resolved from the Host, so
 * trusting that header would make a header pick the project — and Laravel's and
 * Symfony's own default header sets include it.
 */
final class TrustedProxyTest extends TestCase
{
    private const string PEER = '172.20.0.9';

    private const string CLAIMED = '203.0.113.7';

    /**
     * 🛑 Nothing trusted: the header is ignored and `ip()` is the peer.
     *
     * The default, and the safe one. An installation with no `ip_allowlist`
     * binding needs no configuration and gets no trust.
     */
    public function test_with_nothing_trusted_the_header_is_ignored(): void
    {
        $this->assertSame(self::PEER, $this->resolve(''));
    }

    /**
     * 🛑 **§17's criterion: a spoofed header beyond the trusted hop is
     * ignored.**
     *
     * The peer is `172.20.0.9` and the configuration trusts `10.0.0.0/8`, so
     * the request arrives from an address DocUp does not trust — and its claim
     * about who it is for is discarded.
     */
    public function test_a_spoofed_header_from_an_untrusted_hop_is_ignored(): void
    {
        $this->assertSame(
            self::PEER,
            $this->resolve('10.0.0.0/8'),
            '🛑 §17: a spoofed `X-Forwarded-For` beyond the trusted hop count is ignored',
        );
    }

    /**
     * 🛑 And from a **trusted** hop it is honoured, which is what makes the
     * test above mean something.
     *
     * Without this, "ignored" would be satisfied by ignoring the header
     * unconditionally — which is exactly the state Phase 26b found, and which
     * left the `ip_allowlist` gate reading the wrong address.
     */
    public function test_a_header_from_a_trusted_hop_is_honoured(): void
    {
        $this->assertSame(self::CLAIMED, $this->resolve('172.20.0.0/16'));
    }

    /**
     * `*` means the address directly in front.
     *
     * 🛑 Asserted because the first implementation passed `*` straight to
     * Symfony, which trusts **nothing** for it — `*` is Laravel's convention,
     * translated by its own middleware. A setting that silently does nothing is
     * worse than one that is absent: the operator reads the name, believes it,
     * and the gate they configured compares the wrong address.
     */
    public function test_a_star_trusts_the_address_directly_in_front(): void
    {
        $this->assertSame(self::CLAIMED, $this->resolve('*'));
    }

    /**
     * `private` means any RFC1918 address, for a topology with several
     * internal hops.
     *
     * Safe by construction: a public client cannot present a private source
     * address, so trusting the range cannot trust a client.
     */
    public function test_private_trusts_any_private_address(): void
    {
        $this->assertSame(self::CLAIMED, $this->resolve('private'));

        /*
         * 🛑 And a **public** peer is not trusted by it, which is the half that
         * makes `private` safe rather than convenient.
         */
        $this->assertSame(
            '198.51.100.1',
            $this->resolve('private', peer: '198.51.100.1'),
        );
    }

    /**
     * 🛑 **`X-Forwarded-Host` never selects the project, in any
     * configuration.**
     *
     * §8.9.4: "The project MUST be resolved **solely** from the TLS server name
     * or `Host` header plus the path. No request header MUST act as a project,
     * version or tenant selector, in any environment. This is the
     * GHSA-mp38-vprc-7hf5 class."
     *
     * Asserted across **every** trust setting, including the most permissive,
     * because the requirement says "in any environment" and the risk is a
     * future edit widening the header set to Laravel's default — which includes
     * this header.
     */
    public function test_a_forwarded_host_never_selects_the_project(): void
    {
        foreach (['', '*', 'private', '172.20.0.0/16', '10.0.0.0/8'] as $trusted) {
            $request = $this->request();
            $request->headers->set('X-Forwarded-Host', 'evil.attacker.test');

            $this->pass($request, $trusted);

            $this->assertSame(
                'docup-docs.localhost',
                $request->getHost(),
                '🛑 §8.9.4: a header selected the project with `'
                    .($trusted === '' ? 'nothing' : $trusted).'` trusted',
            );
        }
    }

    /**
     * 🛑 `X-Forwarded-Proto` **is** trusted, and it has to be.
     *
     * The edge terminates TLS, so without it every generated URL would be
     * `http://` and §9.3.4's `secure` cookie attribute would be dropped — a
     * reader's session cookie travelling in clear. This is the one place where
     * trusting a header is load-bearing rather than merely convenient.
     */
    public function test_the_forwarded_protocol_is_honoured_from_a_trusted_hop(): void
    {
        $request = Request::create('http://docup-docs.localhost/x', 'GET', [], [], [], [
            'REMOTE_ADDR' => self::PEER,
        ]);
        $request->headers->set('X-Forwarded-Proto', 'https');

        $this->pass($request, '172.20.0.0/16');

        $this->assertTrue($request->isSecure(), '§9.3.4 needs the scheme the reader actually used');

        /* And not from an untrusted one. */
        $spoofed = Request::create('http://docup-docs.localhost/x', 'GET', [], [], [], [
            'REMOTE_ADDR' => self::PEER,
        ]);
        $spoofed->headers->set('X-Forwarded-Proto', 'https');

        $this->pass($spoofed, '10.0.0.0/8');

        $this->assertFalse($spoofed->isSecure());
    }

    /**
     * 🛑 The trust is set on **every** request, not only when something is
     * configured.
     *
     * Under FrankenPHP worker mode the `Request` class's static trusted-proxy
     * state outlives a request. A middleware that returned early when nothing
     * was configured would leave whatever the previous request set — a
     * cross-request leak of trust, and one that would only appear under the
     * SAPI §11.3 says is unevidenced.
     */
    public function test_trust_does_not_leak_between_requests(): void
    {
        /* A request that trusts the peer. */
        $this->resolve('*');

        $this->assertNotSame(
            [],
            Request::getTrustedProxies(),
            'the permissive request configured trust',
        );

        /* Then one that trusts nothing must clear it. */
        $this->assertSame(self::PEER, $this->resolve(''));

        $this->assertSame(
            [],
            Request::getTrustedProxies(),
            '🛑 a worker process must not carry one request\'s trust into the next',
        );
    }

    // ------------------------------------------------------------- fixtures

    /** The address the application resolves, under one trust setting. */
    private function resolve(string $trusted, string $peer = self::PEER): string
    {
        $request = $this->request($peer);

        $this->pass($request, $trusted);

        return (string) $request->ip();
    }

    private function request(string $peer = self::PEER): Request
    {
        $request = Request::create('https://docup-docs.localhost/x', 'GET', [], [], [], [
            'REMOTE_ADDR' => $peer,
        ]);

        $request->headers->set('X-Forwarded-For', self::CLAIMED);

        return $request;
    }

    private function pass(Request $request, string $trusted): void
    {
        Config::set('docup.edge.trusted_proxies', $trusted);

        (new TrustEdgeProxies)->handle($request, static fn (): Response => new Response);
    }
}
