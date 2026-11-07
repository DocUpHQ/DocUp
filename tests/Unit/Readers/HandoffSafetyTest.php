<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Unit\Readers;

use App\Readers\HandoffRejection;
use App\Readers\PkceChallenge;
use App\Readers\ReaderCookies;
use App\Readers\ReaderHandoff;
use App\Readers\ReaderHandoffState;
use PHPUnit\Framework\TestCase;

/**
 * The pure halves of §8.12.10 and §12.4: the PKCE pair, the return path and the
 * cookie table.
 *
 * 🛑 A plain `PHPUnit\Framework\TestCase` with no application, deliberately.
 * Everything asserted here is a function of its arguments, and a booted
 * application would let one of these quietly start depending on configuration
 * — which is how a security rule becomes environment-specific.
 */
final class HandoffSafetyTest extends TestCase
{
    // --------------------------------------------------------- §8.12.10's PKCE

    /** 🛑 `S256`, exactly as RFC 7636 §4.2 defines it. */
    public function test_the_challenge_is_s256_over_the_encoded_verifier(): void
    {
        $pair = PkceChallenge::create();

        $expected = rtrim(strtr(base64_encode(hash('sha256', $pair->verifier, binary: true)), '+/', '-_'), '=');

        $this->assertSame($expected, $pair->challenge);

        /*
         * 🛑 Over the **encoded** verifier, not the raw bytes behind it. Getting
         * this wrong produces a system that verifies perfectly against itself
         * and fails against the OIDC provider P24 points at the same code.
         */
        $raw = base64_decode(strtr($pair->verifier, '-_', '+/'), true);

        $this->assertNotFalse($raw);
        $this->assertNotSame(
            rtrim(strtr(base64_encode(hash('sha256', (string) $raw, binary: true)), '+/', '-_'), '='),
            $pair->challenge,
            'the digest must be over the encoded verifier (RFC 7636 §4.2)',
        );
    }

    /** 43 base64url characters at both ends, so a transposition is visible. */
    public function test_the_pair_is_the_shape_the_column_stores(): void
    {
        $pair = PkceChallenge::create();

        $this->assertSame(43, strlen($pair->verifier));
        $this->assertSame(43, strlen($pair->challenge));
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/', $pair->verifier);
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/', $pair->challenge);
    }

    /** Two pairs never collide: the verifier is CSPRNG. */
    public function test_each_pair_is_fresh(): void
    {
        $this->assertNotSame(PkceChallenge::create()->verifier, PkceChallenge::create()->verifier);
    }

    /** A verifier satisfies only its own challenge. */
    public function test_a_verifier_satisfies_only_its_own_challenge(): void
    {
        $a = PkceChallenge::create();
        $b = PkceChallenge::create();

        $this->assertTrue(PkceChallenge::satisfies($a->verifier, $a->challenge));
        $this->assertFalse(PkceChallenge::satisfies($a->verifier, $b->challenge));
        $this->assertFalse(PkceChallenge::satisfies('', $a->challenge));
    }

    /**
     * 🛑 There is no `plain` method, and this asserts the absence.
     *
     * RFC 7636 permits `plain`; §8.12.18 makes `S256` mandatory. A `plain`
     * challenge *is* the verifier, so a code and its challenge travelling
     * together would prove nothing — and supporting both would make the method
     * a parameter an attacker chooses.
     */
    public function test_the_verifier_is_never_accepted_as_its_own_challenge(): void
    {
        $pair = PkceChallenge::create();

        $this->assertFalse(
            PkceChallenge::satisfies($pair->verifier, $pair->verifier),
            '🛑 a `plain` challenge must not verify',
        );
    }

    // ------------------------------------------------- §8.12.10's return path

    /**
     * 🛑 Every open-redirect vector, refused.
     *
     * §8.12.10 puts the origin beyond a request's reach; this keeps the
     * **path** from smuggling one back. Each case below is a real technique,
     * and `//evil.example/` is the one that gets missed — it is scheme-relative,
     * a browser reads it as another origin, and it *does* begin with `/`.
     */
    public function test_a_return_path_can_never_carry_an_origin(): void
    {
        $hostile = [
            'https://evil.example/',
            'http://evil.example/',
            '//evil.example/',
            '///evil.example/',
            '/\\evil.example',
            '\\\\evil.example',
            'evil.example/path',
            '',
            "/ok\r\nLocation: https://evil.example/",
            "/ok\nSet-Cookie: x=1",
            "/ok\x00",
            '/'.str_repeat('a', 4096),
        ];

        foreach ($hostile as $attempt) {
            $this->assertSame(
                '/',
                ReaderHandoff::safeReturnPath($attempt),
                'hostile return path must collapse to /: '.json_encode($attempt),
            );
        }
    }

    /** And an ordinary path survives unchanged. */
    public function test_an_ordinary_return_path_survives(): void
    {
        foreach (['/', '/en/latest/', '/en/latest/guide.html?q=1', '/a/b/c/#anchor'] as $path) {
            $this->assertSame($path, ReaderHandoff::safeReturnPath($path));
        }
    }

    /** 🛑 §8.12.10's own ceiling, as a constant rather than configuration. */
    public function test_the_code_window_is_thirty_seconds(): void
    {
        $this->assertLessThanOrEqual(30, ReaderHandoff::CODE_TTL_SECONDS);
    }

    // ------------------------------------------------------ the state cookie

    /** A round trip through the cookie keeps all three fields. */
    public function test_the_state_cookie_round_trips(): void
    {
        $state = new ReaderHandoffState(str_repeat('v', 43), '/en/latest/', 2);

        $parsed = ReaderHandoffState::fromCookie($state->toCookie());

        $this->assertNotNull($parsed);
        $this->assertSame($state->verifier, $parsed->verifier);
        $this->assertSame('/en/latest/', $parsed->returnPath);
        $this->assertSame(2, $parsed->attempt);
    }

    /**
     * 🛑 Fails to null on everything, because the caller reads null as "no
     * state" and restarts the handoff — the right outcome for a cookie
     * somebody tampered with, since tampering can only destroy a verifier they
     * do not hold.
     */
    public function test_an_unreadable_state_cookie_is_null(): void
    {
        $cases = [
            null,
            '',
            'not-base64-$$$',
            base64_encode('not json'),
            base64_encode('{"v":1,"r":"/"}'),              // verifier not a string
            base64_encode('{"v":"short","r":"/"}'),        // verifier too short
            base64_encode('{"v":"'.str_repeat('v', 43).'"}'), // no return path
            base64_encode('["array","not","object"]'),
            base64_encode('{"v":"'.str_repeat('*', 43).'","r":"/"}'), // outside RFC 7636's set
            str_repeat('A', 5000),
        ];

        foreach ($cases as $case) {
            $this->assertNull(
                ReaderHandoffState::fromCookie($case),
                'unreadable state must be null: '.json_encode($case),
            );
        }
    }

    /** 🛑 A hostile return path inside the cookie is normalised on the way out. */
    public function test_the_state_cookie_cannot_smuggle_an_origin(): void
    {
        $raw = base64_encode((string) json_encode([
            'v' => str_repeat('v', 43),
            'r' => '//evil.example/',
            'n' => 1,
        ]));

        $parsed = ReaderHandoffState::fromCookie($raw);

        $this->assertNotNull($parsed);
        $this->assertSame('/', $parsed->returnPath);
    }

    /** 🛑 §8.12.20's loop breaker needs the counter to survive a round trip. */
    public function test_the_attempt_counter_is_read_numerically(): void
    {
        /*
         * 🛑 A list of pairs, not a map. PHP normalises `'2'`, `2` and `2.0` to
         * the same array key, so a map would silently test one case three
         * times — which is the shape of mistake this very test is about.
         */
        $cases = [['2', 2], [2, 2], [2.0, 2], ['x', 1], [0, 1], [-5, 1]];

        foreach ($cases as [$stored, $expected]) {
            $raw = base64_encode((string) json_encode([
                'v' => str_repeat('v', 43),
                'r' => '/',
                'n' => $stored,
            ]));

            $parsed = ReaderHandoffState::fromCookie($raw);

            $this->assertNotNull($parsed);
            $this->assertSame(
                $expected,
                $parsed->attempt,
                // 🛑 Phase 20's finding: `is_numeric` then cast, never `is_int`.
                'a numeric string must read as its number: '.json_encode($stored),
            );
        }
    }

    // ----------------------------------------------------- §12.4's one table

    /**
     * 🛑 §12.4, asserted as a table.
     *
     * > "Every cookie is `__Host-` prefixed, Secure, HttpOnly, `SameSite=Lax`.
     * > 🛑 The `__Host-` prefix requires `Secure`, **no** `Domain` attribute and
     * > **`Path=/`**."
     *
     * The failure this guards is silent: a browser does not report a `__Host-`
     * cookie with a `Domain` attribute, it simply does not store it.
     */
    public function test_section_12_4_is_five_rows_and_every_one_obeys_the_prefix(): void
    {
        $this->assertCount(5, ReaderCookies::names(), '§12.4 is five rows');

        foreach (ReaderCookies::names() as $name) {
            $this->assertStringStartsWith('__Host-', $name);
        }
    }

    /**
     * 🛑 Every cookie this class makes, asserted on the **rendered
     * `Set-Cookie` header** rather than on the value object's accessors.
     *
     * The header is what a browser reads and what a proxy may rewrite, and it
     * is the only form in which `Domain` is observably *absent* rather than
     * merely null in PHP. Asserting the accessors would also be asserting
     * Symfony's own types back at itself, which Larastan correctly calls an
     * assertion that cannot fail.
     */
    public function test_every_cookie_the_factory_makes_obeys_the_table(): void
    {
        $cookies = [
            ReaderCookies::session('handle'),
            ReaderCookies::grant('token'),
            ReaderCookies::cacheKey('ck'),
            ReaderCookies::state('state'),
            ReaderCookies::forget(ReaderCookies::SESSION),
        ];

        foreach ($cookies as $cookie) {
            $header = (string) $cookie;

            $this->assertStringStartsWith('__Host-', $header);
            $this->assertStringContainsString('; path=/', $header, '🛑 __Host- requires Path=/');
            $this->assertStringContainsString('; secure', $header, '🛑 __Host- requires Secure');
            $this->assertStringContainsString('; httponly', $header);
            $this->assertStringContainsString('; samesite=lax', $header);

            /*
             * 🛑 The absence that matters. A `__Host-` cookie carrying a
             * `Domain` attribute is not rejected loudly — the browser simply
             * does not store it, the next request arrives with no session, and
             * the reader loops through §8.12.10's handoff with nothing in any
             * log.
             */
            $this->assertStringNotContainsString('domain=', $header, '🛑 __Host- forbids a Domain attribute');

            /* And `path=/` exactly, not a path that merely begins with it. */
            $this->assertDoesNotMatchRegularExpression('/; path=\/\S/', $header);
        }
    }

    /**
     * 🛑 The grant cookie never outlives §8.12.11's ceiling.
     *
     * "`exp` ≤ 10 minutes" is the number that bounds Tier C's exposure window
     * (§8.12.15), so a cookie that held the token for longer would widen the
     * one figure §4.2's non-goal is scoped by.
     */
    public function test_the_grant_cookie_expires_within_ten_minutes(): void
    {
        $cookie = ReaderCookies::grant('token');

        $this->assertLessThanOrEqual(600, $cookie->getExpiresTime() - time());
    }

    // ------------------------------------------------- §9.4's abuse corpus

    /**
     * 🛑 §9.4: a security-critical phase "additionally appends a named case to
     * the permanent abuse corpus".
     *
     * This asserts the cases Phase 22 appended are *real* — that each names a
     * refusal the code can actually produce, or an HTTP status. A corpus case
     * naming a vocabulary that has been renamed is worse than no case: it
     * passes, it looks like coverage, and it defends nothing.
     *
     * The same technique §12.3's own corpus test uses, and for the same reason
     * given there: a rename otherwise fails only as a confusing mismatch, in a
     * dataset, long after the change that caused it.
     */
    public function test_every_reader_corpus_case_names_a_real_refusal(): void
    {
        /** @var array{cases: list<array<string, mixed>>} $corpus */
        $corpus = json_decode(
            (string) file_get_contents(dirname(__DIR__, 2).'/Fixtures/AbuseCorpus/corpus.json'),
            true,
            512,
            JSON_THROW_ON_ERROR,
        );

        $known = array_map(
            static fn (HandoffRejection $case): string => $case->value,
            HandoffRejection::cases(),
        );

        $unknown = [];
        $named = 0;

        foreach ($corpus['cases'] as $case) {
            if (($case['category'] ?? null) !== 'reader') {
                continue;
            }

            $named++;
            $expect = (string) ($case['expect'] ?? '');

            /*
             * Three expectation shapes, each legitimate: a {@see HandoffRejection}
             * value, an HTTP status (§8.12.23's rule is about a response), and
             * a normalised return path (`reader-003`, whose whole point is what
             * the value becomes rather than that it is refused).
             */
            if (ctype_digit($expect) || str_starts_with($expect, '/')) {
                continue;
            }

            if (! in_array($expect, $known, true)) {
                $unknown[] = $case['id'].' expects '.$expect;
            }
        }

        $this->assertGreaterThanOrEqual(
            8,
            $named,
            '§9.4: Phase 22 appends its own cases and they stay appended',
        );

        $this->assertSame([], $unknown, 'corpus cases naming no real refusal: '.implode(', ', $unknown));
    }

    /** 🛑 A clearing cookie carries the same attributes as what it clears. */
    public function test_forgetting_a_cookie_uses_the_same_attributes(): void
    {
        $forget = ReaderCookies::forget(ReaderCookies::GRANT);

        $this->assertSame(ReaderCookies::GRANT, $forget->getName());
        $this->assertSame('', $forget->getValue());
        $this->assertLessThan(time(), $forget->getExpiresTime());

        /*
         * 🛑 The attributes matter more than the expiry. A clearing cookie
         * whose path or domain differs is a *new* cookie the browser stores
         * beside the old one, and the old one keeps being sent.
         */
        $this->assertSame('/', $forget->getPath());
        $this->assertNull($forget->getDomain());
    }
}
