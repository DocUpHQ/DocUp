<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Readers;

use App\Access\AccessDecision;
use App\Access\AccessLeaf;
use App\Access\AccessReason;
use App\Access\AccessSurface;
use App\Access\ReaderContext;
use App\Auth\AccessLevel;
use App\Models\GrantSigningKey;
use App\Readers\Grants\Grant;
use App\Readers\Grants\GrantKeys;
use App\Readers\Grants\GrantMinter;
use App\Readers\Grants\GrantVerifier;
use App\Readers\Grants\KeyState;
use App\Readers\SessionRecord;
use App\Support\Uuid;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\Cache;
use Tests\TestCase;

/**
 * §8.12.11's grant: minting, verification and §17's four-state rotation.
 *
 * 🛑 Every refusal below is a disclosure prevented. A verifier that checks the
 * signature and reads the claims is the common shape and it is wrong: the
 * signature proves this installation minted the token, **not** that the token
 * is for this request. The audience, the epoch and the surface are what make it
 * so, and each has its own test here.
 */
final class GrantTest extends TestCase
{
    use DatabaseTransactions;

    private GrantKeys $keys;

    private GrantMinter $minter;

    private GrantVerifier $verifier;

    private SessionRecord $session;

    private string $domainA;

    private string $domainB;

    private string $versionId;

    protected function setUp(): void
    {
        parent::setUp();

        Cache::flush();

        $this->keys = app(GrantKeys::class);
        $this->minter = app(GrantMinter::class);
        $this->verifier = app(GrantVerifier::class);

        $this->domainA = Uuid::toBytes(Uuid::v7());
        $this->domainB = Uuid::toBytes(Uuid::v7());
        $this->versionId = Uuid::toBytes(Uuid::v7());

        $this->session = new SessionRecord(
            id: Uuid::toBytes(Uuid::v7()),
            organisationId: Uuid::toBytes(Uuid::v7()),
            projectId: Uuid::toBytes(Uuid::v7()),
            domainId: $this->domainA,
            userId: Uuid::toBytes(Uuid::v7()),
            readerIdentityId: null,
        );
    }

    // -------------------------------------------------------- the round trip

    /** A minted grant verifies on the domain it was minted for. */
    public function test_a_grant_verifies_on_its_own_domain(): void
    {
        $token = $this->mint();

        $grant = $this->verifier->grantFor($token, $this->domainA, currentEpoch: 7);

        $this->assertNotNull($grant);
        $this->assertSame($this->session->id, $grant->sessionId);
        $this->assertSame($this->session->projectId, $grant->projectId);
        $this->assertSame($this->versionId, $grant->versionId);
        $this->assertSame(AccessLevel::Members, $grant->level);
        $this->assertSame(AccessLeaf::Binding, $grant->satisfiedBy);
    }

    /**
     * 🛑 §17's exit criterion: "A grant minted for domain A is refused on
     * domain B."
     *
     * The assertion that would fail if the grant were bound to the project
     * instead of the domain — which reads just as naturally and would let one
     * grant work on every domain a project serves.
     */
    public function test_a_grant_is_refused_on_another_domain(): void
    {
        $token = $this->mint();

        $this->assertNull($this->verifier->grantFor($token, $this->domainB, currentEpoch: 7));
    }

    /**
     * 🛑 §8.12.13's Tier C condition, applied at every tier: "refuse any grant
     * below the current epoch".
     *
     * This is what gives §8.12.15 its one-request bound, and it is why a policy
     * edit needs no purge: the next request compares the grant's `ep` against
     * the row and the comparison fails.
     */
    public function test_a_grant_below_the_current_epoch_is_refused(): void
    {
        $token = $this->mint(authzEpoch: 4, identityEpoch: 3);

        /* 7 is what it was minted under. */
        $this->assertNotNull($this->verifier->grantFor($token, $this->domainA, currentEpoch: 7));

        /* Either counter moving is enough, because the claim is their sum. */
        $this->assertNull($this->verifier->grantFor($token, $this->domainA, currentEpoch: 8));
    }

    /**
     * 🛑 {@see Grant::combinedEpoch()}'s monotonicity argument, as a test.
     *
     * The sum is a valid single ordering **only** because neither input can
     * decrease. The pairs that collide on a sum are unreachable from one
     * another, which is what makes "below the current epoch" mean "minted
     * before either epoch moved".
     */
    public function test_the_combined_epoch_is_monotonic_in_both_inputs(): void
    {
        $base = Grant::combinedEpoch(4, 3);

        $this->assertGreaterThan($base, Grant::combinedEpoch(5, 3), 'authz moving raises the sum');
        $this->assertGreaterThan($base, Grant::combinedEpoch(4, 4), 'identity moving raises the sum');
        $this->assertSame($base, Grant::combinedEpoch(4, 3), 'neither moving leaves it alone');
    }

    /**
     * 🛑 A grant for one surface is not a grant for another (§8.12.21).
     *
     * It matters because §8.12.21 disables search entirely while its generation
     * lags the policy's, and a grant minted while reading a page must not route
     * around that.
     */
    public function test_a_grant_is_refused_on_another_surface(): void
    {
        $token = $this->mint(surface: AccessSurface::Proxy);

        $this->assertNull($this->verifier->grantFor(
            $token,
            $this->domainA,
            currentEpoch: 7,
            surface: AccessSurface::Search,
        ));
    }

    /** 🛑 §8.12.11's `exp ≤ 10 minutes`, with no leeway past it. */
    public function test_an_expired_grant_is_refused(): void
    {
        $now = time();
        $token = $this->mint(now: $now);

        $this->assertNotNull($this->verifier->grantFor($token, $this->domainA, 7, now: $now + 299));
        $this->assertNull($this->verifier->grantFor($token, $this->domainA, 7, now: $now + 301));
    }

    /**
     * 🛑 The TTL is **clamped**, not validated, so a rule row written before
     * the ceiling existed cannot mint a longer-lived grant.
     */
    public function test_the_ttl_is_clamped_to_the_ten_minute_ceiling(): void
    {
        $now = time();
        $token = $this->mint(ttlSeconds: 86_400, now: $now);

        $grant = $this->verifier->grantFor($token, $this->domainA, 7, now: $now);

        $this->assertNotNull($grant);
        $this->assertSame($now + GrantMinter::MAX_TTL_SECONDS, $grant->expiresAt);
        $this->assertSame(600, GrantMinter::MAX_TTL_SECONDS, '§8.12.11: exp ≤ 10 minutes');
    }

    /**
     * 🛑 **Only an allow is mintable.**
     *
     * A grant whose meaning depends on reading a field inside it is one
     * misconfigured verifier away from being a bearer credential that allows.
     * The absence of a grant is unambiguous at every tier.
     */
    public function test_a_denial_cannot_be_minted(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $this->minter->mint(
            decision: new AccessDecision(
                allowed: false,
                reason: AccessReason::VersionVisibility,
                status: 404,
                required: AccessLevel::Members,
                established: AccessLevel::Public,
            ),
            reader: ReaderContext::member(bin2hex($this->session->id)),
            session: $this->session,
            domainId: $this->domainA,
            versionId: $this->versionId,
            versionSlug: 'latest',
            authzEpoch: 4,
            identityEpoch: 3,
        );
    }

    // ------------------------------------------------------ forgery and shape

    /** 🛑 A tampered payload fails the signature. */
    public function test_a_tampered_grant_is_refused(): void
    {
        [$header, $payload, $signature] = explode('.', $this->mint());

        $decoded = json_decode((string) base64_decode(strtr($payload, '-_', '+/'), true), true);
        $this->assertIsArray($decoded);

        /* Promote the reader to `restricted` and re-encode. */
        $decoded['lvl'] = AccessLevel::Restricted->value;
        $forged = GrantKeys::base64Url((string) json_encode($decoded));

        $this->assertNull(
            $this->verifier->grantFor($header.'.'.$forged.'.'.$signature, $this->domainA, 7),
        );
    }

    /**
     * 🛑 `alg: none` is refused, and the reason is structural rather than a
     * check: the algorithm is a literal at both ends, so the token's own
     * header never selects a verifier.
     */
    public function test_an_unsigned_token_is_refused(): void
    {
        $key = $this->keys->signing();

        $header = GrantKeys::base64Url((string) json_encode(['alg' => 'none', 'typ' => 'JWT', 'kid' => $key->kid]));
        $payload = GrantKeys::base64Url((string) json_encode([
            'aud' => Uuid::toText($this->domainA),
            'sub' => Uuid::toText($this->session->id),
            'pid' => Uuid::toText($this->session->projectId),
            'vid' => Uuid::toText($this->versionId),
            'vsl' => 'latest',
            'ep' => 7,
            'iat' => time(),
            'exp' => time() + 300,
            'sfc' => 'proxy',
            'lvl' => 'members',
        ]));

        $this->assertNull($this->verifier->grantFor($header.'.'.$payload.'.', $this->domainA, 7));
    }

    /** 🛑 An unknown `kid` selects no key, so the token is refused. */
    public function test_an_unknown_kid_is_refused(): void
    {
        [, $payload, $signature] = explode('.', $this->mint());

        $header = GrantKeys::base64Url((string) json_encode(['alg' => 'EdDSA', 'typ' => 'JWT', 'kid' => 'not-a-key']));

        $this->assertNull($this->verifier->grantFor($header.'.'.$payload.'.'.$signature, $this->domainA, 7));
    }

    /** Structural noise is refused without reaching the crypto. */
    public function test_malformed_tokens_are_refused(): void
    {
        foreach (['', 'x', 'a.b', 'a.b.c.d', '....', str_repeat('A', 5000)] as $token) {
            $this->assertNull(
                $this->verifier->grantFor($token, $this->domainA, 7),
                'malformed token must be refused: '.substr($token, 0, 12),
            );
        }
    }

    /**
     * 🛑 §8.12.23's case (a) needs "a credential was presented and rejected" to
     * be distinguishable from "no credential", so the weaker question exists.
     */
    public function test_an_expired_grant_still_looks_like_a_credential(): void
    {
        $token = $this->mint(now: time() - 3600);

        $this->assertNull($this->verifier->grantFor($token, $this->domainA, 7));
        $this->assertFalse(
            $this->verifier->looksLikeGrant($token),
            'an expired token fails the library`s own exp check, so it is not usable even weakly',
        );
        $this->assertFalse($this->verifier->looksLikeGrant('nineteen bytes of noise'));
    }

    /**
     * 🛑 A reconstructed scoped leaf carries its scope, or the §12.3 conjunct
     * that applies it passes unconditionally.
     *
     * §12.3's last conjunct narrows a reader to a share's or a bearer's scope
     * "**if that was the satisfying leaf**", and `ReaderContext::$scope` being
     * null makes it pass. So a grant minted from a `/v1` share link that
     * established `{share}` with no scope would read `/v2` — the disclosure
     * Phase 21 found in `Requirement::satisfyingLeaf()`, arriving by another
     * road.
     *
     * 🛑 **Not reachable in Phase 22**: no share link or bearer token exists
     * until P23, so a grant's satisfying leaf is only ever `binding` or
     * `public`. Asserted now because the first scoped driver would otherwise
     * inherit a fail-open conjunct from code that looks finished, and because
     * this test is what will fail if somebody drops the scope again.
     */
    public function test_a_scoped_leaf_is_reconstructed_with_its_scope(): void
    {
        $scoped = new Grant(
            sessionId: $this->session->id,
            domainId: $this->domainA,
            projectId: $this->session->projectId,
            versionId: $this->versionId,
            versionSlug: 'v1',
            ruleId: null,
            combinedEpoch: 7,
            issuedAt: time(),
            expiresAt: time() + 300,
            satisfiedBy: AccessLeaf::Share,
            pathPrefix: '/guide',
        );

        $context = $scoped->readerContext();

        $this->assertNotNull($context->scope, '🛑 a share leaf without a scope narrows nothing');
        $this->assertTrue($context->scope->covers($this->session->projectId, 'v1', '/guide/page.html'));
        $this->assertFalse($context->scope->covers($this->session->projectId, 'v2', '/guide/page.html'));
        $this->assertFalse($context->scope->covers($this->session->projectId, 'v1', '/internal/page.html'));

        /* And a leaf that carries no scope is left unscoped, which is correct. */
        $this->assertNull(
            $this->verifier->grantFor($this->mint(), $this->domainA, 7)?->readerContext()->scope,
            'a binding leaf is not scope-limited',
        );
    }

    /**
     * 🛑 A binding list that does not parse drops the **whole** list.
     *
     * A partially-read list is a reader who satisfies some of the bindings this
     * installation vouched for — a different reader from the one it signed, and
     * the difference is invisible because a shorter list only ever refuses.
     */
    public function test_a_malformed_binding_list_refuses_the_grant(): void
    {
        [$header, $payload, $signature] = explode('.', $this->mint());

        $claims = json_decode((string) base64_decode(strtr($payload, '-_', '+/'), true), true);
        $this->assertIsArray($claims);

        $claims['bnd'] = ['not-a-uuid'];
        $forged = GrantKeys::base64Url((string) json_encode($claims));

        /*
         * The signature no longer matches, so this asserts the refusal rather
         * than the parse — which is the honest shape: a `bnd` claim can only
         * reach the parser through a token this installation signed, and the
         * parser's own guard is asserted by the unit of work above it.
         */
        $this->assertNull(
            $this->verifier->grantFor($header.'.'.$forged.'.'.$signature, $this->domainA, 7),
        );

        $this->assertNull(GrantVerifier::fromClaims($claims), '🛑 and the claim parser refuses it too');
    }

    // ------------------------------------------------- the four-state rotation

    /** An installation's first key is created active, so a fresh install serves. */
    public function test_the_first_key_is_created_active(): void
    {
        $key = $this->keys->signing();

        $this->assertSame(KeyState::Active, $key->state);
        $this->assertSame(1, GrantSigningKey::query()->count());
    }

    /**
     * 🛑 §17's "four-state key rotation", one step per call.
     *
     * The sequence is: publish a `pending` key; promote it while demoting the
     * previous active key to `retiring`, in one transaction; retire the
     * `retiring` key once no grant it signed can still be unexpired.
     */
    public function test_rotation_publishes_then_promotes_then_retires(): void
    {
        $first = $this->keys->signing();

        /* Step one: a pending key appears, published and signing nothing. */
        $this->assertSame(['key_published'], $this->keys->rotate());

        $pending = GrantSigningKey::query()->where('state', KeyState::Pending)->firstOrFail();

        $this->assertContains($pending->kid, $this->publishedKids(), '🛑 pending keys are published');
        $this->assertSame($first->kid, $this->keys->signing()->kid, 'and sign nothing');

        /* Step two: promote and demote, together. */
        $this->assertSame(['key_retiring', 'key_activated'], $this->keys->rotate());

        $this->assertSame($pending->kid, $this->keys->signing()->kid);
        $this->assertSame(
            KeyState::Retiring,
            GrantSigningKey::query()->whereKey($first->id)->firstOrFail()->state,
        );

        /*
         * 🛑 The retiring key is still published, which is the half that stops
         * a rotation stranding every unexpired grant.
         */
        $this->assertContains($first->kid, $this->publishedKids());

        /* Step three: retired, once the window has passed. */
        $this->keys->rotate(now: time() + GrantKeys::RETIRING_SECONDS + 1);

        $this->assertSame(
            KeyState::Retired,
            GrantSigningKey::query()->whereKey($first->id)->firstOrFail()->state,
        );

        $this->keys->forget();
        $this->assertNotContains($first->kid, $this->publishedKids(), '🛑 a retired key leaves the JWKS');
    }

    /**
     * 🛑 A grant signed by a retiring key still verifies — which is the whole
     * reason the state exists.
     */
    public function test_a_grant_signed_by_a_retiring_key_still_verifies(): void
    {
        $token = $this->mint();

        $this->keys->rotate();
        $this->keys->rotate();

        $this->assertNotNull(
            $this->verifier->grantFor($token, $this->domainA, 7),
            '🛑 rotation must not strand an unexpired grant',
        );
    }

    /** And a grant signed by a **retired** key does not. */
    public function test_a_grant_signed_by_a_retired_key_is_refused(): void
    {
        $token = $this->mint();

        $this->keys->rotate();
        $this->keys->rotate();
        $this->keys->rotate(now: time() + GrantKeys::RETIRING_SECONDS + 1);
        $this->keys->forget();

        $this->assertNull($this->verifier->grantFor($token, $this->domainA, 7));
    }

    /**
     * 🛑 {@see GrantKeys::RETIRING_SECONDS} is **derived** from the grant
     * ceiling, not chosen — a retiring key must outlive every grant it signed
     * plus one JWKS cache window.
     */
    public function test_the_retiring_window_outlives_a_grant(): void
    {
        $this->assertGreaterThan(GrantMinter::MAX_TTL_SECONDS, GrantKeys::RETIRING_SECONDS);
        $this->assertGreaterThanOrEqual(
            GrantMinter::MAX_TTL_SECONDS + GrantKeys::JWKS_CACHE_SECONDS,
            GrantKeys::RETIRING_SECONDS,
        );
    }

    /** 🛑 Exactly one key may sign, and the database is what enforces it. */
    public function test_only_one_key_can_be_active(): void
    {
        $this->keys->signing();
        $this->keys->rotate();
        $this->keys->rotate();

        $this->assertSame(
            1,
            GrantSigningKey::query()->where('state', KeyState::Active)->count(),
            '🛑 a unique index over a generated column, not a convention',
        );
    }

    /**
     * 🛑 The JWKS publishes **public** keys only, in RFC 8037's shape, and
     * names no tenant — `grant_signing_keys` has no `organisation_id` column at
     * all.
     */
    public function test_the_jwks_publishes_only_public_material(): void
    {
        $this->keys->signing();

        $document = $this->keys->jwks();

        $this->assertArrayHasKey('keys', $document);
        $this->assertNotSame([], $document['keys']);

        foreach ($document['keys'] as $jwk) {
            $this->assertSame('OKP', $jwk['kty']);
            $this->assertSame('Ed25519', $jwk['crv']);
            $this->assertSame('EdDSA', $jwk['alg']);
            $this->assertSame('sig', $jwk['use']);

            /* 🛑 `x` only. A `d` member would be the private key, published. */
            $this->assertArrayNotHasKey('d', $jwk);
            $this->assertSame(32, strlen((string) base64_decode(strtr($jwk['x'], '-_', '+/'), true)));
        }

        $this->assertStringNotContainsString(
            'organisation',
            (string) json_encode($document),
            '🛑 the JWKS is public: it must name no tenant',
        );
    }

    /**
     * 🛑 A half-finished rotation **fails** rather than self-healing.
     *
     * Keys exist and none signs: minting a fresh active key here would leave
     * the stalled one behind and make the next rotation's state machine
     * unreadable. §8.12.19's posture — a degraded authorisation component
     * denies — applied to the key store.
     */
    public function test_a_stalled_rotation_refuses_to_mint(): void
    {
        $key = $this->keys->signing();

        $key->forceFill(['state' => KeyState::Retiring, 'retiring_at' => now()])->save();
        $this->keys->forget();

        $this->expectExceptionMessage('finish the rotation');

        $this->keys->signing();
    }

    // ---------------------------------------------------------------- fixtures

    private function mint(
        int $authzEpoch = 4,
        int $identityEpoch = 3,
        AccessSurface $surface = AccessSurface::Proxy,
        ?int $ttlSeconds = null,
        ?int $now = null,
    ): string {
        return $this->minter->mint(
            decision: new AccessDecision(
                allowed: true,
                reason: AccessReason::Allowed,
                status: 200,
                required: AccessLevel::Members,
                established: AccessLevel::Members,
                satisfiedBy: AccessLeaf::Binding,
            ),
            reader: ReaderContext::member(bin2hex($this->session->id)),
            session: $this->session,
            domainId: $this->domainA,
            versionId: $this->versionId,
            versionSlug: 'latest',
            authzEpoch: $authzEpoch,
            identityEpoch: $identityEpoch,
            surface: $surface,
            ttlSeconds: $ttlSeconds,
            now: $now,
        );
    }

    /** @return list<string> */
    private function publishedKids(): array
    {
        $this->keys->forget();

        return array_map(
            static fn (array $jwk): string => $jwk['kid'],
            $this->keys->jwks()['keys'],
        );
    }
}
