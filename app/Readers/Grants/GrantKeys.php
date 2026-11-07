<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Readers\Grants;

use App\Audit\ActorType;
use App\Audit\Audit;
use App\Credentials\EnvelopeCipher;
use App\Models\GrantSigningKey;
use App\Tls\CertificateStore;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;

/**
 * The installation's Ed25519 grant keypairs, their four-state rotation and the
 * JWKS document (§8.12.11, §17).
 *
 * 🛑 **The sole opener of a grant signing key**, exactly as
 * {@see CertificateStore::pem()} is the sole opener of a certificate
 * key. §8.12.12: "No symmetric key capable of minting a grant MUST reach any
 * edge component" — the asymmetric design means the private half never has to
 * travel at all, and this class is where that stops being an aspiration.
 *
 * ## 🛑 Why the public half is cached and the private half is not
 *
 * Verification happens on every documentation request at Tier A, so the JWKS
 * is read from a cache keyed on nothing: the document changes only on a
 * rotation, and a rotation forgets the key. Signing happens once per grant
 * mint — at most once per ten minutes per session — so opening the envelope
 * each time costs nothing worth saving, and a cached plaintext signing key
 * would put the one secret that mints read access into Valkey, which §8.12.12
 * exists to prevent.
 */
final readonly class GrantKeys
{
    /**
     * How long a key stays `retiring` before it leaves the JWKS.
     *
     * 🛑 **Derived, not chosen.** A `retiring` key must outlive every grant it
     * signed, and §8.12.11 caps a grant at {@see GrantMinter::MAX_TTL_SECONDS}.
     * Twice that, plus the JWKS cache TTL, is the smallest value that cannot
     * strand a grant: the last grant it signed expires after one TTL, and a
     * verifier holding a stale JWKS needs one cache window to notice.
     */
    public const int RETIRING_SECONDS = 2 * GrantMinter::MAX_TTL_SECONDS + self::JWKS_CACHE_SECONDS;

    /**
     * How long a verifier may cache the JWKS document.
     *
     * 🛑 Short, because {@see KeyState::Pending} is only useful if a verifier
     * refreshes before the pending key becomes active. Sixty seconds means a
     * rotation can proceed one minute after publishing, and the document is
     * tiny and immutable between rotations.
     */
    public const int JWKS_CACHE_SECONDS = 60;

    private const string CACHE_KEY = 'authz:grant-jwks';

    public function __construct(private EnvelopeCipher $cipher) {}

    /**
     * The key that signs, creating the installation's first one if there is
     * none.
     *
     * 🛑 **Creates and activates in one step, only when the table is empty.**
     * A fresh installation must be able to serve a private project without an
     * operator running a rotation command first, and the alternative — serving
     * nothing until somebody notices — is an outage on first use. Every
     * *subsequent* key goes through `pending` properly, because by then there
     * is a verifier whose cache could be stale.
     *
     * @throws \RuntimeException when the table holds keys but none is active,
     *                           which is a half-finished rotation and must not
     *                           be papered over by minting a new key
     */
    public function signing(): GrantSigningKey
    {
        $active = GrantSigningKey::query()->where('state', KeyState::Active)->first();

        if ($active instanceof GrantSigningKey) {
            return $active;
        }

        if (GrantSigningKey::query()->exists()) {
            /*
             * 🛑 Fail rather than self-heal. Keys exist and none signs, which
             * means a rotation stopped half way; minting a fresh active key
             * here would leave the stalled one behind and make the next
             * rotation's state machine unreadable. §8.12.19's posture applies —
             * a degraded authorisation component denies.
             */
            throw new \RuntimeException('grant signing keys exist but none is active: finish the rotation');
        }

        return $this->create(activate: true);
    }

    /**
     * Open one key's private half. The only caller is {@see GrantMinter}.
     *
     * 🛑 Not audited per signature, and that is a deliberate difference from
     * {@see CertificateStore::pem()}, which audits every read. A
     * certificate key is read once per issuance; this one is read once per
     * grant mint, which is once per session per ten minutes across every
     * reader on the installation. An audit event per mint would bury §8.22's
     * chain under the product's hottest authenticated path. What *is* audited
     * is every state change below, which is the fact an auditor needs: which
     * key was capable of signing, and when.
     *
     * @return string raw 64 bytes of Ed25519 secret key
     *
     * @throws \RuntimeException when no configured KEK opens the envelope
     */
    public function secretKey(GrantSigningKey $key): string
    {
        $opened = $this->cipher->open($key->sealed(), self::aad($key->kid));

        /*
         * 🛑 `->reveal()`, because {@see \App\Credentials\EnvelopeCipher::open()}
         * returns {@see \App\Credentials\SecretString} values rather than plain
         * strings — deliberately, so that the one place a secret becomes a
         * string is greppable. The first version read the value as a string,
         * failed the guard below and threw "envelope holds no secret_key" about
         * an envelope that had opened perfectly. The guard being fail-closed is
         * why that was a 500 and not an unsigned grant.
         */
        $secret = ($opened['secret_key'] ?? null)?->reveal();

        if (! is_string($secret) || $secret === '') {
            throw new \RuntimeException('grant signing key envelope holds no secret_key');
        }

        $raw = base64_decode($secret, true);

        if ($raw === false || strlen($raw) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
            throw new \RuntimeException('grant signing key is not an Ed25519 secret key');
        }

        return $raw;
    }

    /**
     * §8.12.11's JWKS document: every key a verifier should hold.
     *
     * 🛑 Three of the four states, never only the active one. See
     * {@see KeyState::published()} — a verifier needs the key that is about to
     * sign and the key that just stopped, or rotation strands grants at both
     * ends.
     *
     * The shape is RFC 8037 §2 (`OKP`/`Ed25519`), which is what
     * `firebase/php-jwt` and every edge-side verifier expect for `EdDSA`.
     *
     * @return array{keys: list<array{kty: string, crv: string, use: string, alg: string, kid: string, x: string}>}
     */
    public function jwks(): array
    {
        /** @var array{keys: list<array{kty: string, crv: string, use: string, alg: string, kid: string, x: string}>} $document */
        $document = Cache::remember(self::CACHE_KEY, self::JWKS_CACHE_SECONDS, function (): array {
            $keys = [];

            $published = GrantSigningKey::query()
                ->whereIn('state', array_values(array_map(
                    static fn (KeyState $state): string => $state->value,
                    array_filter(KeyState::cases(), static fn (KeyState $s): bool => $s->published()),
                )))
                ->orderBy('created_at')
                ->get();

            foreach ($published as $key) {
                $keys[] = [
                    'kty' => 'OKP',
                    'crv' => 'Ed25519',
                    'use' => 'sig',
                    'alg' => 'EdDSA',
                    'kid' => $key->kid,
                    'x' => self::base64Url($key->public_key),
                ];
            }

            return ['keys' => $keys];
        });

        return $document;
    }

    /**
     * The public key for one `kid`, for a verifier that holds a token.
     *
     * Read from the same cached document the JWKS endpoint serves, so a
     * verifier inside the application and one at the edge cannot disagree
     * about which keys exist.
     *
     * @return string|null raw 32 bytes, or null when the `kid` is unknown or
     *                     has been retired
     */
    public function publicKey(string $kid): ?string
    {
        foreach ($this->jwks()['keys'] as $jwk) {
            if (hash_equals($jwk['kid'], $kid)) {
                $raw = base64_decode(strtr($jwk['x'], '-_', '+/'), true);

                return $raw === false ? null : $raw;
            }
        }

        return null;
    }

    /**
     * Mint a new keypair.
     *
     * @param  bool  $activate  true only for an installation's first key; see
     *                          {@see self::signing()}
     */
    public function create(bool $activate = false): GrantSigningKey
    {
        $pair = sodium_crypto_sign_keypair();
        $public = sodium_crypto_sign_publickey($pair);
        $secret = sodium_crypto_sign_secretkey($pair);

        /*
         * The `kid` is a digest of the public key. Not a counter: two
         * installations must never collide (a verifier may front both), and an
         * ordinal would imply a sequence that {@see KeyState} already carries
         * and could contradict.
         */
        $kid = substr(self::base64Url(hash('sha256', $public, binary: true)), 0, 32);

        $sealed = $this->cipher->seal(
            ['secret_key' => base64_encode($secret)],
            self::aad($kid),
        );

        /*
         * 🛑 Wiped as soon as it is sealed. `sodium_memzero` is the one
         * mitigation available for a secret that has existed in a PHP string:
         * it cannot be un-copied, but it can be prevented from lingering in a
         * page that is later swapped, dumped by a core file or read by a
         * `var_dump` three frames up.
         */
        sodium_memzero($secret);
        sodium_memzero($pair);

        $state = $activate ? KeyState::Active : KeyState::Pending;

        $key = new GrantSigningKey;
        $key->forceFill([
            'kid' => $kid,
            'state' => $state,
            'public_key' => $public,
            'envelope_version' => $sealed->version,
            'kek_fingerprint' => $sealed->kekFingerprint,
            'wrapped_key' => $sealed->wrappedKey,
            'ciphertext' => $sealed->ciphertext,
            'activated_at' => $activate ? now() : null,
        ])->save();

        $this->forget();

        Audit::record(
            action: 'authz.grant_key.created',
            actorType: ActorType::System,
            subjectType: 'grant_signing_key',
            subjectId: $key->id,
            payload: ['kid' => $kid, 'state' => $state->value],
        );

        return $key;
    }

    /**
     * Advance the rotation by one step, and return what moved.
     *
     * 🛑 **One step per call, in one transaction, and the order inside it is
     * the whole safety property.** The sequence a rotation goes through is:
     *
     *   0. every call first retires any `retiring` key whose
     *      {@see self::RETIRING_SECONDS} window has passed — see the note at
     *      the top of the body for why this is not step 3;
     *   1. a new key appears as `pending` — published, signing nothing;
     *   2. the next call promotes it to `active` and demotes the previous
     *      active key to `retiring` — *in that one transaction*, because the
     *      unique index permits exactly one active key and the two statements
     *      must not be separable by a crash.
     *
     * Reversing 2's two statements makes the promotion fail on the unique
     * index — which is the correct failure, but leaves the installation with
     * no `pending` key and an operator who has to read this comment to find
     * out why. Doing them in separate transactions risks an instant with no
     * active key at all, during which every grant mint fails.
     *
     * @return list<string> fixed-vocabulary descriptions of what changed
     */
    public function rotate(?int $now = null): array
    {
        $now ??= time();

        /*
         * 🛑 **The retirement sweep runs first, and unconditionally.**
         *
         * The first version put it after the promotion and returned early from
         * the publish branch, so a `retiring` key whose window had passed was
         * only ever retired by a call that also had a `pending` key to promote
         * — which is a call an operator makes *because* they are rotating,
         * not because a window expired. A key therefore stayed in the JWKS
         * indefinitely on any installation that rotated once and then stopped.
         *
         * Not a disclosure: a retiring key signs nothing, so the worst of it
         * was a JWKS document that kept a key nobody could use. But §17's
         * fourth state is the one that says "no longer trusted", and a state
         * machine that cannot reach its final state has three states and a
         * comment. Caught by the test walking all three steps rather than
         * asserting each in isolation.
         *
         * It is also its own method, because the scheduler calls **only** this
         * half — see {@see self::retireExpired()}.
         */
        $moved = array_fill(0, $this->retireExpired($now), 'key_retired');

        $pending = GrantSigningKey::query()
            ->where('state', KeyState::Pending)
            ->orderBy('created_at')
            ->first();

        if (! $pending instanceof GrantSigningKey) {
            $this->create();
            $this->forget();

            return array_merge($moved, ['key_published']);
        }

        DB::transaction(function () use ($pending, &$moved): void {
            /*
             * Demote first. See the note above: the unique index over
             * `active_marker` means the promotion cannot succeed while another
             * row is active, so the order is not a preference.
             */
            $previous = GrantSigningKey::query()->where('state', KeyState::Active)->first();

            if ($previous instanceof GrantSigningKey) {
                $previous->forceFill([
                    'state' => KeyState::Retiring,
                    'retiring_at' => now(),
                ])->save();

                $moved[] = 'key_retiring';
            }

            $pending->forceFill([
                'state' => KeyState::Active,
                'activated_at' => now(),
            ])->save();

            $moved[] = 'key_activated';
        });

        $this->forget();

        Audit::record(
            action: 'authz.grant_key.rotated',
            actorType: ActorType::System,
            subjectType: 'grant_signing_key',
            subjectId: $pending->id,
            payload: ['kid' => $pending->kid, 'changes' => implode(',', $moved)],
        );

        return $moved;
    }

    /**
     * Retire every `retiring` key whose window has passed, and nothing else.
     *
     * 🛑 **This is the half that is safe to schedule.** The other half —
     * promoting a `pending` key and demoting the active one — is a rotation,
     * and a rotation happening nightly on its own is the wrong default for the
     * keypair that mints read access to every private project: §8.12.11's grant
     * is verified against a JWKS the edge caches, so every rotation is a moment
     * when a stale cache becomes an outage. Promotion stays
     * `docup:readers:rotate`, which an operator runs deliberately.
     *
     * Retirement is pure housekeeping by comparison and **nothing else can do
     * it**: three of {@see KeyState}'s four transitions are time-based, so
     * without a clock a key sits in `retiring` forever and §17's fourth state
     * is unreachable.
     *
     * @param  int|null  $now  unix seconds; null reads the clock
     * @return int how many keys were retired
     */
    public function retireExpired(?int $now = null): int
    {
        $now ??= time();

        $expired = GrantSigningKey::query()
            ->where('state', KeyState::Retiring)
            ->where('retiring_at', '<=', date('Y-m-d H:i:s', $now - self::RETIRING_SECONDS))
            ->get();

        foreach ($expired as $key) {
            $key->forceFill(['state' => KeyState::Retired, 'retired_at' => now()])->save();
        }

        if ($expired->isNotEmpty()) {
            $this->forget();
        }

        return $expired->count();
    }

    /** Drop the cached JWKS, after any state change. */
    public function forget(): void
    {
        Cache::forget(self::CACHE_KEY);
    }

    /**
     * 🛑 The envelope's additional authenticated data, binding a ciphertext to
     * its `kid`.
     *
     * The same argument {@see CertificateStore::aad()} makes: without
     * it, a ciphertext moved between two rows opens cleanly, and the failure
     * appears as a signature nobody can verify with a database that looks
     * correct.
     */
    public static function aad(string $kid): string
    {
        return 'grant_signing_key|'.$kid;
    }

    /** base64url, no padding — what RFC 8037 and JWT both use. */
    public static function base64Url(string $raw): string
    {
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }
}
