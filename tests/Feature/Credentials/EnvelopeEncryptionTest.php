<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Credentials;

use App\Auth\OrganisationContext;
use App\Credentials\CredentialKind;
use App\Credentials\CredentialVault;
use App\Credentials\EnvelopeCipher;
use App\Credentials\SealedSecret;
use App\Credentials\SecretString;
use App\Models\Organisation;
use App\Models\RepositoryCredential;
use App\Source\Provider;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\DB;
use Tests\TestCase;

/**
 * §9.1.7 envelope encryption, and §8.3.3's four credential kinds.
 *
 * 🛑 Three properties, each of which a plain `Crypt::encryptString()` would
 * fail while still looking encrypted:
 *
 *  1. the plaintext is **not** in the row, in any encoding;
 *  2. a ciphertext **cannot be moved** between records, because the AAD binds
 *     it to the row's identity — an operator with database write access but
 *     no credential access must not be able to point one organisation's token
 *     at their own repository;
 *  3. rotation **rewrites the wrapped key only**, never the payload, which is
 *     what makes "may rotate but never read" a property of the call graph
 *     rather than a promise.
 */
final class EnvelopeEncryptionTest extends TestCase
{
    use DatabaseTransactions;

    private OrganisationContext $context;

    private Organisation $organisation;

    private CredentialVault $vault;

    private const TOKEN = 'ghp_0123456789abcdefghijklmnopqrstuvwxyzAB';

    protected function setUp(): void
    {
        parent::setUp();

        $this->context = app(OrganisationContext::class);
        $this->context->spanAllOrganisations();

        $this->organisation = Organisation::query()->create([
            'name' => 'Vault Co',
            'slug' => 'vault-'.bin2hex(random_bytes(4)),
        ]);

        $this->context->for($this->organisation->id);
        $this->vault = app(CredentialVault::class);
    }

    protected function tearDown(): void
    {
        $this->context->forget();

        parent::tearDown();
    }

    public function test_it_seals_and_opens_every_credential_kind(): void
    {
        $payloads = [
            CredentialKind::PersonalAccessToken->value => ['token' => self::TOKEN],
            CredentialKind::OAuth->value => ['access_token' => 'oauth-'.self::TOKEN, 'refresh_token' => 'refresh-xyz-12345'],
            CredentialKind::GitHubApp->value => [
                'app_id' => '123456',
                'installation_id' => '7891011',
                'private_key' => "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQ\n-----END RSA PRIVATE KEY-----",
            ],
            CredentialKind::DeployKey->value => ['private_key' => "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNza\n-----END OPENSSH PRIVATE KEY-----"],
        ];

        foreach ($payloads as $kindValue => $payload) {
            $kind = CredentialKind::from($kindValue);
            $credential = $this->store($kind, $payload);

            $opened = $this->vault->open($credential->fresh() ?? $credential);

            $this->assertSame(array_keys($payload), array_keys($opened));

            foreach ($payload as $field => $value) {
                $this->assertInstanceOf(SecretString::class, $opened[$field]);
                $this->assertSame($value, $opened[$field]->reveal(), $kindValue.'.'.$field);
            }
        }
    }

    /** 🛑 Property 1: nothing in the row is the plaintext, in any encoding. */
    public function test_the_plaintext_is_absent_from_the_stored_row(): void
    {
        $credential = $this->store(CredentialKind::PersonalAccessToken, ['token' => self::TOKEN]);

        /** @var object $row */
        $row = DB::table('repository_credentials')
            ->where('id', $credential->getRawOriginal('id'))
            ->first();

        $serialised = serialize($row);

        foreach ([
            self::TOKEN,
            base64_encode(self::TOKEN),
            rawurlencode(self::TOKEN),
            bin2hex(self::TOKEN),
        ] as $encoding) {
            $this->assertStringNotContainsString($encoding, $serialised);
        }

        // And the model's own serialisation, which is what an API or an
        // Inertia prop would carry (§8.3.3).
        $json = (string) json_encode($credential->toArray());

        $this->assertStringNotContainsString(self::TOKEN, $json);
        $this->assertStringNotContainsString('ciphertext', $json);
        $this->assertStringNotContainsString('wrapped_key', $json);
    }

    /**
     * 🛑 Property 2: a ciphertext moved between rows does not open.
     *
     * This is the attack `Crypt::encryptString()` would permit: both rows are
     * encrypted under the same key, so swapping the columns yields a
     * credential that decrypts perfectly and belongs to somebody else.
     */
    public function test_a_ciphertext_cannot_be_moved_to_another_record(): void
    {
        $mine = $this->store(CredentialKind::PersonalAccessToken, ['token' => self::TOKEN]);
        $theirs = $this->store(CredentialKind::PersonalAccessToken, ['token' => 'ghp_ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ']);

        /*
         * Two tamper shapes, because the AAD guards **both** layers of the
         * envelope and they fail at different gates:
         *
         *  - the whole envelope moved → the wrapped key will not unwrap, so
         *    the refusal is "no configured key opens this credential";
         *  - the ciphertext alone moved, keeping this row's wrapped key → the
         *    data key unwraps and the payload does not, so the refusal names
         *    the mismatch.
         *
         * The second is the shape that makes the AAD worth having: the data
         * key is this row's, so nothing about the key material is wrong. Only
         * the binding catches it.
         */
        $wholeEnvelope = new RepositoryCredential;
        $wholeEnvelope->forceFill($mine->getAttributes());
        $wholeEnvelope->applySealed($theirs->sealed());

        try {
            $this->vault->open($wholeEnvelope);
            $this->fail('a stolen envelope opened');
        } catch (\RuntimeException $refused) {
            $this->assertStringContainsString('no configured key opens this credential', $refused->getMessage());
        }

        $ciphertextOnly = new RepositoryCredential;
        $ciphertextOnly->forceFill($mine->getAttributes());
        $ciphertextOnly->applySealed(new SealedSecret(
            version: $mine->envelope_version,
            kekFingerprint: $mine->kek_fingerprint,
            wrappedKey: $mine->wrapped_key,
            ciphertext: $theirs->ciphertext,
        ));

        try {
            $this->vault->open($ciphertextOnly);
            $this->fail('a stolen ciphertext opened under this record key');
        } catch (\RuntimeException $refused) {
            $this->assertStringContainsString('does not belong to the record that requested it', $refused->getMessage());
        }
    }

    /**
     * 🛑 Property 3: rotation rewrites the wrapped key and leaves the payload
     * byte-identical.
     *
     * The assertion is on the ciphertext being **unchanged**, because that is
     * the observable consequence of a rotation path with no decrypt in it.
     * A rotation that decrypted and re-encrypted would produce a different
     * ciphertext — correct data, and a capability §9.1.7 forbids.
     */
    public function test_rotation_rewraps_the_key_without_touching_the_payload(): void
    {
        $credential = $this->store(CredentialKind::PersonalAccessToken, ['token' => self::TOKEN]);

        $originalCiphertext = $credential->ciphertext;
        $originalWrappedKey = $credential->wrapped_key;

        // A new KEK: the current key becomes a previous key.
        $oldKey = (string) config('app.key');
        $newKey = 'base64:'.base64_encode(random_bytes(32));

        $rotated = new CredentialVault(new EnvelopeCipher(
            self::rawKey($newKey),
            [self::rawKey($oldKey)],
        ));

        $this->assertTrue($rotated->rotate($credential));

        $this->assertSame($originalCiphertext, $credential->ciphertext, 'rotation re-encrypted the payload');
        $this->assertNotSame($originalWrappedKey, $credential->wrapped_key, 'rotation did not rewrap the data key');

        // Still openable, under the new key only.
        $opened = $rotated->open($credential);
        $this->assertSame(self::TOKEN, $opened['token']->reveal());

        // And the second rotation is a no-op, so a sweep reports real work.
        $this->assertFalse($rotated->rotate($credential));
    }

    /** §9.1.7's `APP_PREVIOUS_KEYS`: a record sealed under an old key still opens. */
    public function test_a_previous_key_still_opens_a_record(): void
    {
        $credential = $this->store(CredentialKind::PersonalAccessToken, ['token' => self::TOKEN]);

        $withNewKeyOnly = new EnvelopeCipher(random_bytes(32));
        $withBoth = new EnvelopeCipher(random_bytes(32), [self::rawKey((string) config('app.key'))]);

        try {
            $withNewKeyOnly->open($credential->sealed(), $credential->aad());
            $this->fail('a record opened under a key that never sealed it');
        } catch (\RuntimeException $failure) {
            $this->assertStringContainsString('APP_KEY', $failure->getMessage());
        }

        $opened = $withBoth->open($credential->sealed(), $credential->aad());
        $this->assertSame(self::TOKEN, $opened['token']->reveal());
    }

    /** Each record gets its own data key, so one compromise is one credential. */
    public function test_every_record_has_its_own_data_key(): void
    {
        $first = $this->store(CredentialKind::PersonalAccessToken, ['token' => self::TOKEN]);
        $second = $this->store(CredentialKind::PersonalAccessToken, ['token' => self::TOKEN]);

        $this->assertNotSame($first->wrapped_key, $second->wrapped_key);
        $this->assertNotSame(
            $first->ciphertext,
            $second->ciphertext,
            'identical plaintexts produced identical ciphertexts',
        );
    }

    /** A payload that does not match its kind is refused at the boundary. */
    public function test_it_refuses_a_payload_that_does_not_match_its_kind(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $this->store(CredentialKind::GitHubApp, ['app_id' => '1']);
    }

    public function test_it_refuses_an_unknown_field(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $this->store(CredentialKind::PersonalAccessToken, ['token' => self::TOKEN, 'extra' => 'x']);
    }

    /** @param  array<string, string>  $payload */
    private function store(CredentialKind $kind, array $payload): RepositoryCredential
    {
        return $this->vault->store(
            organisationId: $this->organisation->id,
            kind: $kind,
            provider: Provider::GitHub,
            providerHost: 'github.com',
            displayName: 'CI credential',
            payload: $payload,
        );
    }

    /** @return non-empty-string */
    private static function rawKey(string $key): string
    {
        $raw = str_starts_with($key, 'base64:')
            ? (string) base64_decode(substr($key, 7), true)
            : $key;

        // A key the cipher cannot use would make every assertion below pass
        // vacuously, so this is a precondition and not a type-checker favour.
        if ($raw === '') {
            throw new \RuntimeException('APP_KEY is empty; this test cannot prove anything');
        }

        return $raw;
    }
}
