<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Credentials;

/**
 * Envelope encryption for provider secrets (§9.1.7).
 *
 * > "Provider secrets, certificate keys and ACME account keys MUST use
 * > envelope encryption: a per-record data key wrapped by a KEK from a KMS or
 * > `APP_KEY` with `APP_PREVIOUS_KEYS`. 🛑 `installation_security_admin` may
 * > rotate but never read. 🛑 Losing `APP_KEY` makes every provider secret
 * > unrecoverable."
 *
 * 🛑 **Why not `Crypt::encryptString()`.** Laravel's encrypter would satisfy
 * "encrypted at rest" and fail §9.1.7 in two ways that matter. It encrypts
 * every record directly under `APP_KEY`, so rotating the key means decrypting
 * and re-encrypting every secret — a rotation path that necessarily produces
 * plaintext, which is exactly what "rotate but never read" forbids. And it
 * authenticates nothing about *which record* a ciphertext belongs to, so a
 * row's ciphertext can be copied over another row's and will decrypt happily:
 * an operator with database write access but no credential access could move
 * one organisation's token onto their own repository and have DocUp use it.
 * The AAD below is what makes that fail.
 *
 * The construction:
 *
 *   data key  = 32 CSPRNG bytes, unique per record
 *   payload   = XChaCha20-Poly1305(plaintext, aad, nonce, data key)
 *   wrapped   = XChaCha20-Poly1305(data key,  aad, nonce, KEK)
 *   KEK       = HKDF-SHA256(APP_KEY, "docup.credential.kek.v1")
 *
 * XChaCha20-Poly1305 for its 192-bit nonce: at that width a random nonce per
 * record needs no counter, no coordination between workers and no state that
 * could be rolled back by a restore from backup. With a 96-bit AEAD a random
 * nonce is a birthday bound somebody eventually crosses.
 *
 * HKDF rather than using `APP_KEY` directly, because `APP_KEY` also encrypts
 * sessions and cookies; deriving a separate key per purpose means a flaw that
 * reveals one does not hand over the others.
 */
final readonly class EnvelopeCipher
{
    /** Bumped only if the construction changes; stored with every record. */
    public const VERSION = 1;

    private const KEK_CONTEXT = 'docup.credential.kek.v1';

    /**
     * @param  non-empty-string  $currentKey  raw APP_KEY bytes
     * @param  list<string>  $previousKeys  raw APP_PREVIOUS_KEYS bytes, newest first
     */
    public function __construct(
        private string $currentKey,
        private array $previousKeys = [],
    ) {}

    /** Built from the application's configured keys. */
    public static function fromConfig(): self
    {
        $configured = config('app.key');
        $current = self::decodeKey(is_string($configured) ? $configured : '');

        if ($current === '') {
            throw new \RuntimeException('APP_KEY is not set; provider secrets cannot be sealed (§9.1.7)');
        }

        $previous = [];
        $configuredPrevious = config('app.previous_keys', []);

        foreach (is_array($configuredPrevious) ? $configuredPrevious : [] as $key) {
            $decoded = self::decodeKey(is_string($key) ? $key : '');

            if ($decoded !== '') {
                $previous[] = $decoded;
            }
        }

        return new self($current, $previous);
    }

    /**
     * Seal a payload against one record's identity.
     *
     * @param  array<string, mixed>  $payload
     * @param  string  $aad  the record's identity — see {@see aad()}. Binding
     *                       it into the AEAD is what stops a ciphertext being
     *                       moved between rows.
     */
    public function seal(array $payload, string $aad): SealedSecret
    {
        $plaintext = json_encode($payload, JSON_THROW_ON_ERROR);

        $dataKey = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES);
        $kek = $this->kek($this->currentKey);

        $sealed = new SealedSecret(
            version: self::VERSION,
            kekFingerprint: $this->fingerprint($kek),
            wrappedKey: $this->encrypt($dataKey, $aad, $kek),
            ciphertext: $this->encrypt($plaintext, $aad, $dataKey),
        );

        sodium_memzero($dataKey);
        sodium_memzero($plaintext);

        return $sealed;
    }

    /**
     * Open a sealed payload.
     *
     * 🛑 Every value in the returned map is a {@see SecretString}, which is
     * also what registers it with the §8.5.21 log scrubber. Returning raw
     * strings here would make the exit criterion "no token appears in any log"
     * depend on every caller remembering to wrap them.
     *
     * @return array<string, SecretString>
     *
     * @throws \RuntimeException when no configured key opens the envelope
     */
    public function open(SealedSecret $sealed, string $aad): array
    {
        $dataKey = null;

        foreach ($this->candidateKeks() as $kek) {
            $candidate = $this->decrypt($sealed->wrappedKey, $aad, $kek);

            if ($candidate !== null) {
                $dataKey = $candidate;
                break;
            }
        }

        if ($dataKey === null) {
            /*
             * §9.1.7: losing APP_KEY makes every provider secret
             * unrecoverable, and §15.2 owes operators an escrow path and a
             * "re-enter all IdP secrets" procedure. The message names the
             * cause so that the runbook is reachable from the error.
             */
            throw new \RuntimeException(
                'no configured key opens this credential; check APP_KEY and APP_PREVIOUS_KEYS (§9.1.7, §15.2)',
            );
        }

        $plaintext = $this->decrypt($sealed->ciphertext, $aad, $dataKey);
        sodium_memzero($dataKey);

        if ($plaintext === null) {
            // The data key opened but the payload did not: the AAD does not
            // match, i.e. this ciphertext belongs to a different record.
            throw new \RuntimeException('this credential does not belong to the record that requested it');
        }

        /** @var array<string, string> $decoded */
        $decoded = json_decode($plaintext, true, 8, JSON_THROW_ON_ERROR);
        sodium_memzero($plaintext);

        return array_map(static fn (string $value): SecretString => new SecretString($value), $decoded);
    }

    /**
     * Rewrap a record's data key under the current KEK.
     *
     * 🛑 **The payload is never decrypted here, and this method has no code
     * path that could decrypt it.** That is the implementation of §9.1.7's
     * "may rotate but never read": the capability is absent, not merely
     * unexercised, so an operator holding the rotate permission cannot be
     * argued into reading by anyone — including a future version of this file,
     * where the absence is visible in a diff.
     *
     * @return SealedSecret the same ciphertext, a new wrapped key
     */
    public function rewrap(SealedSecret $sealed, string $aad): SealedSecret
    {
        $dataKey = null;

        foreach ($this->candidateKeks() as $kek) {
            $candidate = $this->decrypt($sealed->wrappedKey, $aad, $kek);

            if ($candidate !== null) {
                $dataKey = $candidate;
                break;
            }
        }

        if ($dataKey === null) {
            throw new \RuntimeException('no configured key opens this credential; cannot rotate (§9.1.7)');
        }

        $kek = $this->kek($this->currentKey);

        $rewrapped = new SealedSecret(
            version: self::VERSION,
            kekFingerprint: $this->fingerprint($kek),
            wrappedKey: $this->encrypt($dataKey, $aad, $kek),
            ciphertext: $sealed->ciphertext,
        );

        sodium_memzero($dataKey);

        return $rewrapped;
    }

    /** The fingerprint of the KEK a new record would be sealed under. */
    public function currentFingerprint(): string
    {
        return $this->fingerprint($this->kek($this->currentKey));
    }

    /**
     * The additional authenticated data binding a ciphertext to its row.
     *
     * Every component is immutable for the life of the record. A mutable
     * field here — a display name, a repository id that can be re-pointed —
     * would mean an edit silently making the credential unopenable.
     */
    public static function aad(string $credentialId, string $organisationId, CredentialKind $kind): string
    {
        return implode('|', [
            'docup.credential.v'.self::VERSION,
            bin2hex($organisationId),
            bin2hex($credentialId),
            $kind->value,
        ]);
    }

    /**
     * The AAD for a §8.5.25 component build variable.
     *
     * A separate domain string from {@see aad()}'s, not a reuse of it: the
     * two record types are sealed by the same cipher under the same KEK, and
     * a shared prefix would mean a ciphertext lifted from one table opening
     * in the other. The component id and the variable name are both
     * immutable for the life of the row — a rename is a delete and an insert,
     * because a renamed variable whose ciphertext no longer opens is worse
     * than one that cannot be renamed.
     */
    public static function variableAad(string $variableId, string $organisationId, string $componentId, string $name): string
    {
        return implode('|', [
            'docup.component_variable.v'.self::VERSION,
            bin2hex($organisationId),
            bin2hex($componentId),
            bin2hex($variableId),
            $name,
        ]);
    }

    /** @return list<string> the current KEK first, then each previous one */
    private function candidateKeks(): array
    {
        return array_map($this->kek(...), [$this->currentKey, ...$this->previousKeys]);
    }

    private function kek(string $key): string
    {
        return hash_hkdf('sha256', $key, SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES, self::KEK_CONTEXT);
    }

    /** Enough to identify a key, far too little to reconstruct one. */
    private function fingerprint(string $kek): string
    {
        return substr(hash('sha256', 'fingerprint|'.$kek), 0, 16);
    }

    /** Nonce-prefixed AEAD ciphertext. */
    private function encrypt(string $plaintext, string $aad, string $key): string
    {
        $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);

        return $nonce.sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($plaintext, $aad, $nonce, $key);
    }

    /** Null on any failure: a wrong key, a wrong AAD, or a tampered ciphertext. */
    private function decrypt(string $sealed, string $aad, string $key): ?string
    {
        $nonceLength = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;

        if (strlen($sealed) <= $nonceLength) {
            return null;
        }

        try {
            $plaintext = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
                substr($sealed, $nonceLength),
                $aad,
                substr($sealed, 0, $nonceLength),
                $key,
            );
        } catch (\SodiumException) {
            return null;
        }

        return $plaintext === false ? null : $plaintext;
    }

    /** `base64:…` as Laravel writes it, or raw bytes. */
    private static function decodeKey(string $key): string
    {
        if ($key === '') {
            return '';
        }

        if (str_starts_with($key, 'base64:')) {
            $decoded = base64_decode(substr($key, 7), true);

            return $decoded === false ? '' : $decoded;
        }

        return $key;
    }
}
