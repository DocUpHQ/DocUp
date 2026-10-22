<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Credentials;

/**
 * A credential in memory, which cannot be printed by accident.
 *
 * 🛑 Phase 05's exit criteria include "no token appears in any log, at any log
 * level", and the realistic way a token reaches a log is not a developer
 * deciding to log it. It is `Log::debug('fetching', ['repo' => $repository])`
 * on a model that happens to carry one, or `"$e"` on an exception whose
 * message interpolated a URL, or `dd($credential)` left in by somebody
 * debugging something else. Every one of those routes goes through a cast to
 * string, `json_encode`, or `var_dump` — so those are the three this class
 * closes, and it closes them by construction rather than by reminding anybody.
 *
 * The plaintext is reachable only through {@see reveal()}, which is greppable:
 * an audit can enumerate every place a credential is actually unwrapped by
 * searching for one method name.
 */
final class SecretString implements \JsonSerializable
{
    public const REDACTED = '[redacted]';

    public function __construct(private string $value)
    {
        /*
         * Registered the moment it exists, so the §8.5.21 log scrubber can
         * remove this exact byte sequence — and its base64 and URL-encoded
         * forms — from anything written while it is in memory. A secret that
         * escapes through a path this class does not control is still caught
         * on the way out.
         */
        SecretRegistry::remember($value);
    }

    /** The plaintext. The only way to get it, and deliberately easy to grep for. */
    public function reveal(): string
    {
        return $this->value;
    }

    public function isEmpty(): bool
    {
        return $this->value === '';
    }

    /** Constant-time comparison; see `App\Support\SecretToken::matches()`. */
    public function equals(self $other): bool
    {
        return hash_equals($other->value, $this->value);
    }

    public function __toString(): string
    {
        return self::REDACTED;
    }

    public function jsonSerialize(): string
    {
        return self::REDACTED;
    }

    /** `var_dump`, `dd`, Symfony's dumper and Laravel's exception renderer. */
    public function __debugInfo(): array
    {
        return ['value' => self::REDACTED];
    }

    /**
     * 🛑 Refused rather than redacted.
     *
     * Serialisation is how a value reaches a queue payload, a cache entry or
     * a session — all of which are storage this class makes no promises
     * about. Returning a redacted form would be worse than throwing: the job
     * would run, the credential would be the string `[redacted]`, and the
     * failure would surface as an authentication error against the provider
     * hours later and nowhere near the cause.
     */
    public function __serialize(): array
    {
        throw new \LogicException(
            'a SecretString may not be serialised; pass the credential id and re-open it from the vault',
        );
    }
}
