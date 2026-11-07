<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Readers\Grants;

/**
 * §17's "four-state key rotation", with the reason for each state beside it.
 *
 * 🛑 The four exist because a grant's verifier is **not** the minter. §8.12.11
 * puts "public keys at a JWKS endpoint" and §8.12.12 forbids any minting key
 * reaching an edge component, so the edge learns about a key by fetching a
 * document it then caches. Two independent windows follow from that, and each
 * needs a state:
 *
 * - A key must be **published before it signs**, or the first grant under it
 *   reaches an edge whose cached JWKS predates the key. That is `Pending`.
 * - A key must stay **published after it stops signing**, or every unexpired
 *   grant under it fails the moment rotation begins. That is `Retiring`, and
 *   it must outlast §8.12.11's `exp ≤ 10 minutes`.
 *
 * Collapse either and rotation becomes an outage that only happens during a
 * rotation — the class of bug that is tested once, works, and fails in
 * production a year later.
 */
enum KeyState: string
{
    /**
     * Published in the JWKS, signs nothing.
     *
     * Its job is to be in a verifier's cache before it is needed.
     */
    case Pending = 'pending';

    /**
     * 🛑 The one key that signs. At most one exists, and that is enforced by a
     * unique index over a generated column rather than by this enum — see the
     * migration's note on `active_marker`.
     */
    case Active = 'active';

    /**
     * Published, signs nothing, and grants minted under it are still valid.
     *
     * A key leaves this state only once no grant it signed can still be
     * unexpired, which is why {@see GrantKeys::RETIRING_SECONDS} is derived
     * from the grant TTL ceiling rather than chosen.
     */
    case Retiring = 'retiring';

    /**
     * Absent from the JWKS. The row survives so that an audit can name the key
     * a historical decision was signed by.
     */
    case Retired = 'retired';

    /**
     * Whether a key in this state belongs in the published JWKS document.
     *
     * 🛑 Three of four, and `Active` is not the only one. A verifier needs
     * every key that *could* have signed a grant it is about to see, which is
     * the next key, the current one and the one just stood down.
     */
    public function published(): bool
    {
        return $this !== self::Retired;
    }

    /** Whether a key in this state may sign. Exactly one state may. */
    public function signs(): bool
    {
        return $this === self::Active;
    }
}
