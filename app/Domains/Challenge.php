<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Domains;

use App\Support\Uuid;

/**
 * 🛑 §8.10.4's three proofs, as the records an operator must publish.
 *
 * > "Three complementary mechanisms MUST be supported: an organisation-level
 * > parent claim (`_docup-challenge.<apex>` TXT), after which any host under
 * > it binds with no further proof and **no other organisation may bind under
 * > it**; per-host DNS TXT; and CNAME to an unguessable per-domain
 * > `sha256(domain_id)[0:32]` label under the documentation apex, where the
 * > record is simultaneously route and proof."
 *
 * 🛑 **The CNAME label is unguessable on purpose and that is the whole trick
 * of the third mechanism.** A predictable label — the hostname, or its
 * digest — would let anybody who knows the hostname publish the record, so
 * the record would prove nothing. Deriving it from the `domains` row's id
 * means only somebody who was shown that row can publish it, and the same
 * record is what routes traffic in. One record, proof and route together, no
 * second step an operator can forget.
 *
 * `sha256(domain_id)[0:32]` is the specification's, hex over the **raw 16
 * bytes** of the id rather than its text form — the text form is a rendering
 * and two renderings of one id would be two labels.
 */
final readonly class Challenge
{
    /** §8.10.4's TXT name prefix, for both the parent claim and the per-host proof. */
    public const PREFIX = '_docup-challenge';

    /** The token's length in hex characters: 32 CSPRNG bytes. */
    public const TOKEN_BYTES = 32;

    /**
     * A fresh token.
     *
     * 🛑 CSPRNG, and re-issued on every reclaim (§8.10.9: "always with a
     * freshly issued token"). Stored in the clear, unlike every other token
     * in DocUp, because this one is **published in public DNS by design** —
     * §9.1.4's hash-at-rest rule protects secrets a holder presents back, and
     * hashing a value the holder must read out of the database to publish
     * would make it unusable while protecting nothing.
     */
    public static function token(): string
    {
        return bin2hex(random_bytes(self::TOKEN_BYTES));
    }

    /**
     * The TXT name a per-host or parent proof is published at.
     *
     * The same shape for both, which is deliberate: an operator who has done
     * one has done the other, and §8.10.4 names one record for both cases.
     */
    public static function txtName(string $host): string
    {
        return self::PREFIX.'.'.$host;
    }

    /**
     * §8.10.4's unguessable CNAME label, under the documentation apex.
     *
     * @param  string  $domainId  raw 16 bytes
     */
    public static function cnameLabel(string $domainId): string
    {
        return substr(hash('sha256', $domainId), 0, 32);
    }

    /**
     * The full CNAME target: the unguessable label under the documentation
     * apex.
     *
     * @param  string  $domainId  raw 16 bytes
     */
    public static function cnameTarget(string $domainId, string $docsApex): string
    {
        return self::cnameLabel($domainId).'.'.$docsApex;
    }

    /**
     * The id as the label derivation needs it, from either spelling.
     *
     * A caller holding canonical UUID text rather than raw bytes is the
     * normal case in a controller, and converting in two places is how the
     * dashboard and the verifier come to show different labels.
     */
    public static function labelFor(string $idTextOrBytes): string
    {
        $raw = strlen($idTextOrBytes) === 16 ? $idTextOrBytes : Uuid::toBytes($idTextOrBytes);

        return self::cnameLabel($raw);
    }
}
