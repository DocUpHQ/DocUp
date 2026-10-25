<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Webhooks;

/**
 * How a provider spells a digest on the wire.
 *
 * Two cases, because the four schemes of §11.1 use two: lowercase hex
 * (GitHub, Bitbucket, Gitea, Forgejo) and standard base64 (GitLab's Standard
 * Webhooks). The distinction is in an enum rather than a boolean so the
 * comparison in {@see RawBodyVerifier} reads as a statement about the
 * provider rather than as a flag.
 */
enum SignatureEncoding
{
    case Hex;
    case Base64;

    /** Encode a raw digest the way the provider would have. */
    public function encode(string $rawDigest): string
    {
        return match ($this) {
            self::Hex => bin2hex($rawDigest),
            self::Base64 => base64_encode($rawDigest),
        };
    }
}
