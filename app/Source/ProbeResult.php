<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Source;

/**
 * What a reachability probe learned (§8.3.4).
 *
 * `status` is null for an `ssh://` repository, which is inspected but not
 * probed — there is no HTTP to speak.
 *
 * 🛑 A 401 or 403 is **not** a failure. It is the normal answer from a private
 * repository probed without a credential, and it is positive evidence: the
 * host exists, speaks TLS under a valid certificate for its own name, did not
 * redirect, and recognises the path well enough to refuse it. Treating it as
 * unreachable would make every private repository unattachable.
 */
final readonly class ProbeResult
{
    public function __construct(
        public InspectedRepositoryUrl $inspected,
        public ?int $status,
    ) {}

    /** The host answered as itself, whatever it thought of our credentials. */
    public function reachable(): bool
    {
        return $this->status === null || $this->status < 500;
    }

    /** The repository exists and is readable without a credential. */
    public function publiclyReadable(): bool
    {
        return $this->status !== null && $this->status >= 200 && $this->status < 300;
    }

    /** A credential will be needed. */
    public function requiresCredential(): bool
    {
        return in_array($this->status, [401, 403, 404], true);
    }
}
