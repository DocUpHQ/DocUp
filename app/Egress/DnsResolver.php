<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Egress;

/**
 * The seam between §8.3.9's "resolve-then-pin" and the system resolver.
 *
 * It exists so the rebind case is testable. A DNS-rebind attack is a resolver
 * that answers differently the second time it is asked, and there is no way to
 * exercise that against a real recursive resolver inside a test suite without
 * standing up an authoritative server that lies — which would make the test
 * slow, flaky and dependent on the CI runner's network. The fake in
 * `tests/Support` answers public-then-private in-process, which is the same
 * fact under test.
 */
interface DnsResolver
{
    /**
     * Every address the name currently resolves to.
     *
     * Implementations MUST NOT throw on NXDOMAIN or SERVFAIL; an unresolvable
     * name returns {@see ResolvedHost::none()}, because the caller's answer is
     * the same either way and an exception here would be caught and discarded
     * at the one place it mattered.
     */
    public function resolve(string $host): ResolvedHost;
}
