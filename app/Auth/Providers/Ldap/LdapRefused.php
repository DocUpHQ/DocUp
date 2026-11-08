<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers\Ldap;

/**
 * An LDAP exchange refused, carrying its reason as a {@see LdapRejection}.
 *
 * 🛑 The `detail` is the **directory's** own text and is for an operator only.
 * `ldap_error()` names hosts, base DNs and sometimes the reason an account is
 * locked; §8.12.23 gives a refused reader the project's `deny_status` and an
 * empty body, so this string must never reach one. {@see LdapRejection::explain()}
 * is what an operator sees and it says nothing the directory told us.
 */
final class LdapRefused extends \RuntimeException
{
    private function __construct(
        public readonly LdapRejection $rejection,
        public readonly string $detail,
    ) {
        parent::__construct($rejection->value.($detail === '' ? '' : ': '.$detail));
    }

    public static function of(LdapRejection $rejection, string $detail = ''): self
    {
        return new self($rejection, $detail);
    }
}
