<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers\Drivers;

use App\Access\AccessLeaf;
use App\Auth\Providers\AttemptResult;
use App\Auth\Providers\AuthComponent;
use App\Auth\Providers\BindingContext;
use App\Auth\Providers\ProbeResult;
use App\Auth\Providers\ReaderPresentation;

/**
 * §8.12.17's `public` driver: the `{public}` terminal, satisfied by everybody.
 *
 * 🛑 **Not a loophole, and §8.12.7 is why.** The satisfiability invariant
 * refuses any requirement satisfiable without an identity-bearing leaf "unless
 * it is literally the public terminal", so a rule cannot *rest* on this driver
 * while pretending to require something. And §12.3's lattice keeps a public
 * leaf from reaching a resource that demands more: satisfying `{public}` makes
 * a reader `public`, which is the weakest rung.
 *
 * A public terminal that an anonymous reader could not satisfy would make
 * public documentation unservable, which is the other half of why it exists.
 *
 * 🛑 It holds no config, no secret and nothing to probe — and it is a driver
 * rather than a special case in the resolver precisely so that §12.3 has one
 * code path. A resolver with an `if ($type === 'public')` branch is a resolver
 * with two.
 */
final class PublicDriver implements AuthComponent
{
    public static function type(): string
    {
        return 'public';
    }

    public static function leaf(): AccessLeaf
    {
        return AccessLeaf::Public;
    }

    public static function allowsProjectScope(): bool
    {
        return true;
    }

    public static function mayMapDashboardRoles(): bool
    {
        return false;
    }

    /** @param  array<string, mixed>  $config */
    public function validate(array $config): array
    {
        /*
         * 🛑 Returns an empty array rather than `$config`. A `public` binding
         * with configuration would be configuration nothing reads, which is
         * how a key that looks like it does something survives into a release.
         */
        return [];
    }

    public function probe(BindingContext $binding): ProbeResult
    {
        return ProbeResult::pass('the public terminal needs no provider');
    }

    public function attempt(BindingContext $binding, ReaderPresentation $presented): AttemptResult
    {
        /*
         * 🛑 Satisfied without reading `$presented` at all, which is the whole
         * definition. Note what is NOT returned: no subject. §20.3 aggregates
         * an allow "per session, version and hour", and a public reader has no
         * session — giving them one would be inventing an identity for somebody
         * who presented none.
         */
        return AttemptResult::satisfiedBy(AccessLeaf::Public);
    }
}
