<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth;

use App\Auth\Exceptions\TenancyContextMissing;

/**
 * Which organisation the current unit of work belongs to (§8.2.1).
 *
 * 🛑 **Fail loud, not open and not quietly closed.**
 *
 * A global scope needs to know the tenant. There are three things it can do
 * when nobody has said:
 *
 * - **Open** — return every row. One forgotten context becomes full
 *   cross-tenant exposure, which §14 ranks as the top threat. Unacceptable.
 * - **Closed** — return nothing. Safe, but a legitimate query silently returns
 *   an empty set, and "the page is blank" is debugged for an hour before anyone
 *   suspects tenancy.
 * - **Loud** — throw. The caller must either name an organisation or state that
 *   it means all of them.
 *
 * This class is loud. {@see TenancyContextMissing} is the result of forgetting,
 * which is a 500 in development and never a leak.
 *
 * 🛑 **On queued jobs**, read §12.1 before changing anything here. The
 * specification rejects `spatie/laravel-permission` partly because its teams
 * mode carries "a single ambient integer team id with a documented ordering
 * gotcha in queued jobs" — a worker process handles jobs for many tenants in
 * sequence, so ambient state set by job *n* is still set when job *n+1*
 * starts. This is resolved from the container rather than held in a static, and
 * every job MUST set it explicitly in `handle()`. Because the unset state
 * throws rather than inheriting, a job that forgets fails on its first query
 * instead of reading the previous job's tenant.
 */
final class OrganisationContext
{
    /** Raw 16 bytes, or null when nothing has been declared yet. */
    private ?string $organisationId = null;

    /** True when the caller has explicitly asked to span every organisation. */
    private bool $unscoped = false;

    /** Declared, so the distinction between "unset" and "set to null" is real. */
    private bool $declared = false;

    /**
     * Bind the current unit of work to one organisation.
     *
     * @param  string  $organisationId  raw 16 bytes, as every key in this schema is
     */
    public function for(string $organisationId): void
    {
        $this->organisationId = $organisationId;
        $this->unscoped = false;
        $this->declared = true;
    }

    /**
     * Declare that this unit of work legitimately spans every organisation.
     *
     * For installation-wide administration, scheduled maintenance and the
     * `docup:*` commands. Deliberately explicit and deliberately named
     * awkwardly: a reader should notice it.
     */
    public function spanAllOrganisations(): void
    {
        $this->organisationId = null;
        $this->unscoped = true;
        $this->declared = true;
    }

    /** Return to the undeclared state, so the next query must say what it means. */
    public function forget(): void
    {
        $this->organisationId = null;
        $this->unscoped = false;
        $this->declared = false;
    }

    /**
     * Run a callback across every organisation, then restore what was set.
     *
     * Restoring matters more than it looks: without it, one system-wide
     * operation inside a tenant-scoped request would leave the rest of that
     * request unscoped.
     *
     * @template TReturn
     *
     * @param  \Closure(): TReturn  $callback
     * @return TReturn
     */
    public function acrossAllOrganisations(\Closure $callback): mixed
    {
        $previousId = $this->organisationId;
        $previousUnscoped = $this->unscoped;
        $previousDeclared = $this->declared;

        $this->spanAllOrganisations();

        try {
            return $callback();
        } finally {
            $this->organisationId = $previousId;
            $this->unscoped = $previousUnscoped;
            $this->declared = $previousDeclared;
        }
    }

    /** Whether anything has been declared at all. */
    public function isDeclared(): bool
    {
        return $this->declared;
    }

    public function spansAllOrganisations(): bool
    {
        return $this->declared && $this->unscoped;
    }

    /**
     * The organisation every scoped query must filter on.
     *
     * @throws TenancyContextMissing when nothing has been declared
     */
    public function require(): string
    {
        if (! $this->declared) {
            throw TenancyContextMissing::forQuery();
        }

        if ($this->unscoped || $this->organisationId === null) {
            throw TenancyContextMissing::whenSpanningAll();
        }

        return $this->organisationId;
    }

    /** The organisation, or null when spanning all or undeclared. */
    public function current(): ?string
    {
        return $this->organisationId;
    }
}
