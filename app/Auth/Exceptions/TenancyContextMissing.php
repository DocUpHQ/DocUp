<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Exceptions;

/**
 * No organisation was declared before a tenant-scoped query ran (§8.2.1).
 *
 * 🛑 This exception is a feature. The alternative to throwing is returning
 * every organisation's rows, which is §14's top threat, or returning none,
 * which presents as an inexplicably empty page. Failing loudly turns a
 * forgotten declaration into a 500 in development rather than a leak in
 * production.
 *
 * The messages name the fix, because the person who hits this is usually
 * writing a job or a command and has never needed to think about tenancy
 * before.
 */
final class TenancyContextMissing extends \RuntimeException
{
    public static function forQuery(): self
    {
        return new self(
            'No organisation context declared (§8.2.1). A tenant-scoped query ran before anything '
            ."said which organisation it belongs to.\n\n"
            ."Declare one of the two:\n"
            ."  app(OrganisationContext::class)->for(\$organisationId);   // this tenant\n"
            ."  app(OrganisationContext::class)->spanAllOrganisations();  // genuinely installation-wide\n\n"
            .'If this is a queued job, set it inside handle() — see the note in OrganisationContext '
            .'about §12.1 and ambient state leaking between jobs in one worker.'
        );
    }

    public static function whenSpanningAll(): self
    {
        return new self(
            'This context spans all organisations, so there is no single organisation to filter on. '
            .'A caller asked for the current organisation while inside acrossAllOrganisations() or '
            .'after spanAllOrganisations().'
        );
    }
}
