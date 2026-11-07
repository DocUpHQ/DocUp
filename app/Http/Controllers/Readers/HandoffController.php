<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Controllers\Readers;

use App\Auth\OrganisationContext;
use App\Models\Domain;
use App\Models\Project;
use App\Models\User;
use App\Readers\HandoffRefused;
use App\Readers\ReaderHandoff;
use App\Readers\ReaderRejection;
use App\Serving\RoutingSnapshotLoader;
use App\Support\Uuid;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * §8.12.10's step 2, on the **dashboard** origin: mint the handoff code.
 *
 * 🛑 This is the only endpoint in the product that takes a reader from one
 * registrable domain to another, and the one rule that makes it safe is
 * §8.12.10's:
 *
 * > "with the return URL built **from the verified domain row, never from a
 * > request parameter**."
 *
 * So the `domain` parameter is a **lookup key**. An attacker may send any
 * identifier; what they receive is a redirect to the `domains.host` of the row
 * with that id, or a 404. The set of hosts this endpoint can reach is the set
 * of hosts the installation has verified — which is what an open redirect would
 * have to escape and cannot. §17's exit criterion "a return URL supplied as a
 * request parameter is ignored in favour of the domain row" is that, tested.
 *
 * 🛑 **Authenticated, and that is the whole of what this endpoint decides.** It
 * does not decide whether the reader may read the project: §12.3's one function
 * does, on the documentation origin, on every request. Putting an access check
 * here as well would be a second authorisation path — the thing §4.3 forbids —
 * and the first thing it would get wrong is that a session establishing
 * `authenticated` is legitimate even for a reader who holds no role, because a
 * policy rule may admit any authenticated reader.
 */
final readonly class HandoffController
{
    public function __construct(
        private RoutingSnapshotLoader $snapshots,
        private ReaderHandoff $handoff,
        private OrganisationContext $context,
    ) {}

    public function __invoke(Request $request): Response
    {
        $user = $request->user();

        if (! $user instanceof User) {
            // The `auth` middleware owns this; narrowed rather than assumed.
            return ReaderRejection::notFound();
        }

        $domainId = Uuid::tryToBytes((string) $request->query('domain', ''));
        $challenge = (string) $request->query('challenge', '');
        $returnPath = ReaderHandoff::safeReturnPath((string) $request->query('return', '/'));

        if ($domainId === null) {
            return ReaderRejection::notFound();
        }

        /*
         * 🛑 Across all organisations, deliberately. A reader arrives here from
         * a documentation origin with no tenant context of their own, and the
         * domain belongs to whichever organisation owns the project — not to
         * whatever the dashboard last put in the context. {@see ReaderHandoff}
         * re-checks that the domain and the project share an organisation,
         * which is the boundary this read deliberately crosses to find.
         */
        $domain = $this->context->acrossAllOrganisations(
            static fn (): ?Domain => Domain::query()->whereKey($domainId)->first(),
        );

        if (! $domain instanceof Domain) {
            return ReaderRejection::notFound();
        }

        /*
         * Which project the reader was heading for: the mount covering the
         * return path on that domain. Resolved through the same loader the
         * documentation origin uses, so the two halves of the handoff cannot
         * disagree about the answer.
         */
        $snapshot = $this->snapshots->load($domain->host);

        if (! $snapshot->servable) {
            return ReaderRejection::notFound();
        }

        $match = $snapshot->matchFor($returnPath);

        if ($match === null) {
            return ReaderRejection::notFound();
        }

        $project = $this->context->acrossAllOrganisations(
            static fn (): ?Project => Project::query()->whereKey($match->mount->project->id)->first(),
        );

        if (! $project instanceof Project) {
            return ReaderRejection::notFound();
        }

        try {
            $minted = $this->handoff->mint(
                user: $user,
                domain: $domain,
                project: $project,
                challenge: $challenge,
                returnPath: $returnPath,
            );
        } catch (HandoffRefused) {
            /* §8.12.23's default; the reason is already in the audit chain. */
            return ReaderRejection::notFound();
        }

        return (new RedirectResponse($minted['url']))->withHeaders([
            /*
             * 🛑 `no-store`, because the `Location` of this response contains a
             * live single-use code. A shared cache holding it would hand the
             * next reader a code minted for somebody else — and the code is all
             * that is missing from a session, since the verifier is already in
             * the victim's browser.
             */
            'Cache-Control' => 'private, no-store',
            'Vary' => 'Cookie',
            'X-Robots-Tag' => 'noindex, nofollow',
            /*
             * 🛑 And the code must not leak sideways through a `Referer`. The
             * destination is a document on another registrable domain that will
             * load whatever the project's documentation loads; `no-referrer`
             * means none of those requests can carry this URL.
             */
            'Referrer-Policy' => 'no-referrer',
        ]);
    }
}
