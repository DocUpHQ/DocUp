<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Controllers\Readers;

use App\Auth\OrganisationContext;
use App\Auth\Providers\BindingContext;
use App\Auth\Providers\Bindings;
use App\Auth\Providers\Federation\ProvisioningRefused;
use App\Auth\Providers\Ldap\LdapAudit;
use App\Auth\Providers\Ldap\LdapAuthenticator;
use App\Auth\Providers\Ldap\LdapRefused;
use App\Auth\Providers\Ldap\LdapRejection;
use App\Auth\Providers\ReaderThrottle;
use App\Models\Domain;
use App\Models\Project;
use App\Readers\HandoffRefused;
use App\Readers\ReaderHandoff;
use App\Readers\ReaderRejection;
use App\Serving\RoutingSnapshotLoader;
use App\Support\Uuid;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Inertia\Inertia;
use Inertia\Response as InertiaResponse;
use Symfony\Component\HttpFoundation\Response as SymfonyResponse;

/**
 * §8.12.16's credential page, for the one driver that has a password to take.
 *
 * 🛑 **Two requests from the same browser, so the state lives in the
 * session** — not in a table, which is where {@see OidcStartController} and
 * {@see SamlStartController} must keep theirs. Their second leg is a request a
 * *third party* causes, arriving with an identity provider's payload and
 * nothing of DocUp's; this one is a form the reader posts back to the origin
 * that served it, with a session cookie and a CSRF token. A row would be the
 * same guarantee with a migration and a sweeper attached.
 *
 * 🛑 And it is the session rather than hidden fields, which is the design the
 * form shape invites. The domain decides **which directory a password is sent
 * to**; a reader-supplied field would mean re-running that resolution at the
 * moment credentials are in hand. The only reader-controlled values on the
 * POST are the username and the password.
 *
 * ## 🛑 Unauthenticated, like its two siblings
 *
 * §8.12.1 keeps `users` and `reader_identities` "physically disjoint", so a
 * reader authenticated by the operator's directory holds no dashboard session
 * and a route behind `auth` could not serve them. What stands in for `auth` is
 * a **verified domain** and an **active binding**, both resolved server-side
 * from the project rather than from a parameter.
 *
 * ## 🛑 What the reader is never told
 *
 * Every failure is the same failure. A wrong password, a username with no
 * entry, a directory that is down, a binding that was deleted mid-flow and a
 * lockout all render the same form with the same message. The reason is
 * §8.12.23's: this page is reachable by anyone who can reach the dashboard
 * host, and a message that distinguished "no such user" would be an
 * enumeration oracle over the **operator's employee directory**. The audit
 * chain gets the distinction; the reader gets one sentence.
 *
 * 🛑 This is also why there is no `_/auth/ldap` page without a valid pending
 * sign-in. A bare GET is a 404, not an empty form: a form that rendered for
 * anybody would confirm that this installation has LDAP configured, and §8.9.4
 * resolves a project from the host precisely so that reader-visible surfaces
 * do not answer questions about the installation's shape.
 */
final readonly class LdapSignInController
{
    /**
     * Where the pending sign-in lives between the two requests.
     *
     * One slot, so a second GET replaces the first rather than accumulating
     * flows a reader could choose between.
     */
    private const string SESSION_KEY = 'reader.ldap.pending';

    /**
     * 🛑 How long a reader has to type their password.
     *
     * Ten minutes, and the ceiling matters more than the floor: the pending
     * row names a domain, a project and a handoff challenge, and a challenge
     * whose verifier the documentation origin has already forgotten produces a
     * sign-in that works and then fails at the far end. §8.12.10's handoff
     * codes expire within 30 seconds of being *minted*; this window is before
     * that, so it only needs to be shorter than the reader's patience.
     */
    private const int PENDING_SECONDS = 600;

    /** The longest username this form will carry to a directory. */
    private const int MAX_USERNAME = 256;

    public function __construct(
        private RoutingSnapshotLoader $snapshots,
        private Bindings $bindings,
        private OrganisationContext $context,
        private LdapAuthenticator $authenticator,
        private ReaderHandoff $handoff,
        private ReaderThrottle $throttle,
    ) {}

    /** The form, after the same three checks the OIDC start leg makes. */
    public function create(Request $request): SymfonyResponse|InertiaResponse
    {
        $domainId = (string) $request->query('domain', '');
        $challenge = (string) $request->query('challenge', '');
        $returnPath = (string) $request->query('return', '/');

        /*
         * 🛑 A reader arriving from the documentation origin brings the three
         * values; a reader coming back from a failed attempt brings none, and
         * the live pending sign-in is what serves them. The retry URL
         * therefore carries **no challenge**, which is the whole reason this
         * branch exists rather than the form posting its own values back.
         */
        if ($domainId === '' && $challenge === '') {
            $pending = $request->session()->get(self::SESSION_KEY);

            if (! is_array($pending) || ! $this->pendingIsLive($pending)) {
                return ReaderRejection::notFound();
            }

            $domainId = is_string($pending['domain_id'] ?? null) ? $pending['domain_id'] : '';
            $challenge = is_string($pending['challenge'] ?? null) ? $pending['challenge'] : '';
            $returnPath = is_string($pending['return_path'] ?? null) ? $pending['return_path'] : '/';
        }

        $resolved = $this->resolve($domainId, $challenge, $returnPath);

        if ($resolved === null) {
            return ReaderRejection::notFound();
        }

        /*
         * Re-stamped on every render, including a retry, so the window is time
         * to type a password rather than time since the reader left the
         * documentation origin.
         */
        $request->session()->put(self::SESSION_KEY, [
            'domain_id' => $domainId,
            'challenge' => $resolved['challenge'],
            'return_path' => $resolved['returnPath'],
            'expires_at' => time() + self::PENDING_SECONDS,
        ]);

        /*
         * 🛑 No project name, no organisation name, no logo. §8.14.12: "Pages
         * that accept credentials MUST carry **no project or organisation
         * branding**." The reader is told which *directory* they are signing
         * in to, because that is the operator's installation-scope label and
         * the one fact they need to know which password to type.
         *
         * Phase 27 owns the enforcement of that rule across every credential
         * page; this page is written to it now so it is not a page that has to
         * be fixed then.
         */
        return Inertia::render('Auth/ReaderSignIn', [
            'label' => $resolved['label'],
            'failed' => $request->session()->get('reader.ldap.failed') === true,
            /*
             * The token for a NATIVE form post. The success response is a
             * 302 to the documentation origin's handoff URL, which an
             * Inertia XHR cannot follow -- so the form is a real one and
             * needs a real token. Passed here rather than shared globally,
             * because one page needing it is not a reason to put it on
             * every page.
             */
            'csrfToken' => $request->session()->token(),
            't' => __('auth.reader_sign_in'),
        ]);
    }

    /** The bind, and §8.12.10's handoff on the way back. */
    public function store(Request $request): SymfonyResponse
    {
        $pending = $request->session()->get(self::SESSION_KEY);

        if (! is_array($pending) || ! $this->pendingIsLive($pending)) {
            return ReaderRejection::notFound();
        }

        $resolved = $this->resolve(
            domainId: is_string($pending['domain_id'] ?? null) ? $pending['domain_id'] : '',
            challenge: is_string($pending['challenge'] ?? null) ? $pending['challenge'] : '',
            returnPath: is_string($pending['return_path'] ?? null) ? $pending['return_path'] : '/',
        );

        if ($resolved === null) {
            return ReaderRejection::notFound();
        }

        $username = (string) $request->input('username', '');
        $password = (string) $request->input('password', '');
        $binding = $resolved['binding'];

        /*
         * 🛑 Bounded before anything else looks at it. A megabyte of username
         * is a megabyte the directory parses, and `LdapFilter::build()` would
         * escape it faithfully all the way there.
         */
        if ($username === '' || mb_strlen($username) > self::MAX_USERNAME) {
            return $this->refuse($request);
        }

        $credentialKey = $binding->id.'|'.mb_strtolower($username);

        /*
         * 🛑 Checked before the bind, so a locked-out client's guess never
         * reaches the operator's directory at all. That matters more here than
         * it does for a share link: most directories have a lockout policy of
         * their own, so an unthrottled guessing endpoint would let anybody on
         * the internet lock out a named employee's real account.
         */
        if (! $this->throttle->permits($credentialKey, $request->ip())) {
            LdapAudit::throttled($binding, $this->throttle->secondsUntilRetry($credentialKey, $request->ip()));

            return $this->refuse($request);
        }

        try {
            $identity = $this->authenticator->authenticate($binding, $username, $password);
        } catch (LdapRefused $refused) {
            $this->throttle->fail($credentialKey, $request->ip());
            LdapAudit::refused($refused, $binding);

            return $this->refuse($request);
        } catch (ProvisioningRefused $refused) {
            /*
             * 🛑 Not a throttle hit. The reader's password was correct — the
             * binding's provisioning mode declined to create them — so
             * counting it would let a provisioning misconfiguration lock out
             * every reader who typed their password right.
             */
            LdapAudit::refused(
                LdapRefused::of(LdapRejection::SubjectNotFound, $refused->getMessage()),
                $binding,
            );

            return $this->refuse($request);
        }

        $this->throttle->succeed($credentialKey, $request->ip());

        try {
            $minted = $this->handoff->mint(
                subject: $identity,
                domain: $resolved['domain'],
                project: $resolved['project'],
                challenge: $resolved['challenge'],
                returnPath: $resolved['returnPath'],
            );
        } catch (HandoffRefused) {
            return ReaderRejection::notFound();
        }

        $request->session()->forget([self::SESSION_KEY, 'reader.ldap.failed']);
        LdapAudit::succeeded($binding, $identity->id);

        return (new RedirectResponse($minted['url']))->withHeaders([
            'Cache-Control' => 'private, no-store',
            'Referrer-Policy' => 'no-referrer',
            'X-Robots-Tag' => 'noindex, nofollow',
        ]);
    }

    /**
     * The domain, project, binding and normalised return path, or null.
     *
     * 🛑 Run on **both** legs against the same stored values, rather than
     * carried forward from the first. A binding can be disabled, a domain
     * unverified and a project deleted between the form being served and the
     * password being typed, and the second leg is the one that sends the
     * password somewhere.
     *
     * @return array{domain: Domain, project: Project, binding: BindingContext, challenge: string, returnPath: string, label: string}|null
     */
    private function resolve(string $domainId, string $challenge, string $returnPath): ?array
    {
        $key = Uuid::tryToBytes($domainId);

        if ($key === null || preg_match('/^[A-Za-z0-9_-]{43}$/', $challenge) !== 1) {
            return null;
        }

        $returnPath = ReaderHandoff::safeReturnPath($returnPath);

        $domain = $this->context->acrossAllOrganisations(
            static fn (): ?Domain => Domain::query()->whereKey($key)->first(),
        );

        if (! $domain instanceof Domain) {
            return null;
        }

        $snapshot = $this->snapshots->load($domain->host);

        if (! $snapshot->servable) {
            return null;
        }

        $match = $snapshot->matchFor($returnPath);

        if ($match === null) {
            return null;
        }

        /*
         * 🛑 The routing snapshot carries a {@see \App\Serving\SnapshotProject}
         * -- the few fields the serving path needs -- and {@see ReaderHandoff::mint()}
         * takes the model. Loaded here rather than typed around, because the
         * handoff writes a row referencing this project and the snapshot is a
         * cache: a project deleted since the snapshot was built must fail now
         * rather than at the foreign key.
         */
        $snapshotProject = $match->mount->project;

        $project = $this->context->acrossAllOrganisations(
            static fn (): ?Project => Project::query()->whereKey($snapshotProject->id)->first(),
        );

        if (! $project instanceof Project) {
            return null;
        }

        /*
         * 🛑 The binding is resolved through §8.12.3, not named by the reader —
         * {@see SamlStartController} says why at length. For this driver there
         * is a second reason: §8.12.4 makes `ldap` installation-scope only, so
         * a reader who could name one could have DocUp send their password to
         * a directory of their choosing.
         */
        foreach ($this->bindings->contextsFor($snapshotProject->id, $snapshotProject->organisationId, $snapshotProject->authzEpoch) as $candidate) {
            if ($candidate->type === 'ldap' && $candidate->isUsable()) {
                return [
                    'domain' => $domain,
                    'project' => $project,
                    'binding' => $candidate,
                    'challenge' => $challenge,
                    'returnPath' => $returnPath,
                    'label' => $candidate->name,
                ];
            }
        }

        return null;
    }

    /** @param array<array-key, mixed> $pending */
    private function pendingIsLive(array $pending): bool
    {
        $expires = $pending['expires_at'] ?? null;

        return is_int($expires) && $expires > time();
    }

    /**
     * 🛑 One refusal for every cause, back to the form.
     *
     * The pending sign-in is **kept**, so a reader who mistyped can try again
     * without starting from the documentation origin. The failure flag is a
     * flash, so a reload does not keep claiming a failure that is over.
     */
    private function refuse(Request $request): SymfonyResponse
    {
        $request->session()->flash('reader.ldap.failed', true);

        /*
         * 🛑 To the bare route, with nothing in the query string. The pending
         * sign-in holds the domain, the challenge and the return path, so the
         * retry needs none of them in a URL — which keeps a handoff challenge
         * out of the reader's history, out of any proxy log on the dashboard
         * origin and out of a `Referer` if the form ever grows a link.
         */
        return new RedirectResponse(route('reader.ldap.create'));
    }
}
