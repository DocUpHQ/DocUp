<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Access;

use App\Auth\Providers\Bindings;
use App\Auth\Providers\ReaderPresentation;
use App\Models\ReaderIdentity;
use App\Models\User;
use App\Readers\EstablishedReader;
use App\Readers\ReaderResolver;
use App\Readers\SessionRecord;
use App\Serving\Resolver;
use App\Serving\RouteKind;
use App\Serving\RoutingSnapshotLoader;
use App\Serving\SnapshotMount;
use App\Serving\SnapshotProject;
use App\Support\Uuid;

/**
 * 🛑 §8.12.25's policy simulator: "as this identity, on this URL — allow, by
 * rule 7, satisfied by binding X".
 *
 * §19/40 states the stake plainly — "without it operators cannot verify their
 * own configuration, and the observed failure mode is defaulting projects to
 * public, which quietly voids G3". An operator who cannot check their policy
 * does not write a careful one; they write a permissive one and stop thinking
 * about it.
 *
 * ## 🛑 This class decides nothing
 *
 * It is a **renderer**, and every line of it is about assembling an honest
 * question and presenting the answer. §17's Phase 26a exit criterion is
 * explicit about why: the simulator's answer must "provably agree with a live
 * request made as that identity — the same `EffectiveAccess` call site,
 * asserted by test, not a reimplementation". So:
 *
 * | Half of the question | Who answers it | Why not here |
 * |---|---|---|
 * | which version, language and mount-relative path this URL means | {@see Resolver} | §8.9.3's ordering is the serving path's, and a second route resolution would answer about a different page |
 * | what this identity establishes | {@see ReaderResolver::establishAs()} | §8.12.19's degraded short-circuit, the session floor and the leaf union are merge rules with wrong answers a reasonable person would give |
 * | whether they may read it | {@see ReaderGate::simulate()} → {@see EffectiveAccess} | §4.3/7 makes it the sole decider, and §12.3's lattice is the thing being verified |
 *
 * What is left is this class's actual work: turning a URL into a host and a
 * path, turning an operator's choice of stored row into the `SessionRecord` a
 * live request would have resolved, resolving a binding id to the name
 * §8.12.25 wants printed, and — the part a naive simulator gets wrong —
 * **saying what it could not simulate**.
 *
 * ## 🛑 Nothing is written, and nothing is minted
 *
 * No session, no grant, no cookie, no decision-log row (see
 * {@see ReaderGate::simulate()} for why that one matters most). A simulation
 * leaves the installation exactly as it found it, which is what makes it safe
 * to run against production while an incident is live — the one moment an
 * operator most needs it and least wants to perturb anything.
 *
 * The one thing a simulation *should* leave behind is the record that an
 * operator ran it, and that is deliberately **not** here: the audit event is
 * written at the call site, by the controller that knows who the actor is. A
 * simulator that audited would also audit every one of a test suite's hundred
 * calls through the chain lock, and an audit trail nobody can afford to leave
 * on is an audit trail that gets switched off.
 */
final readonly class PolicySimulator
{
    public function __construct(
        private RoutingSnapshotLoader $snapshots,
        private Resolver $resolver,
        private ReaderGate $gate,
        private ReaderResolver $readers,
        private ReaderPolicies $policies,
        private Bindings $bindings,
    ) {}

    /**
     * Answer §8.12.25's question.
     *
     * @param  string  $host  the documentation host, as a reader would send it
     * @param  string  $path  the request path, as a reader would send it —
     *                        version-rooted and absolute, because that is what
     *                        an operator has in front of them when they copy a
     *                        URL out of a browser
     * @param  AccessSurface  $surface  §8.12.21's four surfaces. The default is
     *                                  the proxy because that is the one a
     *                                  reader uses; an operator debugging a
     *                                  project whose search went quiet needs
     *                                  {@see AccessSurface::Search}, where
     *                                  §8.12.21's generation check applies and
     *                                  the answer is legitimately different.
     * @param  int|null  $now  unix seconds; null reads the clock. 🛑 A future
     *                         value is the supported way to ask "will this
     *                         still hold", because §12.3's `not_before` and
     *                         `not_after` are decision inputs — so the question
     *                         is answered by the decider rather than by a
     *                         calendar in this class.
     *
     * @throws SimulationRefused when the identity does not belong to the
     *                           organisation whose project the URL resolves to
     */
    public function simulate(
        SimulatedIdentity $identity,
        string $host,
        string $path,
        AccessSurface $surface = AccessSurface::Proxy,
        ?int $now = null,
    ): SimulationAnswer {
        $now ??= time();

        $snapshot = $this->snapshots->load($host);
        $route = $this->resolver->resolveRoute($snapshot, $path);

        [$label, $groups] = $this->describe($identity);

        if ($route->kind !== RouteKind::Resolved || $route->mount === null || $route->version === null) {
            /*
             * 🛑 Reported, not authorised. §8.9.3 and §8.11.1 decide what a URL
             * means before §12.3 decides who may read it, and a URL that means
             * nothing never reaches the second question. Calling this `deny`
             * would send an operator to edit a policy that was never consulted.
             */
            return new SimulationAnswer(
                identity: $identity,
                host: $snapshot->host,
                requestPath: $path,
                routeRule: $route->matchedRule,
                rejection: $route->reason?->value,
                redirectTo: $route->redirectTo,
                identityLabel: $label,
                identityGroups: $groups,
            );
        }

        $mount = $route->mount;
        $version = $route->version;
        $project = $mount->project;

        $established = $this->establish($identity, $mount);
        $context = $established->context;

        $decision = $this->gate->simulate(
            mount: $mount,
            version: $version,
            language: $route->language,
            /*
             * 🛑 `remainder`, not the path as typed, and the reason is the one
             * {@see \App\Http\Controllers\Serving\DocumentController} states at
             * its own call: §12.3 makes `path_patterns` "expressed relative to
             * a component mount", and `remainder` is that space. Handing the
             * policy the version-rooted form would make the simulator agree
             * with itself and disagree with every real request.
             */
            path: $route->remainder,
            surface: $surface,
            reader: $context,
            now: $now,
        );

        return new SimulationAnswer(
            identity: $identity,
            host: $snapshot->host,
            requestPath: $path,
            routeRule: $route->matchedRule,
            decision: $decision,
            projectSlug: $project->slug,
            versionSlug: $version->slug,
            language: $route->language,
            mountRelativePath: $route->remainder,
            satisfiedByBinding: $this->satisfyingBindingName($decision, $context, $project),
            unsimulatable: $this->unsimulatable($project, $version->slug, $route->language, $route->remainder, $now),
            identityLabel: $label,
            identityGroups: $groups,
            /*
             * 🛑 §8.12.19's degradation, reported. The decision below it is
             * still the real one — §8.12.14 forbids a path that bypasses the
             * decider, and `ProviderOutcome::merge()` short-circuits on
             * `degraded` so §12.3 refuses this reader anyway — but an operator
             * looking at a surprising denial has to be told that a provider is
             * down rather than left reading their policy. This is the one
             * case where the policy is innocent and the answer looks like its
             * fault.
             */
            degradedBinding: $established->degradedBinding,
        );
    }

    /**
     * Build the reader context the serving path would have built.
     *
     * 🛑 **Through {@see ReaderResolver::establishAs()}, which is the live
     * path's own merge.** The only thing invented here is the
     * {@see SessionRecord}, and it is invented from stored facts: the
     * organisation and project the URL resolved to, the domain that answered,
     * and the one row the operator named. Everything that *follows* from those
     * facts — which binding vouched, which groups the identity carries, whether
     * a role assignment reaches §12.3's `members` rung, whether any binding is
     * degraded — is derived by the code that derives it for a real reader.
     *
     * 🛑 The session id is random and never leaves this method. `contextFor()`
     * uses it as the reader's subject, which §20.3 would key an aggregate on;
     * a value that looked like a session handle, or one derived from the
     * identity, would be a handle-shaped string in an operator's browser or a
     * stable pseudonym across simulations. Neither is wanted and neither is
     * needed, because nothing is logged.
     */
    private function establish(SimulatedIdentity $identity, SnapshotMount $mount): EstablishedReader
    {
        $project = $mount->project;

        $session = $identity->kind === SimulatedIdentityKind::Anonymous
            ? null
            : new SessionRecord(
                id: random_bytes(16),
                organisationId: (string) $project->organisationId,
                projectId: $project->id,
                /*
                 * 🛑 The project's organisation, not the identity's, and the
                 * guard in {@see self::describe()} is what makes the two the
                 * same. §8.12.11 binds a grant to a domain; a `SessionRecord`
                 * for a tenant other than the project's would be a row the
                 * handoff could never have produced, so simulating it would
                 * answer about a reader who cannot exist.
                 */
                domainId: $this->domainIdFor($mount),
                userId: $identity->userId,
                readerIdentityId: $identity->readerIdentityId,
            );

        return $this->readers->establishAs(
            $session,
            $project,
            new ReaderPresentation(remoteAddress: $identity->remoteAddress),
            /*
             * Nothing was rejected: the operator named a row that exists, which
             * {@see self::describe()} has already established. §8.12.23's case
             * (a) is about a credential that was presented and refused, and a
             * simulation presents none.
             */
            credentialRejected: false,
        );
    }

    /**
     * The domain the simulated session is bound to.
     *
     * 🛑 Taken from the mount's own project rather than the snapshot's
     * `domainId`, which is deliberately **not** threaded here: a documentation
     * host may carry mounts from several projects (§8.7), and the session a
     * live reader holds was established against the domain they signed in on.
     * Since nothing in the decision reads the domain — {@see ReaderGate} never
     * receives it — the value only has to be stable and project-shaped, and
     * using the project id keeps this method from inventing a domain that does
     * not exist.
     */
    private function domainIdFor(SnapshotMount $mount): string
    {
        return $mount->project->id;
    }

    /**
     * Confirm the identity exists and is this organisation's, and read the two
     * facts an operator needs to see to know they picked the right one.
     *
     * 🛑 **The tenancy guard is here and it is not optional.** A
     * `reader_identities` row carries the binding that vouched for it and the
     * groups §8.13.7 reconciled onto it; simulating another organisation's
     * identity against this project would read both into an answer rendered in
     * this tenant's dashboard. §8.2.2 makes a cross-tenant reference a 404, and
     * this refuses rather than returning a misleading `deny` — a denial would
     * read as "that identity may not read this", which is a statement about
     * somebody else's reader that this operator is not entitled to.
     *
     * @return array{0: string|null, 1: list<string>} the display label and the
     *                                                reconciled groups
     *
     * @throws SimulationRefused
     */
    private function describe(SimulatedIdentity $identity): array
    {
        if ($identity->kind === SimulatedIdentityKind::Anonymous) {
            return [null, []];
        }

        if ($identity->kind === SimulatedIdentityKind::Member) {
            $user = User::query()->find($identity->userId);

            if (! $user instanceof User) {
                throw SimulationRefused::noSuchIdentity();
            }

            /*
             * A member's name, which is not a reader subject: §8.12.1's
             * prohibition on email is about `reader_identities`, and a
             * dashboard member's own name is already on every page of the
             * dashboard this is rendered in.
             */
            return [$user->name, []];
        }

        /*
         * 🛑 Scoped by §8.2.1's global scope, so a reader identity belonging to
         * another organisation is simply **not found** — the tenancy guard is
         * the absence of a row rather than a comparison this code could get
         * wrong. The dashboard always has a tenant context (the `tenant`
         * middleware), which is exactly why the simulator lives behind it.
         */
        $reader = ReaderIdentity::query()->find($identity->readerIdentityId);

        if (! $reader instanceof ReaderIdentity) {
            throw SimulationRefused::noSuchIdentity();
        }

        if ($reader->deprovisioned_at !== null) {
            /*
             * 🛑 Refused rather than simulated as anonymous. §8.13.7
             * deprovisions an identity by stamping this column, and
             * {@see \App\Http\Controllers\Readers\AuthCallbackController}
             * refuses the sign-in outright — so there is no reader to simulate,
             * and answering "deny" would be answering a question about a
             * policy when the truth is about an identity.
             */
            throw SimulationRefused::deprovisioned();
        }

        return [$reader->display_label, $this->groupsOf($reader)];
    }

    /**
     * §8.13.7's reconciled groups, as a list of names.
     *
     * @return list<string>
     */
    private function groupsOf(ReaderIdentity $reader): array
    {
        $stored = $reader->reader_groups;

        if (! is_string($stored) || $stored === '') {
            return [];
        }

        $decoded = json_decode($stored, true);

        if (! is_array($decoded)) {
            return [];
        }

        $groups = [];

        foreach ($decoded as $group) {
            if (is_string($group)) {
                $groups[] = $group;
            }
        }

        return $groups;
    }

    /**
     * §8.12.25's "binding X", resolved to the name an operator configured.
     *
     * The satisfying leaf tells you the *kind*; §8.12.25 asks for the binding.
     * Which one it was is the intersection of two facts the decision already
     * carries: the bindings this reader satisfied, and the binding the matched
     * rule named — if it named one at all, because a rule written
     * `{"leaf": "binding"}` with no id is satisfied by any identity binding and
     * the answer is then whichever one vouched.
     *
     * 🛑 Read through {@see Bindings}, never from `auth_provider_bindings`
     * directly. §8.12.2 makes that class the one reader of the provider tables
     * because every read through it opens the secret envelope into a
     * `SecretString` and nothing else does; an architecture test enforces it.
     * This needs a name and nothing else, and it gets the name from the same
     * §8.12.3-scoped list the drivers were resolved from.
     */
    private function satisfyingBindingName(
        AccessDecision $decision,
        ReaderContext $context,
        SnapshotProject $project,
    ): ?string {
        if ($decision->satisfiedBy === null || ! $decision->satisfiedBy->bearsIdentity()) {
            return null;
        }

        $candidates = $context->satisfiedBindings;

        if ($decision->rule !== null) {
            $named = [];

            foreach ($decision->rule->requirement->bindingLeaves() as $pair) {
                if ($pair['leaf'] === $decision->satisfiedBy) {
                    $named[] = $pair['binding_id'];
                }
            }

            if ($named !== []) {
                $candidates = array_values(array_intersect($candidates, $named));
            }
        }

        if ($candidates === []) {
            return null;
        }

        foreach ($this->bindings->contextsFor($project->id, $project->organisationId, $project->authzEpoch) as $binding) {
            if (hash_equals(Uuid::toText($binding->id), $candidates[0])) {
                return $binding->name;
            }
        }

        return null;
    }

    /**
     * 🛑 The leaves a rule matching this URL depends on that **no** simulation
     * can establish.
     *
     * §9.1.4 stores a share link's and a reader token's secret hashed, so there
     * is nothing to present to the driver that would satisfy `{share}` or
     * `{bearer}`. {@see SimulatedIdentityKind} explains why the answer is to
     * report that rather than to hand-build the leaf.
     *
     * This is the difference between two denials that look identical and mean
     * opposite things: "your policy refuses this identity" and "this identity
     * was never the one that rule is for". An operator told only `deny` would
     * conclude the first and go looking for a bug in a rule that is working
     * exactly as written.
     *
     * Only rules that **match this URL** are considered, including shadow rules
     * — §8.12.6's first-match-wins means a rule that does not match is not part
     * of this answer, and a shadow rule is part of the next answer, which is
     * what §8.12.22's linter is for.
     *
     * @return list<AccessLeaf>
     */
    private function unsimulatable(
        SnapshotProject $project,
        string $versionSlug,
        string $language,
        string $path,
        int $now,
    ): array {
        $policy = $this->policies->forProject($project->id, $project->authzEpoch);
        $leaves = [];

        foreach ($policy->rules as $rule) {
            if (! $rule->matches($versionSlug, $language, $path, $now)) {
                continue;
            }

            foreach ([AccessLeaf::Share, AccessLeaf::Bearer] as $leaf) {
                if ($rule->requirement->usesLeaf($leaf) && ! in_array($leaf, $leaves, true)) {
                    $leaves[] = $leaf;
                }
            }
        }

        return $leaves;
    }
}
