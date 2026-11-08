<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Access;

use App\Serving\RejectionReason;
use App\Serving\RouteOutcome;

/**
 * §8.12.25's sentence, as a value an operator can read and a test can assert.
 *
 * > "as this identity, on this URL — allow, by rule 7, satisfied by binding X"
 *
 * Three facts, and this type carries all three plus the one the requirement
 * leaves implicit: **how the URL was understood**. An operator debugging a
 * policy is at least as likely to have the wrong path space as the wrong rule
 * — §12.3 writes `path_patterns` relative to a component mount while the
 * reader types a version-rooted URL — so a simulator that reported only the
 * verdict would confirm the wrong thing. {@see self::$mountRelativePath} is
 * what the policy actually saw.
 *
 * 🛑 **A decision is optional and its absence is a real answer.** A URL that
 * resolves to no version is not a denial: nothing was authorised, because
 * there was nothing to authorise. Reporting that as `deny` would teach an
 * operator that their policy refused a page their routing never reached, and
 * they would edit the policy for an hour.
 */
final readonly class SimulationAnswer
{
    /**
     * @param  string  $host  the documentation host, as resolved
     * @param  string  $requestPath  the path as the operator typed it
     * @param  string  $routeRule  {@see RouteOutcome::$matchedRule}
     *                             — which routing rule matched, so an
     *                             unexpected version or language is traceable
     *                             to the rule that chose it rather than guessed at
     * @param  string|null  $rejection  {@see RejectionReason}'s
     *                                  value when the URL resolved to nothing
     * @param  string|null  $redirectTo  where the URL redirects, when it does.
     *                                   🛑 A redirect is reported rather than
     *                                   followed: following it would answer a
     *                                   question about a different URL and
     *                                   label the answer with this one.
     * @param  string|null  $mountRelativePath  the space §12.3's
     *                                          `path_patterns` are written in
     * @param  string|null  $satisfiedByBinding  §8.12.25's "binding X" — the
     *                                           binding's own name, resolved
     *                                           for display. Null when the
     *                                           satisfying leaf names no
     *                                           binding, which `{public}`,
     *                                           `{gate}`, `{share}` and
     *                                           `{bearer}` never do.
     * @param  list<AccessLeaf>  $unsimulatable  🛑 leaves a rule matching this
     *                                           URL depends on that **no**
     *                                           simulation can establish,
     *                                           because §9.1.4 stores their
     *                                           credentials hashed. A denial
     *                                           with this list non-empty may be
     *                                           a correct refusal of this
     *                                           identity and nothing more — the
     *                                           operator has to know which.
     * @param  string|null  $identityLabel  the stored row's display label, for
     *                                      the operator to confirm they picked
     *                                      the identity they meant. 🛑 Never an
     *                                      email: §8.12.1 forbids one existing
     *                                      on a reader identity at all.
     * @param  list<string>  $identityGroups  the groups the stored identity
     *                                        carries (§8.13.7), shown because
     *                                        a reader who signed in yesterday
     *                                        and a reader who signed in after
     *                                        the mapping changed are different
     *                                        readers
     * @param  string|null  $degradedBinding  🛑 §8.12.19: the name of a binding
     *                                        that is degraded, when one is. The
     *                                        decision beside it is still the
     *                                        real one — a degraded binding
     *                                        establishes nothing, so §12.3
     *                                        refuses — but this is the one case
     *                                        where the policy is innocent and
     *                                        the denial looks like its fault
     */
    public function __construct(
        public SimulatedIdentity $identity,
        public string $host,
        public string $requestPath,
        public string $routeRule,
        public ?AccessDecision $decision = null,
        public ?string $rejection = null,
        public ?string $redirectTo = null,
        public ?string $projectSlug = null,
        public ?string $versionSlug = null,
        public ?string $language = null,
        public ?string $mountRelativePath = null,
        public ?string $satisfiedByBinding = null,
        public array $unsimulatable = [],
        public ?string $identityLabel = null,
        public array $identityGroups = [],
        public ?string $degradedBinding = null,
    ) {}

    /** Whether the URL reached a published version at all. */
    public function reachedAVersion(): bool
    {
        return $this->decision !== null;
    }

    /**
     * §8.12.25's sentence in one line, which is also what the audit payload
     * records and what a test asserts against.
     *
     * 🛑 Built from {@see AccessDecision::header()} rather than beside it, so
     * the simulator's wording and the wording a reader's own response carries
     * on §17's decision header cannot drift. An operator comparing the two —
     * which is exactly what they do when a simulation and reality disagree —
     * must not have to translate between them.
     */
    public function summary(): string
    {
        if ($this->decision === null) {
            return 'unresolved:'.($this->redirectTo !== null ? 'redirect' : ($this->rejection ?? 'unknown'));
        }

        $summary = $this->decision->header();

        if ($this->satisfiedByBinding !== null) {
            $summary .= ';binding='.$this->satisfiedByBinding;
        }

        if ($this->degradedBinding !== null) {
            $summary .= ';degraded='.$this->degradedBinding;
        }

        return $summary;
    }
}
