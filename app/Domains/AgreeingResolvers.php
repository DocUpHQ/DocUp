<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Domains;

/**
 * 🛑 §8.10.6's "two independent resolvers that must agree".
 *
 * The requirement is not redundancy. One resolver seeing a record another
 * does not is what a **partially propagated takeover** looks like: an
 * attacker who can influence one recursive resolver, or who publishes a
 * record and withdraws it, gets a verification pass from a single-resolver
 * check. So disagreement is a distinct outcome from failure, recorded as
 * such, and it never verifies.
 *
 * 🛑 It also never **fails** a domain that was already verified. §8.10.6's
 * state machine moves `active → failing` on a failed check, and treating a
 * resolver outage as a failed check would start a seven-day clock on every
 * domain in the installation the next time a DoH provider had a bad hour.
 * {@see Outcome::Unresolvable} is the answer for that, and the caller leaves
 * the state alone.
 */
final readonly class AgreeingResolvers
{
    /** @param  list<DnsRecords>  $resolvers */
    public function __construct(private array $resolvers) {}

    /**
     * The TXT values both resolvers agree on.
     *
     * Agreement is on the **set**, not the order: DNS does not promise an
     * order and two providers routinely return one rotated.
     */
    public function txt(string $name): ResolverAnswer
    {
        return $this->agree(
            static fn (DnsRecords $resolver): ?array => $resolver->txt($name),
        );
    }

    /** The CNAME target both resolvers agree on. */
    public function cname(string $name): ResolverAnswer
    {
        return $this->agree(static function (DnsRecords $resolver) use ($name): ?array {
            $target = $resolver->cname($name);

            return $target === null ? null : ($target === '' ? [] : [$target]);
        });
    }

    /**
     * @param  callable(DnsRecords): (list<string>|null)  $ask
     */
    private function agree(callable $ask): ResolverAnswer
    {
        $answers = [];
        $observed = [];

        foreach ($this->resolvers as $resolver) {
            $answer = $ask($resolver);

            $observed[$resolver->name()] = $answer;

            if ($answer === null) {
                continue;
            }

            $sorted = $answer;
            sort($sorted, SORT_STRING);
            $answers[] = $sorted;
        }

        if (count($answers) < 2) {
            /*
             * 🛑 Fewer than two usable answers is not a failed proof. §8.10.6
             * asks for two resolvers that agree; one resolver agreeing with
             * itself is the single-resolver check the requirement exists to
             * replace, so it is reported as unresolvable and the caller
             * leaves the domain's state where it was.
             */
            return new ResolverAnswer(Outcome::Unresolvable, [], $observed);
        }

        $first = $answers[0];

        foreach ($answers as $answer) {
            if ($answer !== $first) {
                return new ResolverAnswer(Outcome::Disagreed, [], $observed);
            }
        }

        return new ResolverAnswer(Outcome::Answered, $first, $observed);
    }
}
