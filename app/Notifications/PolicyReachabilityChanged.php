<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Notifications;

use App\Access\PolicyFinding;
use App\Access\PolicyObservation;
use App\Domains\OrganisationOwners;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

/**
 * 🛑 §8.12.22's alert: "a nightly policy linter that … **alerts** on
 * reachability changes".
 *
 * ## 🛑 Why widening leads
 *
 * The mail opens with the widenings and says how many there are in the subject,
 * because the two directions are not symmetric in consequence. A rule narrowed
 * too far produces a support ticket within the hour from somebody who cannot
 * read their own documentation. A rule widened too far produces **nothing** —
 * no ticket, no error, no log line out of the ordinary — until it is found by
 * somebody who was not supposed to find it. §19/40 names the failure mode this
 * phase exists for: "the observed failure mode is defaulting projects to
 * public, which quietly voids G3". Quietly is the operative word, and this mail
 * is the noise.
 *
 * 🛑 **It names the rule as the operator wrote it**, by position and label. A
 * mail that said "a rule changed" would be a mail that sends somebody to read
 * their whole policy at 9am, which is the same as a mail nobody acts on.
 */
final class PolicyReachabilityChanged extends Notification
{
    /**
     * @param  list<PolicyObservation>  $observations  the rules whose
     *                                                 reachability or breadth
     *                                                 changed since the last run
     */
    public function __construct(
        private readonly string $projectSlug,
        private readonly array $observations,
    ) {}

    /**
     * Send to the organisation's owners.
     *
     * A static helper rather than a dispatcher of its own, exactly as
     * {@see DomainFailing::dispatch()} does and for the reason stated there:
     * §8.18's notification routing is a later phase, and inventing half of it
     * here would be the second subscription mechanism that phase has to
     * reconcile. What cannot wait is that somebody is told, and §20.3's audit
     * row written beside this is the record that they were.
     *
     * @param  string  $organisationId  raw 16 bytes
     * @param  list<PolicyObservation>  $observations
     */
    public static function dispatch(string $organisationId, string $projectSlug, array $observations): void
    {
        if ($observations === []) {
            return;
        }

        foreach (OrganisationOwners::of($organisationId) as $user) {
            $user->notify(new self($projectSlug, $observations));
        }
    }

    /** @return list<string> */
    public function via(object $notifiable): array
    {
        return ['mail'];
    }

    public function toMail(object $notifiable): MailMessage
    {
        $widened = array_values(array_filter(
            $this->observations,
            static fn (PolicyObservation $observation): bool => $observation->widened(),
        ));

        $mail = (new MailMessage)
            ->subject($this->subject(count($widened)))
            ->greeting('The access policy for '.$this->projectSlug.' changed.');

        if ($widened !== []) {
            $mail->line('**More readers can now read more. Check these first:**');

            foreach ($widened as $observation) {
                $mail->line('• '.$observation->summary());
            }

            $mail->line('');
        }

        $others = array_values(array_filter(
            $this->observations,
            static fn (PolicyObservation $observation): bool => ! $observation->widened(),
        ));

        if ($others !== []) {
            $mail->line('Also changed:');

            foreach ($others as $observation) {
                $mail->line('• '.$observation->summary());
            }
        }

        /*
         * 🛑 The remedy is the simulator, named explicitly. §8.12.25 exists
         * because "operators cannot verify their own configuration" otherwise,
         * and an alert that reports a problem without pointing at the tool that
         * answers it has done half the job.
         */
        $mail->line('');
        $mail->line('To check what this means for a particular reader, use the policy '
            .'simulator on the project: it answers "as this identity, on this URL" with '
            .'the rule that decided and the binding that satisfied it.');

        if ($this->mentions(PolicyFinding::ReachabilityChanged)) {
            $mail->line('');
            $mail->line('A rule changed reachability. Under first-match-wins an earlier rule '
                .'can cover a later one completely, which makes the later one unable to '
                .'decide anything — so the rule that is now deciding may not be the one '
                .'you edited.');
        }

        return $mail;
    }

    private function subject(int $widened): string
    {
        if ($widened > 0) {
            return '['.$this->projectSlug.'] '.$widened
                .' access rule'.($widened === 1 ? '' : 's').' now admit'.($widened === 1 ? 's' : '').' more readers';
        }

        return '['.$this->projectSlug.'] access policy changed — '
            .count($this->observations).' rule'.(count($this->observations) === 1 ? '' : 's');
    }

    private function mentions(PolicyFinding $finding): bool
    {
        foreach ($this->observations as $observation) {
            if (in_array($finding, $observation->changes, true)) {
                return true;
            }
        }

        return false;
    }
}
