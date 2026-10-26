<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Notifications;

use App\Domains\Challenge;
use App\Domains\DomainLedger;
use App\Domains\OrganisationOwners;
use App\Domains\Reverification;
use App\Models\Domain;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

/**
 * 🛑 §8.10.6's first-failure warning.
 *
 * > "State MUST progress `verified → active → failing` (7-day grace,
 * > **warning at the first failure, not the twenty-ninth**) `→ suspended`."
 *
 * The emphasis is the specification's and it is about when a human finds
 * out. A warning on the last day of the window has technically warned: the
 * operator then has hours to notice the mail, work out which record changed
 * and get a change through whatever process owns their DNS zone. Seven days
 * is a repair window, not a discovery window, so this goes out the first
 * time a check fails and the clock starts beside it.
 *
 * 🛑 **The mail carries the record to publish**, not a link to a page that
 * carries it. The recipient is usually not the person who set the domain up,
 * is reading on a phone, and needs one fact: what to put back in DNS.
 */
final class DomainFailing extends Notification
{
    public function __construct(
        private readonly Domain $domain,
        private readonly string $detail,
    ) {}

    /**
     * Send the warning to the organisation's owners.
     *
     * A static helper rather than a dispatcher of its own: §8.18's
     * notification routing is a later phase, and inventing half of it here
     * would be the second subscription mechanism that phase then has to
     * reconcile. What cannot wait is that somebody is told on day one, and
     * the domain event {@see DomainLedger} writes is the record
     * that they were.
     */
    public static function dispatch(Domain $domain, string $detail): void
    {
        foreach (OrganisationOwners::of($domain->organisation_id) as $user) {
            $user->notify(new self($domain, $detail));
        }
    }

    /** @return list<string> */
    public function via(object $notifiable): array
    {
        return ['mail'];
    }

    public function toMail(object $notifiable): MailMessage
    {
        $deadline = ($this->domain->failing_since ?? now())
            ->copy()
            ->addDays(Reverification::GRACE_DAYS);

        return (new MailMessage)
            ->subject('['.$this->domain->host.'] DNS verification failed — '.Reverification::GRACE_DAYS.' days to fix it')
            ->greeting($this->domain->host.' stopped verifying today.')
            ->line('It is still serving. If the record is not back by '
                .$deadline->toFormattedDateString().', it will stop.')
            ->line('What we looked for: '.$this->detail)
            ->line('The TXT record: '.Challenge::txtName($this->domain->host)
                .' = '.(string) $this->domain->verification_token)
            ->line('If you set this domain up with a CNAME instead, check that record is still in place — '
                .'it is both the route and the proof, so losing it would also have broken traffic.')
            ->line('We re-check daily and this clears itself the moment the record is back.');
    }
}
