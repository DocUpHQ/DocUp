<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Notifications;

use App\Access\BreakGlass;
use App\Models\BreakGlassGrant;
use App\Models\Project;
use App\Models\User;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

/**
 * 🛑 §8.12.20's operator alert: a break-glass window was opened.
 *
 * > "An installation-owner break-glass read override MUST exist behind MFA,
 * > step-up re-authentication and a mandatory reason, rate-limited to 3/hour,
 * > **raising an operator alert** and audited."
 *
 * ## 🛑 Why this goes to every installation owner, including the one who opened it
 *
 * The alert exists for the case where the person opening the window is not the
 * person who should be. An owner whose session has been taken will see mail
 * about an override they did not perform — which is the only signal they will
 * get, because everything else about the activation looks legitimate by
 * construction: it passed MFA, it passed step-up, and it carries a plausible
 * reason.
 *
 * So the recipient list is the role rather than a configured address, and the
 * actor is **not** excluded from it. Excluding them would be the small
 * convenience that removes the one person most able to say "that was not me".
 *
 * 🛑 And the mail leads with **who and why**, not with what was read. At the
 * moment it is sent nothing has been read yet; what an owner has to decide is
 * whether this activation should be allowed to continue, and that is a judgement
 * about the person and the reason.
 */
final class BreakGlassOpened extends Notification
{
    public function __construct(
        private readonly BreakGlassGrant $grant,
        private readonly User $actor,
        private readonly Project $project,
    ) {}

    /** @return list<string> */
    public function via(object $notifiable): array
    {
        return ['mail'];
    }

    public function toMail(object $notifiable): MailMessage
    {
        $closes = $this->grant->expires_at->format('H:i:s T');

        return (new MailMessage)
            /*
             * 🛑 The subject names the override, the person and the project,
             * because a subject that said "security notice" would be a subject
             * somebody triages later. There is no later: the window is
             * fifteen minutes.
             */
            ->subject('Break-glass override opened by '.$this->actor->name.' on '.$this->project->slug)
            ->line(
                '🛑 '.$this->actor->name.' opened a break-glass read override on **'
                .$this->project->slug.'**, which lets them read every document in that project '
                .'regardless of its access policy.'
            )
            ->line('**Their stated reason:** '.$this->grant->reason)
            ->line(
                'The window closes at '.$closes.' — '.BreakGlass::WINDOW_MINUTES
                .' minutes after it opened — and every document read through it is recorded in '
                .'the decision log, attributed to this override rather than to a policy rule.'
            )
            ->line(
                '🛑 **If this was not you and you did not expect it**, treat the account as '
                .'compromised: an override that passed MFA and step-up re-authentication came '
                .'from a session that holds both. Close the window, revoke the sessions, and '
                .'read the audit chain for `authz.break_glass.opened`.'
            )
            ->line(
                'You are receiving this because you hold `installation_owner`. §8.12.20 sends it '
                .'to the role rather than to a configured address, and does not exclude the '
                .'person who opened it — they are the one most able to say it was not them.'
            );
    }

    /**
     * 🛑 The payload for a stored channel, with the reason included.
     *
     * The reason is operator-written prose and may name a person or an
     * incident, which is why the column is classified `personal`. It is here
     * anyway: an alert that withheld the reason would be an alert nobody can
     * act on, and the recipient is an installation owner who can read the audit
     * chain regardless.
     *
     * @return array<string, mixed>
     */
    public function toArray(object $notifiable): array
    {
        return [
            'grant' => bin2hex($this->grant->id),
            'project' => $this->project->slug,
            'actor' => bin2hex($this->actor->id),
            'reason' => $this->grant->reason,
            'expires_at' => $this->grant->expires_at->toIso8601String(),
        ];
    }
}
