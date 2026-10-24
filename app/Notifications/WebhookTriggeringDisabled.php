<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Notifications;

use App\Models\Build;
use App\Models\Project;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

/**
 * §8.5.17's governor tripping: "project auto-disabled" from §8.18.1's
 * catalogue.
 *
 * 🛑 **The mail says what is still possible, first.** A message that only
 * announced a disablement would read as "your project is broken and we
 * have stopped" — and the single most important fact is that §8.5.17
 * disables *webhook triggering* and nothing else: the author can still
 * press Build, which is the only way they can prove the problem is fixed.
 * An operator who believes they are locked out does not try.
 */
final class WebhookTriggeringDisabled extends Notification
{
    public function __construct(
        private readonly Project $project,
        private readonly int $consecutiveFailures,
        private readonly Build $lastBuild,
    ) {}

    /**
     * @return list<string>
     */
    public function via(object $notifiable): array
    {
        return ['mail'];
    }

    public function toMail(object $notifiable): MailMessage
    {
        return (new MailMessage)
            ->subject(sprintf('[%s] Automatic builds paused after %d failures', $this->project->slug, $this->consecutiveFailures))
            ->greeting('Automatic builds are paused for '.$this->project->name.'.')
            ->line(sprintf(
                'The default version has failed %d times in a row for reasons a change to the project can fix, so pushes will no longer start a build.',
                $this->consecutiveFailures,
            ))
            ->line('You can still build manually, and a successful manual build is what clears this.')
            ->line('Last failure: '.(string) ($this->lastBuild->failure_identifier ?? 'unknown'))
            ->line('Builds that failed for reasons on our side — a runner outage, an unreachable store — are not counted here and never pause a project.');
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(object $notifiable): array
    {
        return [
            'project' => bin2hex($this->project->id),
            'consecutive_failures' => $this->consecutiveFailures,
        ];
    }
}
