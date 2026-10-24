<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Notifications;

use App\Builds\FailureCatalogue;
use App\Models\Build;
use App\Models\Project;
use App\Models\ProjectVersion;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

/**
 * §8.18.2: "🛑 Build-failure email MUST exist."
 *
 * > "Read the Docs mails on every failed build of a tracked version, and a
 * > migrating team notices its absence within a day."
 *
 * 🛑 **The message is the failure catalogue's sentence, not a restatement
 * of it.** §8.5.15 makes the identifier a stable contract and
 * {@see FailureCatalogue} owns the prose for each one; an email that
 * phrased the same failure differently would be a second wording to keep
 * in step, and the one people quote in a support request would be
 * whichever they happened to read.
 *
 * 🛑 **No log excerpt.** §8.5.21 redacts secrets on the way into the log,
 * but email leaves this installation through a server the operator does
 * not control and lands in archives nobody is auditing — so the mail
 * carries the identifier, the sentence and a link, and the log stays
 * behind the same authorisation as the project (§8.5.22).
 */
final class BuildFailed extends Notification
{
    public function __construct(
        private readonly Build $build,
        private readonly Project $project,
        private readonly ProjectVersion $version,
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
        $identifier = (string) ($this->build->failure_identifier ?? 'user.build_command_failed');

        return (new MailMessage)
            ->subject(sprintf('[%s] Build failed: %s', $this->project->slug, $this->version->slug))
            ->greeting('A build failed.')
            ->line(sprintf(
                '%s — version %s — build %s',
                $this->project->name,
                $this->version->slug,
                bin2hex($this->build->id),
            ))
            ->line(FailureCatalogue::message($identifier))
            ->line('Failure identifier: '.$identifier)
            ->line('The full log is in the dashboard, under this build.');
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(object $notifiable): array
    {
        return [
            'build' => bin2hex($this->build->id),
            'project' => bin2hex($this->project->id),
            'identifier' => $this->build->failure_identifier,
        ];
    }
}
