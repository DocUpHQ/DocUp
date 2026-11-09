<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Access;

use App\Audit\ActorType;
use App\Audit\Audit;
use App\Auth\ApiTokens;
use App\Auth\MfaEnforcement;
use App\Auth\Role;
use App\Auth\RoleResolver;
use App\Auth\SessionStamps;
use App\Http\Middleware\RequireRecentAuthentication;
use App\Models\BreakGlassGrant;
use App\Models\Project;
use App\Models\User;
use App\Notifications\BreakGlassOpened;
use App\Readers\ReaderSessions;
use App\Support\Uuid;
use Illuminate\Contracts\Session\Session;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Notification;

/**
 * 🛑 §8.12.20's break-glass read override, and the **one** place it is opened.
 *
 * > "An installation-owner **break-glass** read override MUST exist behind MFA,
 * > step-up re-authentication and a mandatory reason, rate-limited to 3/hour,
 * > raising an operator alert and audited."
 *
 * Five requirements in one sentence, and the reason they are all enforced here
 * rather than in a controller is the one {@see ApiTokens} gives for
 * minting: a second activation path is a second place to forget one of them.
 * The route also carries {@see RequireRecentAuthentication}, which is defence
 * in depth and better UX — it redirects to the confirmation page rather than
 * throwing — but the service does not trust it.
 *
 * ## 🛑 The override does not decide anything
 *
 * §4.3/7 allows exactly one decider and §12.3 names it. So this class does
 * **not** grant access: it records a grant, and {@see EffectiveAccess} reads
 * one named field on {@see ReaderContext} as a conjunct of its own with its own
 * {@see AccessReason}. Three consequences follow, and all three are the point:
 *
 * 1. A break-glass allow is **distinguishable** in §20.3's decision log and in
 *    the `X-DocUp-Decision` header. An override that looked like an ordinary
 *    allow would satisfy the feature and defeat the audit requirement.
 * 2. It cannot override §8.12.19's degraded-binding 503 or §8.12.21's stale
 *    search index, because both are evaluated before it. Neither is a policy
 *    refusal — one is an outage and the other is a known-stale copy of
 *    authorisation facts — so there is nothing there for an owner to override.
 * 3. It can never be publicly cached. §9.3.2 forbids a public cache directive
 *    on private content, and an override's allow is the most private there is.
 *
 * ## 🛑 Why the reason and the rate limit live in a table
 *
 * A session flag would satisfy "an override exists" and leave nobody able to
 * answer "who read what, and why". And the rate limit is counted from the
 * grants table rather than a cache bucket: a Valkey counter resets on a flush,
 * an eviction or a restart, so "3 per hour" would hold only while the cache
 * happened to be healthy — and the one time the limit matters is an incident,
 * which is also when somebody is restarting things.
 */
final readonly class BreakGlass
{
    /**
     * How long a window stays open.
     *
     * 🛑 §8.12.20 does not give a number, so this one is argued rather than
     * picked: fifteen minutes is §8.13.3's dashboard idle timeout, which is the
     * longest the owner's own session survives unattended. A window outliving
     * the session that opened it would be an override nobody is present for.
     */
    public const int WINDOW_MINUTES = 15;

    /** §8.12.20's limit, in words: "rate-limited to 3/hour". */
    public const int MAX_PER_HOUR = 3;

    /**
     * 🛑 The floor on §8.12.20's "mandatory reason".
     *
     * Mandatory has to mean more than NOT NULL, which a single character
     * satisfies. Forty characters and four distinct words is about one
     * sentence — enough that somebody reading it in six months learns
     * something, and little enough that it is not an obstacle during an
     * incident.
     */
    public const int MIN_REASON = 40;

    public const int MIN_REASON_WORDS = 4;

    /** The column's width, and what keeps the field answerable in a review. */
    public const int MAX_REASON = 500;

    public function __construct(
        private RoleResolver $roles,
        private Session $session,
    ) {}

    /**
     * 🛑 Open a window, or refuse with the precondition that was not met.
     *
     * @param  int|null  $now  injected for tests; `time()` otherwise
     *
     * @throws BreakGlassRefused
     */
    public function open(User $actor, Project $project, string $reason, ?int $now = null): BreakGlassGrant
    {
        $now ??= time();
        $reason = trim($reason);

        /*
         * 🛑 In this order, because the order decides what the owner is told
         * first — and "you are not an installation owner" is more useful than
         * "your reason is too short" to somebody who will never be allowed to
         * do this at all.
         */
        $this->assertOwner($actor);
        $this->assertSecondFactor($actor);
        $this->assertSteppedUp($actor, $now);
        $this->assertReason($actor, $reason);
        $this->assertWithinRate($actor, $project, $now);

        $grant = DB::transaction(function () use ($actor, $project, $reason, $now): BreakGlassGrant {
            $grant = new BreakGlassGrant;

            $grant->forceFill([
                'id' => Uuid::v7(),
                'organisation_id' => $project->organisation_id,
                'project_id' => $project->id,
                'user_id' => $actor->id,
                'reason' => $reason,
                'opened_at' => date('Y-m-d H:i:s.v', $now),
                'expires_at' => date('Y-m-d H:i:s.v', $now + self::WINDOW_MINUTES * 60),
            ])->save();

            Audit::record(
                action: 'authz.break_glass.opened',
                actorType: ActorType::User,
                organisationId: $project->organisation_id,
                actorId: $actor->id,
                subjectType: 'break_glass_grant',
                subjectId: $grant->id,
                /*
                 * 🛑 The reason goes in the chain as well as in the row, and
                 * the duplication is deliberate: the row cascades away with the
                 * account (§20's platform erasure) and §8.22.5 makes the chain
                 * append-only. The reviewable copy is the chain's.
                 */
                payload: [
                    'project' => bin2hex($project->id),
                    'reason' => $reason,
                    'window_minutes' => self::WINDOW_MINUTES,
                ],
            );

            return $grant;
        });

        /*
         * 🛑 §8.12.20's "raising an operator alert", outside the transaction.
         *
         * A notification that failed to send must not roll back the audit
         * record of an override that happened — the record is the requirement,
         * and an alert nobody received is a smaller problem than a window
         * nobody can see. The queue retries; the chain cannot be rewritten.
         */
        $this->alert($grant, $actor, $project);

        return $grant;
    }

    /**
     * Close a window early.
     *
     * 🛑 Distinct from letting it expire, and recorded as such: a grant closed
     * deliberately is evidence that somebody was watching, and one that ran its
     * full window is not.
     */
    public function close(BreakGlassGrant $grant, User $actor, ?int $now = null): void
    {
        if ($grant->closed_at !== null) {
            return;
        }

        $now ??= time();

        DB::transaction(function () use ($grant, $actor, $now): void {
            $grant->forceFill(['closed_at' => date('Y-m-d H:i:s.v', $now)])->save();

            Audit::record(
                action: 'authz.break_glass.closed',
                actorType: ActorType::User,
                organisationId: $grant->organisation_id,
                actorId: $actor->id,
                subjectType: 'break_glass_grant',
                subjectId: $grant->id,
                payload: ['closed_early' => true],
            );
        });
    }

    /**
     * 🛑 The serving path's one question: does this dashboard user hold an open
     * window on this project?
     *
     * Returns the grant's **id** rather than the model, because that is all
     * {@see ReaderContext} carries and all §20.3's log needs — and because a
     * model here would mean a tenancy-scoped query on a path that has no tenant
     * (§8.9.4).
     *
     * 🛑 A raw query for the same reason {@see ReaderSessions}
     * uses one: the global §8.2.1 scope cannot be satisfied on the serving
     * path, and `acrossAllOrganisations()` would be a wider hammer than one
     * `DB::table()` with both keys in its index.
     *
     * 🛑 And the caller must only ask when the session carries a `user_id`. A
     * reader-identity session and an anonymous request can never hold a grant,
     * so asking would be one index seek per request for every reader on the
     * installation to answer a question whose answer is always null.
     *
     * @param  string  $userId  raw 16 bytes
     * @param  string  $projectId  raw 16 bytes
     * @return string|null the grant id, raw 16 bytes
     */
    public function activeFor(string $userId, string $projectId, ?int $now = null): ?string
    {
        $now ??= time();

        $row = DB::table('break_glass_grants')
            ->select('id')
            ->where('user_id', $userId)
            ->where('project_id', $projectId)
            ->whereNull('closed_at')
            ->where('expires_at', '>', date('Y-m-d H:i:s.v', $now))
            ->orderByDesc('expires_at')
            ->first();

        $id = $row->id ?? null;

        return is_string($id) ? $id : null;
    }

    /** How many windows this person has opened in the last hour. */
    public function openedInTheLastHour(User $actor, ?int $now = null): int
    {
        $now ??= time();

        return DB::table('break_glass_grants')
            ->where('user_id', $actor->id)
            ->where('opened_at', '>', date('Y-m-d H:i:s.v', $now - 3600))
            ->count();
    }

    // ------------------------------------------------------- the preconditions

    /** @throws BreakGlassRefused */
    private function assertOwner(User $actor): void
    {
        /*
         * `rolesAnywhere` with no organisation, which resolves installation
         * scope — an installation owner's assignment is not organisation-bound.
         */
        if (! in_array(Role::InstallationOwner, $this->roles->rolesAnywhere($actor), true)) {
            $this->refuse($actor, BreakGlassRejection::NotAnInstallationOwner);
        }
    }

    /** @throws BreakGlassRefused */
    private function assertSecondFactor(User $actor): void
    {
        if (! MfaEnforcement::isEnrolled($actor)) {
            $this->refuse($actor, BreakGlassRejection::MfaNotEnrolled);
        }
    }

    /**
     * §8.13.5's five-minute window, read from the session rather than passed in.
     *
     * 🛑 Read here, not accepted as a parameter, and that is what makes it
     * unskippable: a caller who could supply the confirmation time could supply
     * `now()`. The only way to satisfy this is a session that really did
     * confirm a password within the window, which is the fact §8.12.20 asks
     * for.
     *
     * @throws BreakGlassRefused
     */
    private function assertSteppedUp(User $actor, int $now): void
    {
        $confirmedAt = $this->session->get(SessionStamps::CONFIRMED_AT);

        $fresh = is_int($confirmedAt)
            && $now - $confirmedAt < RequireRecentAuthentication::SENSITIVE_MINUTES * 60;

        if (! $fresh) {
            $this->refuse($actor, BreakGlassRejection::StepUpRequired);
        }
    }

    /** @throws BreakGlassRefused */
    private function assertReason(User $actor, string $reason): void
    {
        if (mb_strlen($reason) > self::MAX_REASON) {
            $this->refuse($actor, BreakGlassRejection::ReasonTooLong);
        }

        /*
         * 🛑 A length AND a word count, because a length alone is satisfied by
         * `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`. Distinct words, so
         * `incident incident incident incident` does not pass either — a
         * placeholder that repeats is still a placeholder.
         */
        $words = preg_split('/[^\p{L}\p{N}]+/u', mb_strtolower($reason), -1, PREG_SPLIT_NO_EMPTY) ?: [];
        $distinct = count(array_unique(array_filter($words, static fn (string $w): bool => mb_strlen($w) > 1)));

        if (mb_strlen($reason) < self::MIN_REASON || $distinct < self::MIN_REASON_WORDS) {
            $this->refuse($actor, BreakGlassRejection::ReasonTooThin);
        }
    }

    /** @throws BreakGlassRefused */
    private function assertWithinRate(User $actor, Project $project, int $now): void
    {
        if ($this->activeFor($actor->id, $project->id, $now) !== null) {
            $this->refuse($actor, BreakGlassRejection::AlreadyOpen);
        }

        if ($this->openedInTheLastHour($actor, $now) >= self::MAX_PER_HOUR) {
            $this->refuse($actor, BreakGlassRejection::RateLimited);
        }
    }

    /**
     * 🛑 Record the refusal, then throw.
     *
     * Every refused attempt is audited, not only the successful activations. A
     * sequence of refusals is exactly the signal an operator wants, and it is
     * the signal somebody who has taken an owner's session would produce while
     * working out which precondition they cannot meet.
     *
     * @throws BreakGlassRefused
     */
    private function refuse(User $actor, BreakGlassRejection $rejection): never
    {
        Audit::record(
            action: $rejection->auditAction(),
            actorType: ActorType::User,
            organisationId: null,
            actorId: $actor->id,
            subjectType: 'user',
            subjectId: $actor->id,
        );

        throw BreakGlassRefused::of($rejection);
    }

    /** §8.12.20's operator alert. */
    private function alert(BreakGlassGrant $grant, User $actor, Project $project): void
    {
        $owners = User::query()
            ->whereIn('id', $this->roles->installationOwnerIds())
            ->get()
            ->all();

        if ($owners === []) {
            return;
        }

        Notification::send($owners, new BreakGlassOpened($grant, $actor, $project));
    }
}
