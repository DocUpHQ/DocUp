<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding;

use App\Audit\ActorType;
use App\Audit\Audit;
use App\Branding\Chrome\ChromeContent;
use App\Branding\Email\EmailSlots;
use App\Models\DomainMount;
use App\Models\ProjectVersion;
use App\Models\ThemeRevision;
use App\Support\Uuid;
use Illuminate\Support\Facades\DB;

/**
 * 🛑 The only writer of `theme_revisions`, and the only place §8.14.5's gate
 * decides anything.
 *
 * Every rule this phase has lives on one of two sides of a line. On one side
 * are the pure ones — {@see TokenGrammar}, {@see ThemeCascade},
 * {@see ContrastGate} — which are functions and have unit tests. On the other
 * is this class, which is where those answers meet a row, an audit event and
 * an operator's override. Keeping the decision here rather than in a model
 * mutator is what makes "a theme below 3:1 cannot be published" a statement
 * about the system rather than about one code path.
 *
 * ## 🛑 Two hashes, and they are not the same hash
 *
 * `theme_revisions.content_hash` is over **this revision's own** normalised
 * content. It answers "has this draft changed since I last looked" and is the
 * ETag of its preview.
 *
 * The **stylesheet** URL is addressed by {@see ResolvedTheme::contentHash()},
 * computed per consumer from the whole cascade. That is what makes §8.14.4's
 * economy real: "500 projects cost one bundle plus 500 small files" holds
 * because two projects whose cascades resolve identically share one URL and one
 * cache entry, which a revision-scoped hash could not express — the same
 * organisation revision resolves to different bytes under two different project
 * revisions.
 */
final readonly class ThemeRevisions
{
    public function __construct(
        private TokenGrammar $grammar,
        private Themes $themes,
        private ResolvedFrameAncestors $frameAncestors,
    ) {}

    public static function make(?string $organisationId = null, ?string $projectId = null): self
    {
        $grammar = new TokenGrammar(new ThemeAssets($organisationId, $projectId), Themes::catalogue());

        return new self($grammar, new Themes($grammar), app(ResolvedFrameAncestors::class));
    }

    /**
     * 🛑 §8.14.6: save a draft, which affects no consuming project.
     *
     * Validation happens **here**, on the draft, not at publish. An operator
     * who typed `calc(100% - 2px)` should be told now and not in three days
     * when they try to go live — and a draft that could hold an invalid value
     * would be a draft whose preview could not be rendered.
     *
     * @param  array<array-key, mixed>  $tokens  this level's own values
     * @param  array<array-key, mixed>  $locks  §8.14.1's per-path locks
     * @param  array<array-key, mixed>  $chrome  §8.14.3's structured content
     * @param  array<array-key, mixed>  $email  §8.14.13's slot overrides
     *
     * @throws TokenRefused
     */
    public function draft(
        CascadeLevel $level,
        ?string $scopeId,
        ?string $organisationId,
        array $tokens,
        array $locks = [],
        array $chrome = [],
        array $email = [],
        ?string $actorId = null,
    ): ThemeRevision {
        $parsed = $this->grammar->parseAll($tokens, $level);
        $declaredLocks = ThemeLocks::fromAuthored($locks);

        /*
         * 🛑 §8.14.1's locks, enforced at write time against everything
         * shallower. {@see ThemeLocks} says why resolution enforces them too
         * and why both are needed.
         */
        ThemeCascade::assertWritable($parsed, $this->inheritedLocks($level, $scopeId, $organisationId), $level);

        /*
         * 🛑 Parsed before storage, so a chrome fragment or an email slot that
         * §8.14.3 or §8.14.13 refuses never reaches a column. Both return
         * normalised data, which is what is stored — so the bytes in the row
         * are DocUp's own shape rather than the request's.
         */
        $normalisedChrome = ChromeContent::parse($chrome, $level)->toStorage();
        $normalisedEmail = EmailSlots::parse($email)->toStorage();

        $storedTokens = [];

        foreach ($parsed as $name => $pair) {
            $token = TokenRegistry::get($name);

            $storedTokens[$name] = $token->isPaired() && $pair->differs()
                ? ['light' => $pair->light->toStorage(), 'dark' => $pair->dark->toStorage()]
                : $pair->light->toStorage();
        }

        $revision = new ThemeRevision;
        /* `id` is `@property-read`, so it is filled through the model. */
        $revision->forceFill(['id' => Uuid::v7()]);
        $revision->organisation_id = $organisationId;
        $revision->scope_type = $level->value;
        $revision->scope_id = $scopeId;
        $revision->revision_number = $this->nextRevisionNumber($level, $scopeId);
        $revision->state = 'draft';
        $revision->tokens = $storedTokens;
        $revision->locks = $declaredLocks->toStorage();
        $revision->chrome = $normalisedChrome;
        $revision->email = $normalisedEmail;
        $revision->content_hash = self::ownHash($storedTokens, $declaredLocks->toStorage(), $normalisedChrome, $normalisedEmail);
        $revision->created_by = $actorId;

        /*
         * The contrast report is computed on the draft, because §8.14.6's
         * whole point is that an operator can look at a revision before it is
         * live — and the first thing worth looking at is whether it would be
         * refused.
         */
        $report = $this->judge($revision);
        $revision->contrast = $report->toArray();
        $revision->contrast_verdict = $report->worst()->value;

        $revision->save();

        Audit::record(
            action: 'branding.theme.drafted',
            actorType: $actorId === null ? ActorType::System : ActorType::User,
            organisationId: $organisationId,
            actorId: $actorId,
            subjectType: 'theme_revision',
            subjectId: (string) $revision->id,
            payload: [
                'scope' => $level->value,
                'revision' => $revision->revision_number,
                'tokens' => count($storedTokens),
                'locks' => $declaredLocks->toStorage(),
                'contrast' => $report->worst()->value,
            ],
        );

        return $revision;
    }

    /**
     * 🛑 §8.14.5's gate, and §8.14.6's publish.
     *
     * > "warn below 4.5:1, **refuse publication below 3:1**, operator override
     * > audited."
     *
     * The refusal is here and nowhere else. `$override` is the escape hatch
     * §8.14.5 requires, and it is not a quiet one: it is recorded on the row
     * for as long as the revision is live, it demands a reason, and it raises
     * its own audit action so a search for `branding.theme.contrast_overridden`
     * finds every one.
     *
     * @throws TokenRefused when a pair is below 3:1 and no override was given
     */
    public function publish(ThemeRevision $revision, ?string $actorId = null, bool $override = false, string $reason = ''): ThemeRevision
    {
        $report = $this->judge($revision);

        if ($report->refuses() && ! $override) {
            $refusals = array_map(
                static fn (ContrastFinding $finding): string => $finding->describe(),
                $report->refusals(),
            );

            throw TokenRefused::of(
                TokenRejection::ContrastTooLow,
                'contrast',
                'below 3:1 — '.implode('; ', $refusals),
            );
        }

        if ($report->refuses() && trim($reason) === '') {
            /*
             * 🛑 An override with no reason is not an override. §8.14.5 says
             * "operator override audited", and an audit record whose reason
             * field is empty tells whoever reads it in a year that somebody
             * clicked something.
             */
            throw TokenRefused::of(
                TokenRejection::ContrastTooLow,
                'contrast',
                'an override must state a reason',
            );
        }

        $level = CascadeLevel::from($revision->scope_type);

        DB::transaction(function () use ($revision, $report, $actorId, $override): void {
            /*
             * 🛑 The previous publication is superseded, not deleted. A reader
             * may hold a year-long `immutable` cache entry for a stylesheet
             * addressed by the old theme's hash, and §8.14.4's guarantee is
             * that the bytes behind an address never change — so the row that
             * can regenerate those bytes stays.
             *
             * In a transaction with the new publication because the unique
             * index permits exactly one `published` row per scope: without it,
             * the insert races the update and one of the two fails on 1062.
             */
            ThemeRevision::query()
                ->where('scope_type', $revision->scope_type)
                ->where('state', 'published')
                ->when(
                    $revision->scope_id === null,
                    fn ($query) => $query->whereNull('scope_id'),
                    fn ($query) => $query->where('scope_id', $revision->scope_id),
                )
                ->whereKeyNot($revision->getKey())
                ->update(['state' => 'superseded']);

            $revision->state = 'published';
            $revision->contrast = $report->toArray();
            $revision->contrast_verdict = $report->worst()->value;
            $revision->contrast_override = $override && $report->refuses();
            /* Immutable, because the column is cast to one. */
            $revision->published_at = now()->toImmutable();
            $revision->published_by = $actorId;
            $revision->save();
        });

        Audit::record(
            action: 'branding.theme.published',
            actorType: $actorId === null ? ActorType::System : ActorType::User,
            organisationId: $revision->organisation_id,
            actorId: $actorId,
            subjectType: 'theme_revision',
            subjectId: (string) $revision->id,
            payload: [
                'scope' => $level->value,
                'revision' => $revision->revision_number,
                'contrast' => $report->worst()->value,
                'warnings' => count($report->warnings()),
            ],
        );

        if ($revision->contrast_override) {
            $revision->contrast_override_reason = trim($reason);
            $revision->save();

            Audit::record(
                action: 'branding.theme.contrast_overridden',
                actorType: $actorId === null ? ActorType::System : ActorType::User,
                organisationId: $revision->organisation_id,
                actorId: $actorId,
                subjectType: 'theme_revision',
                subjectId: (string) $revision->id,
                reasonCode: 'contrast_below_minimum',
                payload: [
                    'reason' => trim($reason),
                    'refusals' => array_map(
                        static fn (ContrastFinding $finding): array => $finding->toArray(),
                        $report->refusals(),
                    ),
                ],
            );
        }

        /*
         * 🛑 §8.14.16's `frame-ancestors`, recomputed for every project this
         * publication can affect. Phase 28 added it, and the reason it is HERE
         * rather than on the serving path is in
         * {@see ResolvedFrameAncestors}: §8.9.1 forbids a query on the
         * resolution path and §9.2 has no room for a four-rung cascade per
         * document request, so the value is written when its inputs change.
         *
         * After the audit record, deliberately. The publication is the fact to
         * be audited; the reconciliation is a consequence of it, and an
         * exception here must not be able to lose the record of a publish that
         * did happen.
         */
        $this->frameAncestors->reconcile($level, $revision->scope_id === null ? null : (string) $revision->scope_id);

        return $revision;
    }

    /**
     * 🛑 §8.14.5's report for one revision, judged where it sits.
     *
     * The theme judged is the cascade **as this revision would make it**:
     * everything shallower as published, this revision at its own rung,
     * nothing deeper. Judging the revision's own tokens alone would report a
     * project that overrode one colour as having no text at all; judging with
     * deeper rungs applied would let a mount's override hide a project's
     * unreadable pairing.
     */
    public function judge(ThemeRevision $revision): ContrastReport
    {
        $level = CascadeLevel::from($revision->scope_type);
        $scopeId = $revision->scope_id === null ? null : (string) $revision->scope_id;

        $target = match ($level) {
            CascadeLevel::Installation => new ThemeTarget,
            CascadeLevel::Organisation => new ThemeTarget(organisationId: $scopeId),
            CascadeLevel::Project => new ThemeTarget(
                organisationId: $revision->organisation_id === null ? null : (string) $revision->organisation_id,
                projectId: $scopeId,
            ),
            CascadeLevel::Mount => new ThemeTarget(
                organisationId: $revision->organisation_id === null ? null : (string) $revision->organisation_id,
                mountId: $scopeId,
            ),
            CascadeLevel::Version => new ThemeTarget(
                organisationId: $revision->organisation_id === null ? null : (string) $revision->organisation_id,
                versionId: $scopeId,
            ),
        };

        $resolved = $this->themes->preview($target, $revision);

        return ContrastGate::judge(
            $resolved->scheme(ColourScheme::Light),
            $resolved->scheme(ColourScheme::Dark),
        );
    }

    /**
     * The union of every shallower level's locks (§8.14.1).
     *
     * 🛑 Only levels **above** this one. A level's own locks do not constrain
     * its own values — "this is the brand colour and nobody below changes it"
     * is the normal case, and a level that could not set a token it locked
     * would make locking useless.
     */
    private function inheritedLocks(CascadeLevel $level, ?string $scopeId, ?string $organisationId): ThemeLocks
    {
        $target = match ($level) {
            CascadeLevel::Installation => null,
            CascadeLevel::Organisation => new ThemeTarget,
            CascadeLevel::Project => new ThemeTarget(organisationId: $organisationId),
            CascadeLevel::Mount, CascadeLevel::Version => new ThemeTarget(
                organisationId: $organisationId,
                projectId: $this->projectOf($level, $scopeId),
            ),
        };

        return $target === null ? ThemeLocks::none() : $this->themes->resolve($target)->locks;
    }

    /**
     * The project a mount or a version belongs to, for the lock lookup.
     *
     * Returns null when it cannot be determined, which makes the inherited
     * lock set narrower than reality — so a write that should have been
     * refused by a project lock would be accepted. {@see ThemeCascade} is why
     * that is survivable: resolution drops the value again, so the lock still
     * takes effect on every reader. The loud error is what is lost, not the
     * rule.
     */
    private function projectOf(CascadeLevel $level, ?string $scopeId): ?string
    {
        if ($scopeId === null) {
            return null;
        }

        $key = Uuid::tryToBytes((string) $scopeId);

        if ($key === null) {
            return null;
        }

        if ($level === CascadeLevel::Mount) {
            $mount = DomainMount::query()->whereKey($key)->first();

            return $mount instanceof DomainMount ? (string) $mount->project_id : null;
        }

        $version = ProjectVersion::query()->whereKey($key)->first();

        return $version instanceof ProjectVersion ? (string) $version->project_id : null;
    }

    private function nextRevisionNumber(CascadeLevel $level, ?string $scopeId): int
    {
        $highest = ThemeRevision::query()
            ->where('scope_type', $level->value)
            ->when(
                $scopeId === null,
                fn ($query) => $query->whereNull('scope_id'),
                fn ($query) => $query->where('scope_id', Uuid::tryToBytes((string) $scopeId) ?? str_repeat("\xff", 16)),
            )
            ->max('revision_number');

        return is_numeric($highest) ? (int) $highest + 1 : 1;
    }

    /**
     * 🛑 This revision's own identity, over canonical JSON.
     *
     * Not the stylesheet address — see the class docblock. `JSON_THROW_ON_ERROR`
     * and sorted keys so the hash is a function of the content rather than of
     * the order a form submitted its fields in; an unsorted hash would make
     * every save look like a change.
     *
     * @param  array<string, mixed>  $tokens
     * @param  list<string>  $locks
     * @param  array<string, mixed>  $chrome
     * @param  array<string, mixed>  $email
     */
    private static function ownHash(array $tokens, array $locks, array $chrome, array $email): string
    {
        ksort($tokens);
        ksort($chrome);
        ksort($email);

        return hash('sha256', json_encode([
            'tokens' => $tokens,
            'locks' => $locks,
            'chrome' => $chrome,
            'email' => $email,
        ], JSON_THROW_ON_ERROR));
    }
}
