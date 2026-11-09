<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding;

use App\Models\DomainMount;
use App\Models\ThemeAssignment;
use App\Models\ThemeRevision;
use App\Support\Uuid;

/**
 * 🛑 The one place §8.14.1's cascade is assembled from rows.
 *
 * {@see ThemeCascade} is the rule; this is the reader. The split is the same
 * one §8.14.2 draws between a grammar and its call sites: the cascade can be
 * unit-tested over layers somebody constructed, and the query that finds those
 * layers has one implementation that the serving path, the dashboard, the
 * preview and the credential pages all go through.
 *
 * ## 🛑 Published revisions only
 *
 * `state = 'published'` on every rung, and §8.14.6 is why: "A token edit
 * currently going live across every consuming project instantly is a foot-gun;
 * staging is the mitigation." A draft that leaked into this query would be the
 * foot-gun with extra steps — an operator experimenting on an organisation
 * theme would restyle two hundred projects while deciding.
 *
 * {@see self::preview()} is the deliberate exception: it substitutes **one**
 * named draft at its own rung and leaves every other rung published, so a
 * preview shows what publishing that draft would actually do rather than what
 * it looks like in isolation.
 *
 * ## 🛑 The mount rung goes through an assignment
 *
 * §10.5 puts `theme_assignment_id` on `domain_mounts`, so the mount rung is
 * the revision that mount's **assignment** names. {@see ThemeAssignment} says
 * why the indirection earns its place.
 */
final readonly class Themes
{
    public function __construct(private TokenGrammar $grammar) {}

    /** With the installation font catalogue and no asset scope — enough to read. */
    public static function make(?string $organisationId = null, ?string $projectId = null): self
    {
        return new self(new TokenGrammar(
            new ThemeAssets($organisationId, $projectId),
            self::catalogue(),
        ));
    }

    /**
     * Resolve the theme one consumer sees.
     *
     * @throws TokenRefused when a stored revision no longer parses
     */
    public function resolve(ThemeTarget $target): ResolvedTheme
    {
        return ThemeCascade::resolve($this->layers($target, null, null));
    }

    /**
     * 🛑 §8.14.6's preview: one draft in place of its rung's published revision.
     *
     * > "Theme revisions MUST support **draft and preview before publish**."
     *
     * The draft replaces the published revision **at its own level** and
     * nothing else moves, which is the only version of preview that answers the
     * question an operator is asking. A preview that resolved the draft alone
     * would show a page styled by one rung of a four-rung cascade; a preview
     * that pulled every rung's latest draft would show a composite nobody is
     * about to publish.
     */
    public function preview(ThemeTarget $target, ThemeRevision $draft): ResolvedTheme
    {
        return ThemeCascade::resolve($this->layers($target, $draft, self::levelOf($draft)));
    }

    /**
     * The layers for one target, with an optional draft substituted.
     *
     * @return list<ThemeLayer>
     *
     * @throws TokenRefused
     */
    private function layers(ThemeTarget $target, ?ThemeRevision $substitute, ?CascadeLevel $substituteAt): array
    {
        /*
         * 🛑 The registry defaults are the root and are never a row. An
         * installation that has never saved a theme still resolves all
         * forty-five tokens, so nothing downstream has to cope with a missing
         * value — which is what lets {@see ContrastGate} treat an absent token
         * as a defect rather than a default.
         */
        $layers = [new ThemeLayer(CascadeLevel::Installation, $this->grammar->defaults(), ThemeLocks::none())];

        $rungs = [
            [CascadeLevel::Installation, null],
            [CascadeLevel::Organisation, $target->organisationId],
            [CascadeLevel::Project, $target->projectId],
            [CascadeLevel::Version, $target->versionId],
        ];

        foreach ($rungs as [$level, $scopeId]) {
            if ($level !== CascadeLevel::Installation && $scopeId === null) {
                continue;
            }

            $revision = $substituteAt === $level
                ? $substitute
                : $this->published($level, $scopeId);

            if ($revision instanceof ThemeRevision) {
                $layers[] = $this->layerFor($revision, $level);
            }
        }

        /*
         * The mount rung, last among the four §8.14.1 names and before the
         * version overlay in ordinal terms — {@see ThemeCascade} sorts, so the
         * order of this array does not matter and the code can read in the
         * order the rows are found.
         */
        if ($target->mountId !== null) {
            $revision = $substituteAt === CascadeLevel::Mount
                ? $substitute
                : $this->forMount($target->mountId);

            if ($revision instanceof ThemeRevision) {
                $layers[] = $this->layerFor($revision, CascadeLevel::Mount);
            }
        }

        return $layers;
    }

    /**
     * One rung's published revision.
     *
     * @throws TokenRefused never — the query is a lookup
     */
    private function published(CascadeLevel $level, ?string $scopeId): ?ThemeRevision
    {
        $query = ThemeRevision::query()
            ->where('scope_type', $level->value)
            ->where('state', 'published');

        $query = $scopeId === null
            ? $query->whereNull('scope_id')
            : $query->where('scope_id', Uuid::tryToBytes($scopeId) ?? str_repeat("\xff", 16));

        $revision = $query->first();

        return $revision instanceof ThemeRevision ? $revision : null;
    }

    /** The revision a mount's assignment names, if it has one. */
    private function forMount(string $mountId): ?ThemeRevision
    {
        $key = Uuid::tryToBytes($mountId);

        if ($key === null) {
            return null;
        }

        /*
         * `DomainMount` is organisation-scoped, and this runs on the serving
         * path where the tenant context is the request's. Read through the
         * model rather than a raw join so that scope still applies: a mount
         * from another tenant must not contribute a layer, and the global
         * scope is what guarantees it rather than a `where` somebody could
         * forget.
         */
        $mount = DomainMount::query()->whereKey($key)->first();

        if (! $mount instanceof DomainMount || $mount->theme_assignment_id === null) {
            return null;
        }

        $assignment = ThemeAssignment::query()->whereKey(
            Uuid::tryToBytes((string) $mount->theme_assignment_id) ?? str_repeat("\xff", 16),
        )->first();

        if (! $assignment instanceof ThemeAssignment) {
            return null;
        }

        $revision = $assignment->revision()->first();

        /*
         * 🛑 The assignment's revision is used whatever its state, and that is
         * deliberate rather than an oversight. An assignment is a named
         * binding an operator made to a specific revision; if that revision
         * were later superseded, honouring only `published` would silently
         * drop the mount's theme back to the project's — a visual change
         * across a reseller's estate caused by somebody publishing a newer
         * revision of a different theme. The RESTRICT foreign key is what
         * stops the row disappearing.
         */
        return $revision instanceof ThemeRevision ? $revision : null;
    }

    /**
     * Parse one stored revision into a layer.
     *
     * @throws TokenRefused when a stored value no longer satisfies its grammar
     */
    private function layerFor(ThemeRevision $revision, CascadeLevel $level): ThemeLayer
    {
        return new ThemeLayer(
            level: $level,
            tokens: $this->grammar->parseAll($revision->tokens, $level),
            locks: ThemeLocks::fromStorage($revision->locks),
            revisionId: (string) $revision->id,
        );
    }

    private static function levelOf(ThemeRevision $revision): CascadeLevel
    {
        return CascadeLevel::from($revision->scope_type);
    }

    /**
     * The installation's self-hosted font families (§8.14.2).
     *
     * @return list<string>
     */
    public static function catalogue(): array
    {
        $configured = config('branding.font_catalogue');

        if (! is_array($configured)) {
            return [];
        }

        return array_values(array_filter(
            array_map(static fn (mixed $family): string => is_string($family) ? $family : '', $configured),
            static fn (string $family): bool => $family !== '',
        ));
    }
}
