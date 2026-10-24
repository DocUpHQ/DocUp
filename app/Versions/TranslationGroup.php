<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Versions;

use App\Audit\ActorType;
use App\Audit\Audit;
use App\Models\ProjectVersion;
use App\Support\Uuid;
use Illuminate\Support\Facades\DB;

/**
 * §8.6.12: a translation is a **version**, not a sibling project.
 *
 * > "🛑 Language MUST be a property of a project version with a
 * > `translation_group_id`, **not** a sibling project. Read the Docs models
 * > translations as separate projects, which duplicates domains,
 * > authentication and branding per language. One project, one domain set,
 * > one policy, one brand, a real language switcher, and a routing path
 * > that stays two-dimensional."
 *
 * 🛑 **The group is what makes a language switcher possible at all.** `/en/v2/`
 * and `/ja/v2/` are two rows sharing a slug (§10.4's
 * `UNIQUE (project_id, language, slug)`), and nothing but a shared
 * `translation_group_id` says they are the same documentation. Matching on
 * the slug would be close enough until a project translated `v2` as `v2-ja`
 * — which is exactly what a translator does when the slug is user-visible.
 *
 * 🛑 **Grouping is an explicit act.** Nothing here infers a group from
 * equal slugs, because the inference is wrong in both directions: two
 * versions can share a slug and not be translations of each other (a
 * monorepo with two components), and two translations can have different
 * slugs.
 */
final readonly class TranslationGroup
{
    /**
     * Put these versions in one translation group.
     *
     * The group id is minted from the first member when none of them has
     * one, and an existing group is joined rather than replaced — so
     * adding a third language to a pair does not renumber the pair and
     * invalidate whatever cached the group.
     *
     * @param  list<ProjectVersion>  $versions
     * @param  string|null  $actorId  raw 16 bytes
     *
     * @throws VersionRefused when two of them share a language
     */
    public function group(array $versions, ?string $actorId = null): string
    {
        $this->assertOneVersionPerLanguage($versions);

        $groupId = null;

        foreach ($versions as $version) {
            if (is_string($version->translation_group_id) && $version->translation_group_id !== '') {
                $groupId ??= $version->translation_group_id;
            }
        }

        $groupId ??= Uuid::v7();

        foreach ($versions as $version) {
            if ($version->translation_group_id === $groupId) {
                continue;
            }

            $version->forceFill(['translation_group_id' => $groupId])->save();

            Audit::record(
                action: 'version.translation_grouped',
                actorType: $actorId === null ? ActorType::System : ActorType::User,
                organisationId: $version->organisation_id,
                actorId: $actorId,
                subjectType: 'project_version',
                subjectId: $version->id,
                payload: ['group' => bin2hex($groupId), 'language' => $version->language],
            );
        }

        return $groupId;
    }

    /**
     * The other languages of this version, for a language switcher.
     *
     * Excludes the version itself, so a caller rendering a switcher does
     * not have to filter its own entry out — and returns an empty list for
     * an ungrouped version rather than null, because "this documentation
     * exists in one language" and "this documentation is not grouped" are
     * the same thing to a reader.
     *
     * @return list<ProjectVersion>
     */
    public function siblingsOf(ProjectVersion $version): array
    {
        if (! is_string($version->translation_group_id) || $version->translation_group_id === '') {
            return [];
        }

        return array_values(
            ProjectVersion::query()
                ->where('project_id', $version->project_id)
                ->where('translation_group_id', $version->translation_group_id)
                ->whereKeyNot($version->id)
                ->where('active', true)
                ->orderBy('language')
                ->get()
                ->all(),
        );
    }

    /**
     * The same documentation in another language, or null.
     *
     * 🛑 Null is the answer §8.6.13 needs: "A missing page in a non-default
     * language MUST return 404 plus a notification banner, **never a
     * silent fallback to another language**." A helper that fell back
     * would make that requirement unimplementable by its callers.
     */
    public function inLanguage(ProjectVersion $version, string $language): ?ProjectVersion
    {
        if ($version->language === $language) {
            return $version;
        }

        foreach ($this->siblingsOf($version) as $sibling) {
            if ($sibling->language === $language) {
                return $sibling;
            }
        }

        return null;
    }

    /**
     * @param  list<ProjectVersion>  $versions
     *
     * @throws VersionRefused
     */
    private function assertOneVersionPerLanguage(array $versions): void
    {
        $seen = [];

        foreach ($versions as $version) {
            if (isset($seen[$version->language])) {
                /*
                 * 🛑 Two versions of one project in one language cannot be
                 * translations of each other — that is what a *version* is.
                 * Allowing it would make the language switcher ambiguous
                 * and `inLanguage()` return whichever row came back first.
                 */
                throw VersionRefused::of(
                    VersionRejection::DuplicateLanguageInGroup,
                    $version->language,
                );
            }

            $seen[$version->language] = true;
        }
    }

    /**
     * Every language this project publishes, for a switcher's full set.
     *
     * @param  string  $projectId  raw 16 bytes
     * @return list<string>
     */
    public function languagesOf(string $projectId): array
    {
        /** @var list<string> */
        return array_values(array_map(strval(...), DB::table('project_versions')
            ->where('project_id', $projectId)
            ->where('active', true)
            ->whereNull('deleted_at')
            ->distinct()
            ->orderBy('language')
            ->pluck('language')
            ->all()));
    }
}
