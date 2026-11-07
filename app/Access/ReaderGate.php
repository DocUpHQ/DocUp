<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Access;

use App\Auth\AccessLevel;
use App\Serving\SnapshotMount;
use App\Serving\SnapshotVersion;

/**
 * What the four surfaces of §8.12.21 call: load the policy, decide, record.
 *
 * 🛑 **This is not a second decision and must never become one.** Everything
 * about *whether* a reader may read is {@see EffectiveAccess}; this class
 * assembles that function's inputs from the routing snapshot and writes the
 * outcome to §20.3's log. The division is the same one §12.3 draws between
 * `narrows` (a constraint) and `permits` (a decision), and the same one Phase
 * 16 drew when it put `MountExposure` beside the lattice rather than inside it:
 * assembly here, judgement there, and an architecture test that fails if
 * judgement leaks out.
 *
 * So there is no branch in this class on a visibility, a level or a rule. If a
 * future change wants one, it belongs in the function.
 *
 * ## 🛑 Why every request pays for this
 *
 * §8.12.14: "There MUST be **no public fast path** that bypasses an
 * authorisation decision on a cached `is_public` flag. A stale read in the
 * unsafe direction serves private bytes with no decision at all, which is a
 * worse class of bug than a stale allow for an already-authorised reader."
 *
 * A public project therefore takes the same path as a private one. It is
 * affordable because it has to be: the policy comes from one query cached on
 * the authz epoch, the decision is pure, and the log write is an insert that
 * cannot fail the request.
 */
final readonly class ReaderGate
{
    /**
     * The decision header's name — §17's "the decision header".
     *
     * 🛑 On the `X-DocUp-` family §7.4 strips from every inbound request, so a
     * reader cannot forge one and nothing downstream can mistake theirs for
     * DocUp's. {@see AccessDecision::header()} builds the value and says why a
     * denial carries one at all.
     */
    public const string DECISION_HEADER = 'X-DocUp-Decision';

    public function __construct(private ReaderPolicies $policies) {}

    /**
     * Authorise one reader request against a resolved mount and version.
     *
     * @param  string  $path  normalised, relative to the version root
     * @param  AccessLevel|null  $componentMinAccess  🛑 §8.7.7's ceiling from
     *                                                the published manifest,
     *                                                supplied **only** once the
     *                                                mount has matched — which
     *                                                is what "re-evaluated on
     *                                                every request after mount
     *                                                matching" means. Null
     *                                                before the match.
     * @param  ReaderContext|null  $reader  🛑 null means anonymous, and in Phase
     *                                      21 it is always null: no reader
     *                                      identity exists until Phase 22
     *                                      builds `docs_sessions` and the grant
     *                                      handoff. The parameter is here so
     *                                      that phase changes where the context
     *                                      comes from and nothing about how it
     *                                      is used.
     * @param  int|null  $now  unix seconds; null reads the clock. The clock is
     *                         read **here** and never in the decision function,
     *                         which is what keeps that function pure and the
     *                         48-case table exact.
     */
    public function authorise(
        SnapshotMount $mount,
        SnapshotVersion $version,
        string $language,
        string $path,
        AccessSurface $surface = AccessSurface::Proxy,
        ?AccessLevel $componentMinAccess = null,
        ?ReaderContext $reader = null,
        ?int $now = null,
        int $searchGeneration = 0,
    ): AccessDecision {
        $project = $mount->project;
        $now ??= time();
        $reader ??= ReaderContext::anonymous();

        $decision = EffectiveAccess::decide(new AccessRequest(
            projectId: $project->id,
            /*
             * 🛑 Unrecognised lattice values resolve to the **strongest** level,
             * not the weakest. A column value this code has not been taught —
             * a future migration's fifth level, a hand-edited row — must deny,
             * because the alternative is serving private bytes on the strength
             * of a string nobody recognised.
             */
            projectVisibility: self::level($project->visibility),
            versionVisibility: self::level($version->visibility),
            mountExposure: $mount->mountExposure,
            policy: $this->policies->forProject($project->id, $project->authzEpoch),
            reader: $reader,
            versionSlug: $version->slug,
            language: $language,
            path: $path,
            surface: $surface,
            componentMinAccess: $componentMinAccess,
            denyStatus: $project->denyStatus,
            now: $now,
            policyGeneration: $project->policyGeneration,
            searchGeneration: $searchGeneration,
            /*
             * 🛑 §8.12.23's case (b), and **both** halves of it: a challenge is
             * permitted when "the resource's **existence is already public**,
             * because the project appears in the visibility-filtered index of
             * §8.2.7, and only its content requires authentication".
             *
             * 🛑 The first version read the project alone, and that is a
             * disclosure. A public project with a `members` version would then
             * answer 401 with a `WWW-Authenticate` header for that version —
             * confirming to anybody who guessed the slug that the version
             * exists. A private version is absent from the sitemap, the
             * flyout, `llms.txt` and search (§8.6.2), so its existence is
             * precisely what has **not** been disclosed.
             *
             * So the resource's existence is public when the project is public
             * **and** this version is. What remains for a challenge is the case
             * the requirement describes: otherwise-public content with a
             * guarded path inside it, where a reader can already see the
             * project and the version and only the page needs a credential.
             */
            existencePublic: $project->visibility === 'public' && $version->visibility === 'public',
        ));

        DecisionLog::record(
            decision: $decision,
            surface: $surface,
            organisationId: $project->organisationId,
            projectId: $project->id,
            versionId: $version->id,
            mountId: $mount->id,
            subject: $reader->subject,
            authzEpoch: $project->authzEpoch,
            now: $now,
        );

        return $decision;
    }

    /**
     * 🛑 §8.12.21's "authorised view", as a predicate the generated surfaces
     * can ask.
     *
     * > "Every privacy-sensitive derived surface MUST be generated from the
     * > **authorised** view: search index and API, sitemap, `robots.txt`,
     * > `llms.txt`, flyout, addons payload, file manifests, build logs and
     * > analytics."
     *
     * "Generated from the authorised view" is implemented literally: it asks
     * {@see EffectiveAccess} whether an **anonymous** reader may read the
     * resource, which is exactly the reader a sitemap, a `robots.txt` or an
     * `llms.txt` is written for. A generator that applied its own filter — a
     * `where('visibility', 'public')` and a hope — would be a second
     * authorisation path, and the first thing it would forget is that
     * §8.2.10's project visibility dominates the version's.
     *
     * 🛑 **Nothing is logged.** A generation pass makes one decision per
     * version per mount; §20.3's log is for reader requests, and writing
     * thousands of synthetic rows at every pointer flip would bury the
     * denials it exists to preserve.
     *
     * Takes stored strings rather than models, because the callers hold
     * Eloquent rows and this namespace must not depend on them.
     *
     * @param  string  $projectId  raw 16 bytes
     * @param  string  $mountExposure  §10.5's lattice plus `inherit`
     */
    public function anonymousMayRead(
        string $projectId,
        string $projectVisibility,
        string $versionVisibility,
        string $mountExposure,
        string $versionSlug,
        int $authzEpoch,
        string $language = 'en',
        AccessSurface $surface = AccessSurface::Proxy,
        ?int $now = null,
    ): bool {
        return EffectiveAccess::decide(new AccessRequest(
            projectId: $projectId,
            projectVisibility: self::level($projectVisibility),
            versionVisibility: self::level($versionVisibility),
            mountExposure: $mountExposure,
            policy: $this->policies->forProject($projectId, $authzEpoch),
            reader: ReaderContext::anonymous(),
            versionSlug: $versionSlug,
            language: $language,
            surface: $surface,
            now: $now ?? time(),
        ))->allowed;
    }

    /**
     * A lattice value from a stored string, failing closed.
     *
     * `restricted` for an unrecognised value, which is the strongest level and
     * therefore the one no reader reaches without an explicit rule naming the
     * resource. See the note at the call site for why that direction.
     */
    private static function level(string $stored): AccessLevel
    {
        return AccessLevel::tryFrom($stored) ?? AccessLevel::Restricted;
    }

    /**
     * The headers a decision contributes to a response.
     *
     * 🛑 `WWW-Authenticate` appears **only** where §8.12.23 permits a
     * challenge, and {@see AccessDecision::mayChallenge()} is the one predicate
     * that decides it. §8.12.24 fixes the value: `Bearer realm="docup",
     * scope="docs:read"`.
     *
     * @return array<string, string>
     */
    public static function headers(AccessDecision $decision): array
    {
        $headers = [self::DECISION_HEADER => $decision->header()];

        if ($decision->mayChallenge()) {
            $headers['WWW-Authenticate'] = 'Bearer realm="docup", scope="docs:read"';
        }

        return $headers;
    }
}
