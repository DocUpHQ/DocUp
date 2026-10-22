<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Serving;

use App\Serving\FileKind;
use App\Serving\FileOutcome;
use App\Serving\HostKind;
use App\Serving\MountMatch;
use App\Serving\RejectionReason;
use App\Serving\Resolver;
use App\Serving\RouteKind;
use App\Serving\RouteOutcome;
use App\Serving\RoutingSnapshot;
use App\Serving\SnapshotMount;
use App\Serving\SnapshotProject;
use App\Serving\SnapshotVersion;
use Tests\TestCase;

/**
 * §7.3's grammar, step by step.
 *
 * §8.9.1 asks for ≥95% branch coverage and ≥80% mutation on this class, which
 * is why the cases below are exhaustive rather than representative: every
 * rejection reason the resolver can produce has a test that produces it, and
 * every grammar step has both a match and a miss.
 *
 * No database and no HTTP, because §8.9.1 requires the resolver to have "no
 * database queries and no framework dependencies". A test that needed either
 * would be evidence that it had acquired one.
 */
final class ResolverTest extends TestCase
{
    private Resolver $resolver;

    protected function setUp(): void
    {
        parent::setUp();

        $this->resolver = new Resolver;
    }

    // ----------------------------------------------------------------- builders

    private function version(
        string $slug = 'latest',
        string $language = 'en',
        bool $active = true,
        bool $listed = true,
        bool $published = true,
        ?string $manifestId = 'manifest-1',
        string $id = 'version-1',
    ): SnapshotVersion {
        return new SnapshotVersion(
            id: $id,
            slug: $slug,
            language: $language,
            active: $active,
            listed: $listed,
            published: $published,
            visibility: 'public',
            publishedManifestId: $manifestId,
        );
    }

    /** @param  list<SnapshotVersion>  $versions */
    private function project(
        array $versions,
        ?string $urlPrefix = null,
        string $scheme = 'lang_and_version',
        ?string $defaultVersionId = 'version-1',
        int $routingEpoch = 7,
    ): SnapshotProject {
        return new SnapshotProject(
            id: 'project-1',
            slug: 'alpha',
            urlPrefix: $urlPrefix,
            versioningScheme: $scheme,
            routingEpoch: $routingEpoch,
            visibility: 'public',
            chromeMode: 'injected',
            defaultVersionId: $defaultVersionId,
            versions: $versions,
        );
    }

    /** @param  list<string>|null  $versionScope */
    private function mount(
        SnapshotProject $project,
        string $pathPrefix = '',
        string $mode = 'canonical',
        ?string $schemeOverride = null,
        ?array $versionScope = null,
        string $id = 'mount-1',
    ): SnapshotMount {
        return new SnapshotMount(
            id: $id,
            pathPrefix: $pathPrefix,
            mode: $mode,
            mountExposure: 'inherit',
            isIndexable: $mode === 'canonical',
            project: $project,
            versioningSchemeOverride: $schemeOverride,
            versionScope: $versionScope,
        );
    }

    /** @param  list<SnapshotMount>  $mounts */
    private function snapshot(array $mounts, bool $servable = true): RoutingSnapshot
    {
        return new RoutingSnapshot(
            host: 'alpha.docs.example.com',
            kind: HostKind::DefaultSubdomain,
            servable: $servable,
            mounts: $mounts,
        );
    }

    // ------------------------------------------------------------- the host gate

    /** 🛑 §8.10.6: "Suspended and unverified hosts MUST be neither served nor certified." */
    public function test_an_unservable_host_resolves_nothing(): void
    {
        $snapshot = $this->snapshot([$this->mount($this->project([$this->version()]))], servable: false);

        $outcome = $this->resolver->resolveRoute($snapshot, '/en/latest/guide.html');

        $this->assertSame(RouteKind::Rejected, $outcome->kind);
        $this->assertSame(RejectionReason::HostNotServable, $outcome->reason);
        $this->assertSame(404, $outcome->status());
    }

    /**
     * 🛑 §8.9.3: "It MUST NEVER fall through to a default project."
     *
     * The strongest form of this test is that a host with mounts available in
     * the installation but none of its own resolves to nothing — which is what
     * makes a dangling CNAME pointed here serve nothing rather than somebody
     * else's documentation.
     */
    public function test_a_host_with_no_mounts_is_a_hard_404(): void
    {
        $outcome = $this->resolver->resolveRoute($this->snapshot([]), '/en/latest/guide.html');

        $this->assertSame(RouteKind::Rejected, $outcome->kind);
        $this->assertSame(RejectionReason::HostNotFound, $outcome->reason);
        $this->assertNull($outcome->mount);
        $this->assertNull($outcome->version);
    }

    public function test_an_empty_snapshot_is_never_servable(): void
    {
        $snapshot = RoutingSnapshot::empty('nothing.example.com', HostKind::Custom);

        $this->assertFalse($snapshot->servable);
        $this->assertSame([], $snapshot->mounts);
    }

    // --------------------------------------------------------- reserved segments

    /**
     * §7.3: "`/_/` and `/.well-known/` are reserved first segments,
     * unmountable."
     *
     * Refused by the resolver rather than resolved, because they are not
     * documentation — and because a project slugged `_` would otherwise shadow
     * `/_/search` for its own domain.
     */
    public function test_the_reserved_namespaces_are_not_documentation_paths(): void
    {
        $snapshot = $this->snapshot([$this->mount($this->project([$this->version()]))]);

        foreach (['/_/addons', '/_/search?q=x', '/.well-known/acme-challenge/t'] as $path) {
            $outcome = $this->resolver->resolveRoute($snapshot, $path);

            $this->assertSame(RejectionReason::ReservedSegment, $outcome->reason, "for [{$path}]");
        }
    }

    public function test_a_segment_merely_starting_with_an_underscore_is_not_reserved(): void
    {
        // `_static` is where Sphinx puts its assets. Treating it as reserved
        // would 404 every stylesheet in every Sphinx project.
        $snapshot = $this->snapshot([$this->mount($this->project([$this->version()]))]);

        $outcome = $this->resolver->resolveRoute($snapshot, '/en/latest/_static/css/site.css');

        $this->assertSame(RouteKind::Resolved, $outcome->kind);
        $this->assertSame('_static/css/site.css', $outcome->remainder);
    }

    // ----------------------------------------------------------- the mount step

    public function test_it_matches_the_longest_mount_prefix(): void
    {
        $root = $this->mount($this->project([$this->version()]), pathPrefix: '', id: 'root');
        $guides = $this->mount($this->project([$this->version()]), pathPrefix: 'guides', id: 'guides');
        $deep = $this->mount($this->project([$this->version()]), pathPrefix: 'guides/api', id: 'deep');

        $snapshot = $this->snapshot([$root, $guides, $deep]);

        $this->assertSame('deep', $snapshot->matchFor('/guides/api/en/latest/x.html')?->mount->id);
        $this->assertSame('guides', $snapshot->matchFor('/guides/en/latest/x.html')?->mount->id);
        $this->assertSame('root', $snapshot->matchFor('/en/latest/x.html')?->mount->id);

        // And the remainder comes back with it, so nothing strips the prefix a
        // second time. See SegmentPrefix for why that duplication had to go.
        // No null guard: the assertions above already established that this
        // host matches, and the analyser narrows accordingly — a redundant
        // assertNotNull here is itself a finding.
        $this->assertSame(
            'en/latest/x.html',
            $snapshot->matchFor('/guides/api/en/latest/x.html')->remainder,
        );
    }

    /**
     * 🛑 §7.3's "on a segment boundary". A mount at `api` must not match
     * `apiary`.
     *
     * Without the boundary rule, a portal mount for one project silently
     * swallows another project's URLs on a shared domain — and the symptom is
     * one team's documentation appearing under another team's path.
     */
    public function test_a_mount_prefix_only_matches_on_a_segment_boundary(): void
    {
        $root = $this->mount($this->project([$this->version()]), pathPrefix: '', id: 'root');
        $api = $this->mount($this->project([$this->version()]), pathPrefix: 'api', id: 'api');

        $snapshot = $this->snapshot([$root, $api]);

        $this->assertSame('api', $snapshot->matchFor('/api/en/latest/')?->mount->id);
        $this->assertSame('api', $snapshot->matchFor('/api')?->mount->id);
        $this->assertSame('root', $snapshot->matchFor('/apiary/en/latest/')?->mount->id, 'apiary must not match api');
    }

    public function test_a_host_whose_mounts_do_not_cover_the_path_is_a_404(): void
    {
        // Only a prefixed mount exists, and the path is not under it. There is
        // no root mount to fall back to, which is §8.9.3's point.
        $snapshot = $this->snapshot([$this->mount($this->project([$this->version()]), pathPrefix: 'guides')]);

        $outcome = $this->resolver->resolveRoute($snapshot, '/en/latest/guide.html');

        $this->assertSame(RejectionReason::MountNotFound, $outcome->reason);
    }

    /** §8.10.2's third mode: the caller builds the target from the canonical mount. */
    public function test_a_redirect_mode_mount_does_not_resolve_here(): void
    {
        $snapshot = $this->snapshot([
            $this->mount($this->project([$this->version()]), mode: 'redirect'),
        ]);

        $outcome = $this->resolver->resolveRoute($snapshot, '/en/latest/guide.html');

        $this->assertSame(RouteKind::Rejected, $outcome->kind);
        $this->assertSame('mount.redirect_mode', $outcome->matchedRule);
    }

    // --------------------------------------------------------- the project prefix

    public function test_it_consumes_the_project_url_prefix(): void
    {
        $snapshot = $this->snapshot([
            $this->mount($this->project([$this->version()], urlPrefix: 'docs')),
        ]);

        $outcome = $this->resolver->resolveRoute($snapshot, '/docs/en/latest/guide.html');

        $this->assertSame(RouteKind::Resolved, $outcome->kind);
        $this->assertSame('guide.html', $outcome->remainder);
    }

    public function test_a_path_missing_the_project_prefix_is_rejected(): void
    {
        $snapshot = $this->snapshot([
            $this->mount($this->project([$this->version()], urlPrefix: 'docs')),
        ]);

        $outcome = $this->resolver->resolveRoute($snapshot, '/en/latest/guide.html');

        $this->assertSame(RejectionReason::ProjectPrefixMismatch, $outcome->reason);
    }

    public function test_the_project_prefix_also_matches_only_on_a_boundary(): void
    {
        $snapshot = $this->snapshot([
            $this->mount($this->project([$this->version()], urlPrefix: 'docs')),
        ]);

        $outcome = $this->resolver->resolveRoute($snapshot, '/docsite/en/latest/guide.html');

        $this->assertSame(RejectionReason::ProjectPrefixMismatch, $outcome->reason);
    }

    // ---------------------------------------------------------- the version step

    public function test_lang_and_version_consumes_two_segments(): void
    {
        $snapshot = $this->snapshot([$this->mount($this->project([$this->version()]))]);

        $outcome = $this->resolver->resolveRoute($snapshot, '/en/latest/deep/guide.html');

        $this->assertSame(RouteKind::Resolved, $outcome->kind);
        $this->assertSame('en', $outcome->language);
        $this->assertSame('latest', $outcome->version?->slug);
        $this->assertSame('deep/guide.html', $outcome->remainder);
        $this->assertSame('version.matched', $outcome->matchedRule);
    }

    public function test_multi_version_consumes_one_segment(): void
    {
        $snapshot = $this->snapshot([
            $this->mount($this->project([$this->version()], scheme: 'multi_version')),
        ]);

        $outcome = $this->resolver->resolveRoute($snapshot, '/latest/guide.html');

        $this->assertSame(RouteKind::Resolved, $outcome->kind);
        $this->assertSame('guide.html', $outcome->remainder);
    }

    public function test_single_version_consumes_nothing(): void
    {
        $snapshot = $this->snapshot([
            $this->mount($this->project([$this->version()], scheme: 'single_version')),
        ]);

        $outcome = $this->resolver->resolveRoute($snapshot, '/guide.html');

        $this->assertSame(RouteKind::Resolved, $outcome->kind);
        $this->assertSame('guide.html', $outcome->remainder);
        $this->assertSame('version.single', $outcome->matchedRule);
    }

    /**
     * 🛑 `single_version` at the root must not redirect to itself.
     *
     * Its canonical root IS `/`, so a rule that always redirected an empty path
     * to the default version would redirect `/` to `/` forever. The resolver
     * compares the target against the request and falls through instead, which
     * is what makes §8.9.7 "add what is missing" rather than "always redirect".
     */
    public function test_single_version_at_the_root_resolves_rather_than_looping(): void
    {
        $snapshot = $this->snapshot([
            $this->mount($this->project([$this->version()], scheme: 'single_version')),
        ]);

        $outcome = $this->resolver->resolveRoute($snapshot, '/');

        $this->assertSame(RouteKind::Resolved, $outcome->kind);
        $this->assertSame('', $outcome->remainder);
        $this->assertSame('version.single', $outcome->matchedRule);
    }

    /**
     * And it DOES redirect when there is a prefix to add, which is the other
     * half of the same comparison.
     */
    public function test_single_version_with_a_prefix_redirects_from_the_bare_root(): void
    {
        $snapshot = $this->snapshot([
            $this->mount($this->project([$this->version()], urlPrefix: 'docs', scheme: 'single_version')),
        ]);

        $outcome = $this->resolver->resolveRoute($snapshot, '/');

        $this->assertSame(RouteKind::Redirect, $outcome->kind);
        $this->assertSame('/docs/', $outcome->redirectTo);
    }

    public function test_a_mount_root_without_a_default_version_is_rejected(): void
    {
        $snapshot = $this->snapshot([
            $this->mount($this->project([$this->version()], defaultVersionId: null), pathPrefix: 'portal'),
        ]);

        $outcome = $this->resolver->resolveRoute($snapshot, '/portal');

        $this->assertSame(RejectionReason::VersionNotFound, $outcome->reason);
        $this->assertSame('version.no_default', $outcome->matchedRule);
    }

    /**
     * The mount root WITH its project prefix present also redirects.
     *
     * `/portal/docs` has consumed both prefixes and has no version left, which
     * is §8.9.7's empty path reached by the other route — through the project
     * prefix rather than past it. Covered explicitly because the two paths into
     * that redirect are different branches, and only one of them was tested.
     */
    public function test_a_consumed_project_prefix_with_no_version_redirects(): void
    {
        $snapshot = $this->snapshot([
            $this->mount($this->project([$this->version()], urlPrefix: 'docs'), pathPrefix: 'portal'),
        ]);

        $outcome = $this->resolver->resolveRoute($snapshot, '/portal/docs');

        $this->assertSame(RouteKind::Redirect, $outcome->kind);
        $this->assertSame('/portal/docs/en/latest/', $outcome->redirectTo);
        $this->assertSame('version.default_redirect', $outcome->matchedRule);
    }

    /** `multi_version` with a slug no version carries. */
    public function test_multi_version_rejects_an_unknown_slug(): void
    {
        $snapshot = $this->snapshot([
            $this->mount($this->project([$this->version()], scheme: 'multi_version')),
        ]);

        $outcome = $this->resolver->resolveRoute($snapshot, '/v9/guide.html');

        $this->assertSame(RejectionReason::VersionNotFound, $outcome->reason);
        $this->assertSame('version.no_match', $outcome->matchedRule);
    }

    /** A mount override beats the project's own scheme (§10.5). */
    public function test_a_mount_override_wins_over_the_project_scheme(): void
    {
        $snapshot = $this->snapshot([
            $this->mount(
                $this->project([$this->version()], scheme: 'lang_and_version'),
                schemeOverride: 'multi_version',
            ),
        ]);

        $outcome = $this->resolver->resolveRoute($snapshot, '/latest/guide.html');

        $this->assertSame(RouteKind::Resolved, $outcome->kind);
        $this->assertSame('guide.html', $outcome->remainder);
    }

    /**
     * `/en` names a language and no version, and is refused rather than
     * guessed.
     *
     * Guessing a version would give one page two URLs, which is the surface
     * §8.9.6 spends its strictness collapsing.
     */
    public function test_a_language_without_a_version_is_rejected(): void
    {
        $snapshot = $this->snapshot([$this->mount($this->project([$this->version()]))]);

        $outcome = $this->resolver->resolveRoute($snapshot, '/en');

        $this->assertSame(RejectionReason::VersionNotFound, $outcome->reason);
        $this->assertSame('version.missing_segment', $outcome->matchedRule);
    }

    public function test_an_unknown_language_is_named_as_such(): void
    {
        $snapshot = $this->snapshot([$this->mount($this->project([$this->version()]))]);

        $outcome = $this->resolver->resolveRoute($snapshot, '/ja/latest/guide.html');

        // Distinguished from version.not_found, because §8.6.13 requires "404
        // plus a notification banner" for a missing page in another language
        // and the banner cannot say which went wrong otherwise.
        $this->assertSame(RejectionReason::LanguageNotFound, $outcome->reason);
    }

    public function test_an_unknown_version_in_a_known_language_is_named_as_such(): void
    {
        $snapshot = $this->snapshot([$this->mount($this->project([$this->version()]))]);

        $outcome = $this->resolver->resolveRoute($snapshot, '/en/v9/guide.html');

        $this->assertSame(RejectionReason::VersionNotFound, $outcome->reason);
        $this->assertSame('version.no_match', $outcome->matchedRule);
    }

    public function test_a_version_outside_the_mounts_scope_is_rejected(): void
    {
        $snapshot = $this->snapshot([
            $this->mount($this->project([$this->version(), $this->version('v1', id: 'version-2')]),
                versionScope: ['latest']),
        ]);

        $outcome = $this->resolver->resolveRoute($snapshot, '/en/v1/guide.html');

        $this->assertSame(RejectionReason::VersionNotFound, $outcome->reason);
        $this->assertSame('version.out_of_scope', $outcome->matchedRule);
    }

    /**
     * 🛑 §8.6.2's four axes, independently.
     *
     * Each of the three the resolver consults excludes a version on its own,
     * and `listed` excludes nothing — because §8.6.2 distinguishes `hidden`
     * from `private` precisely so that an unlisted version still serves by
     * direct URL.
     */
    public function test_each_serving_axis_excludes_a_version_independently(): void
    {
        $cases = [
            'inactive' => $this->version(active: false),
            'unpublished' => $this->version(published: false),
            'published with no manifest' => $this->version(manifestId: null),
        ];

        foreach ($cases as $label => $version) {
            $snapshot = $this->snapshot([$this->mount($this->project([$version]))]);

            $outcome = $this->resolver->resolveRoute($snapshot, '/en/latest/guide.html');

            $this->assertSame(RejectionReason::NothingPublished, $outcome->reason, $label);
        }

        // And the axis that must NOT exclude.
        $snapshot = $this->snapshot([$this->mount($this->project([$this->version(listed: false)]))]);

        $outcome = $this->resolver->resolveRoute($snapshot, '/en/latest/guide.html');

        $this->assertSame(RouteKind::Resolved, $outcome->kind, 'an unlisted version must still serve');
    }

    // ------------------------------------------------------------- the redirects

    /** §8.9.7: "An empty path MUST 302 to the default version". */
    public function test_an_empty_path_redirects_to_the_default_version(): void
    {
        $snapshot = $this->snapshot([$this->mount($this->project([$this->version()]))]);

        $outcome = $this->resolver->resolveRoute($snapshot, '/');

        $this->assertSame(RouteKind::Redirect, $outcome->kind);
        $this->assertSame('/en/latest/', $outcome->redirectTo);
        $this->assertSame('version.default_redirect', $outcome->matchedRule);
    }

    public function test_the_default_redirect_keeps_the_mount_and_project_prefixes(): void
    {
        $snapshot = $this->snapshot([
            $this->mount($this->project([$this->version()], urlPrefix: 'docs'), pathPrefix: 'portal'),
        ]);

        $outcome = $this->resolver->resolveRoute($snapshot, '/portal');

        $this->assertSame(RouteKind::Redirect, $outcome->kind);
        $this->assertSame('/portal/docs/en/latest/', $outcome->redirectTo);
    }

    /**
     * A version root without its slash is redirected, never served.
     *
     * Serving `index.html` at `/en/latest` would make every relative link in
     * it resolve against `/en/`, which is one level too high — so the document
     * would load and all of its assets would 404.
     */
    public function test_a_version_root_without_a_slash_redirects_to_the_slash_form(): void
    {
        $snapshot = $this->snapshot([$this->mount($this->project([$this->version()]))]);

        $outcome = $this->resolver->resolveRoute($snapshot, '/en/latest');

        $this->assertSame(RouteKind::Redirect, $outcome->kind);
        $this->assertSame('/en/latest/', $outcome->redirectTo);
        $this->assertSame('version.slash_redirect', $outcome->matchedRule);
    }

    public function test_a_version_root_with_a_slash_resolves_with_an_empty_remainder(): void
    {
        $snapshot = $this->snapshot([$this->mount($this->project([$this->version()]))]);

        $outcome = $this->resolver->resolveRoute($snapshot, '/en/latest/');

        $this->assertSame(RouteKind::Resolved, $outcome->kind);
        $this->assertSame('', $outcome->remainder);
    }

    /**
     * 🛑 §8.6.14: the default version is "an explicit stored pointer … not a
     * derived value".
     *
     * With the pointer unset there is nothing to redirect to, and the answer is
     * a 404 rather than a guess. A fallback to "the newest version" would make
     * the redirect target move on its own when a branch was created, which is
     * how an external link rots silently.
     */
    public function test_without_a_default_version_pointer_there_is_no_redirect(): void
    {
        $snapshot = $this->snapshot([
            $this->mount($this->project([$this->version()], defaultVersionId: null)),
        ]);

        $outcome = $this->resolver->resolveRoute($snapshot, '/');

        $this->assertSame(RejectionReason::VersionNotFound, $outcome->reason);
        $this->assertSame('version.no_default', $outcome->matchedRule);
    }

    public function test_a_default_pointer_at_an_unservable_version_is_not_followed(): void
    {
        $snapshot = $this->snapshot([
            $this->mount($this->project([$this->version(active: false)])),
        ]);

        $outcome = $this->resolver->resolveRoute($snapshot, '/');

        $this->assertSame(RejectionReason::VersionNotFound, $outcome->reason);
    }

    public function test_single_version_without_a_default_pointer_serves_nothing(): void
    {
        $snapshot = $this->snapshot([
            $this->mount($this->project([$this->version()], scheme: 'single_version', defaultVersionId: null)),
        ]);

        $outcome = $this->resolver->resolveRoute($snapshot, '/guide.html');

        $this->assertSame(RejectionReason::VersionNotFound, $outcome->reason);
    }

    // --------------------------------------- multi_version language ambiguity

    /**
     * 🛑 `multi_version` with translations is ambiguous by construction, because
     * §10.4's unique key is `(project_id, language, slug)`.
     *
     * The resolver prefers the default version's language and otherwise takes
     * the lowest code, so the answer is at least deterministic. An arbitrary
     * answer would make a misconfiguration into an intermittent bug.
     */
    public function test_multi_version_prefers_the_default_versions_language(): void
    {
        $english = $this->version('v1', 'en', id: 'version-en');
        $japanese = $this->version('v1', 'ja', id: 'version-ja');

        $snapshot = $this->snapshot([
            $this->mount($this->project([$japanese, $english], scheme: 'multi_version',
                defaultVersionId: 'version-ja')),
        ]);

        $outcome = $this->resolver->resolveRoute($snapshot, '/v1/guide.html');

        $this->assertSame('ja', $outcome->version?->language);
    }

    public function test_multi_version_falls_back_to_the_lowest_language_code(): void
    {
        $english = $this->version('v1', 'en', id: 'version-en');
        $japanese = $this->version('v1', 'ja', id: 'version-ja');

        // The default pointer names a version with a different slug, so it
        // cannot break the tie for `v1`.
        $snapshot = $this->snapshot([
            $this->mount($this->project(
                [$japanese, $english, $this->version('latest', 'de', id: 'version-de')],
                scheme: 'multi_version',
                defaultVersionId: 'version-de',
            )),
        ]);

        $outcome = $this->resolver->resolveRoute($snapshot, '/v1/guide.html');

        $this->assertSame('en', $outcome->version?->language);
    }

    // --------------------------------------------------------------- the file step

    /** @return array<string, array{sha256: string, bytes: int, content_type: string}> */
    private function files(string ...$paths): array
    {
        $files = [];

        foreach ($paths as $path) {
            $files[$path] = [
                'sha256' => str_repeat('a', 64),
                'bytes' => 12,
                'content_type' => 'text/html; charset=utf-8',
            ];
        }

        return $files;
    }

    /**
     * Both halves of the file step, as the controller sequences them.
     *
     * A helper rather than two calls in every test, because the sequencing is
     * the controller's job and these tests are about the answers. The one thing
     * it deliberately does NOT hide is that the manifest belongs to the matched
     * mount's build — see {@see MountMatch}.
     *
     * @param  list<array{mount_path: string, build_id: string|null}>  $mounts
     * @param  array<string, array{sha256: string, bytes: int, content_type: string}>  $manifestFiles
     */
    private function resolveFile(array $mounts, array $manifestFiles, string $remainder): FileOutcome
    {
        $match = $this->resolver->resolveMount($mounts, $remainder);

        if ($match === null) {
            return FileOutcome::rejected(RejectionReason::MountNotFound);
        }

        return $this->resolver->resolveFile($manifestFiles, $match);
    }

    public function test_it_resolves_a_file_from_the_manifest(): void
    {
        $outcome = $this->resolveFile(
            [['mount_path' => '', 'build_id' => 'build-1']],
            $this->files('html/index.html', 'html/guide.html'),
            'guide.html',
        );

        $this->assertSame(FileKind::File, $outcome->kind);
        $this->assertSame('html/guide.html', $outcome->key);
        $this->assertSame('"'.str_repeat('a', 64).'"', $outcome->etag());
    }

    /** §8.9.7: "a directory path MUST resolve `index.html`". */
    public function test_a_slash_terminated_path_resolves_index_html(): void
    {
        $outcome = $this->resolveFile(
            [['mount_path' => '', 'build_id' => 'build-1']],
            $this->files('html/index.html', 'html/deep/index.html'),
            'deep/',
        );

        $this->assertSame(FileKind::File, $outcome->kind);
        $this->assertSame('html/deep/index.html', $outcome->key);
    }

    public function test_an_empty_remainder_resolves_the_root_index(): void
    {
        $outcome = $this->resolveFile(
            [['mount_path' => '', 'build_id' => 'build-1']],
            $this->files('html/index.html'),
            '',
        );

        $this->assertSame('html/index.html', $outcome->key);
    }

    /** §8.9.7: "and 302 to the slash form". */
    public function test_a_directory_without_a_slash_is_a_redirect(): void
    {
        $outcome = $this->resolveFile(
            [['mount_path' => '', 'build_id' => 'build-1']],
            $this->files('html/index.html', 'html/deep/index.html'),
            'deep',
        );

        $this->assertSame(FileKind::Directory, $outcome->kind);
        $this->assertSame('deep/', $outcome->directoryRedirect);
        $this->assertNull($outcome->etag());
    }

    public function test_a_missing_file_is_a_404_from_the_manifest_alone(): void
    {
        $outcome = $this->resolveFile(
            [['mount_path' => '', 'build_id' => 'build-1']],
            $this->files('html/index.html'),
            'nothing/here.html',
        );

        $this->assertSame(FileKind::Rejected, $outcome->kind);
        $this->assertSame(RejectionReason::FileNotFound, $outcome->reason);
    }

    public function test_a_directory_form_with_no_index_is_a_404(): void
    {
        $outcome = $this->resolveFile(
            [['mount_path' => '', 'build_id' => 'build-1']],
            $this->files('html/deep/guide.html'),
            'deep/',
        );

        $this->assertSame(RejectionReason::FileNotFound, $outcome->reason);
    }

    public function test_it_matches_the_longest_component_mount(): void
    {
        $mounts = [
            ['mount_path' => '', 'build_id' => 'root'],
            ['mount_path' => 'api', 'build_id' => 'api'],
            ['mount_path' => 'api/v2', 'build_id' => 'api-v2'],
        ];

        // The component mount is consumed, so the manifest key is relative to
        // the component rather than to the version.
        $outcome = $this->resolveFile($mounts, $this->files('html/ref.html'), 'api/v2/ref.html');

        $this->assertSame('html/ref.html', $outcome->key);
    }

    public function test_a_component_mount_only_matches_on_a_segment_boundary(): void
    {
        $mounts = [
            ['mount_path' => '', 'build_id' => 'root'],
            ['mount_path' => 'api', 'build_id' => 'api'],
        ];

        // `apiary/x.html` must fall to the root mount, so the key keeps the
        // full path rather than having `api` stripped from it.
        $outcome = $this->resolveFile($mounts, $this->files('html/apiary/x.html'), 'apiary/x.html');

        $this->assertSame('html/apiary/x.html', $outcome->key);
    }

    /**
     * The longest component mount wins whatever order the manifest lists them.
     *
     * §10.4 fixes no order on `mounts_json`, so a manifest may well list the
     * longest first — and then the scan's "a shorter candidate cannot beat a
     * longer one" short-circuit is the branch that runs. Tested in both orders
     * because only one of them was, and a scan that depended on the order would
     * have passed.
     */
    public function test_the_longest_component_mount_wins_in_either_order(): void
    {
        $descending = [
            ['mount_path' => 'api/v2', 'build_id' => 'api-v2'],
            ['mount_path' => 'api', 'build_id' => 'api'],
            ['mount_path' => '', 'build_id' => 'root'],
        ];

        $match = $this->resolver->resolveMount($descending, 'api/v2/ref.html');

        $this->assertNotNull($match);
        $this->assertSame('api/v2', $match->mountPath);
        $this->assertSame('ref.html', $match->within);

        $ascending = array_reverse($descending);

        $this->assertSame('api/v2', $this->resolver->resolveMount($ascending, 'api/v2/ref.html')?->mountPath);
    }

    public function test_a_path_covered_by_no_component_mount_is_rejected(): void
    {
        $outcome = $this->resolveFile(
            [['mount_path' => 'api', 'build_id' => 'api']],
            $this->files('html/x.html'),
            'guides/x.html',
        );

        $this->assertSame(RejectionReason::MountNotFound, $outcome->reason);
    }

    // ----------------------------------------------------------- the cache key

    /**
     * 🛑 §8.9.10: `res:{routing_epoch}:{host}:{sha1(path)}`, with the epoch in
     * the key rather than purged.
     *
     * Maximum tolerated staleness for this epoch is 0 (§10.8), and putting it in
     * the key is what achieves 0: a bumped epoch addresses different keys, so
     * there is no window in which a stale entry can be read.
     */
    public function test_the_cache_key_carries_the_epoch(): void
    {
        $before = RouteOutcome::cacheKey(7, 'alpha.docs.example.com', '/en/latest/guide.html');
        $after = RouteOutcome::cacheKey(8, 'alpha.docs.example.com', '/en/latest/guide.html');

        $this->assertSame(
            'res:7:alpha.docs.example.com:'.hash('sha256', '/en/latest/guide.html'),
            $before,
        );

        $this->assertNotSame($before, $after, 'a bumped epoch must address a different key');
    }

    public function test_the_cache_key_separates_hosts_and_paths(): void
    {
        $this->assertNotSame(
            RouteOutcome::cacheKey(7, 'a.docs.example.com', '/x'),
            RouteOutcome::cacheKey(7, 'b.docs.example.com', '/x'),
        );

        $this->assertNotSame(
            RouteOutcome::cacheKey(7, 'a.docs.example.com', '/x'),
            RouteOutcome::cacheKey(7, 'a.docs.example.com', '/y'),
        );
    }

    // --------------------------------------------------------- the soft landing

    /** §8.8.6: the previous manifest stays resolvable for a bounded window. */
    public function test_the_soft_landing_window_expires(): void
    {
        $now = 1_800_000_000;

        $inside = new SnapshotVersion(
            id: 'v', slug: 'latest', language: 'en', active: true, listed: true, published: true,
            visibility: 'public', publishedManifestId: 'new', previousManifestId: 'old',
            softLandingExpiresAt: $now + 60,
        );

        $expired = new SnapshotVersion(
            id: 'v', slug: 'latest', language: 'en', active: true, listed: true, published: true,
            visibility: 'public', publishedManifestId: 'new', previousManifestId: 'old',
            softLandingExpiresAt: $now - 1,
        );

        $never = $this->version();

        $this->assertSame('old', $inside->softLandingManifestId($now));
        $this->assertNull($expired->softLandingManifestId($now));
        $this->assertNull($never->softLandingManifestId($now));
    }
}
