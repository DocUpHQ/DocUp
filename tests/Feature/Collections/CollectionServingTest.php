<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Collections;

use App\Artifacts\Publisher;
use App\Auth\AccessLevel;
use App\Auth\OrganisationContext;
use App\Collections\CollectionIndex;
use App\Collections\CollectionRefused;
use App\Collections\CollectionRejection;
use App\Collections\Collections;
use App\Collections\Flyout;
use App\Collections\MountExposure;
use App\Composition\Components;
use App\Composition\Mounts;
use App\Http\Controllers\Serving\DocumentController;
use App\Models\Build;
use App\Models\Collection;
use App\Models\DomainMount;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Serving\Resolver;
use App\Serving\RoutingSnapshotLoader;
use App\Serving\SnapshotMount;
use App\Serving\SnapshotVersion;
use App\Support\Uuid;
use App\Versions\TranslationGroup;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Storage;
use Illuminate\Testing\TestResponse;
use Symfony\Component\HttpFoundation\Response;
use Tests\Support\ArchiveWriter;
use Tests\TestCase;

/**
 * 🛑 Phase 16's four exit criteria, through the real route table.
 *
 * > "A parent project plus two collection members plus a `/ja/` translation
 * > serve under one domain with one flyout and correct `hreflang`. A
 * > collection alias colliding with a version slug, a language code or `/_/`
 * > is rejected. 🛑 A missing page under `/ja/` returns 404 **plus a
 * > notification banner**, never a silent fallback to `/en/`. A private
 * > member of a public collection is absent from the collection index,
 * > indistinguishably from not existing."
 *
 * Real requests rather than service calls, because the claim is about what a
 * reader receives: a collection is §8.2.5's *presentation* construct, so the
 * only honest proof that it works is that four URLs on one hostname answer.
 */
final class CollectionServingTest extends TestCase
{
    use DatabaseTransactions;

    private OrganisationContext $context;

    private Organisation $organisation;

    private Collections $collections;

    private Components $components;

    private Mounts $mounts;

    private Project $parent;

    private ProjectVersion $english;

    private ProjectVersion $japanese;

    private Collection $collection;

    private string $host;

    private string $fixtures;

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('artifacts');
        Cache::flush();

        $this->fixtures = sys_get_temp_dir().'/docup-p16-'.getmypid();

        if (! is_dir($this->fixtures)) {
            mkdir($this->fixtures, 0o755, true);
        }

        $this->context = app(OrganisationContext::class);
        $this->context->spanAllOrganisations();

        $this->organisation = Organisation::query()->create([
            'name' => 'Collected Co',
            'slug' => 'collected-'.bin2hex(random_bytes(4)),
        ]);

        $this->context->for($this->organisation->id);

        $this->collections = new Collections;
        $this->components = new Components;
        $this->mounts = new Mounts;

        $slug = 'platform-'.bin2hex(random_bytes(3));
        $this->host = $slug.'.'.$this->docsApex();

        $this->parent = $this->project($slug, AccessLevel::Public);
        $this->giveADefaultSubdomain($this->parent, $this->host);

        // 🛑 Two versions of ONE project sharing a slug across languages, as
        // §10.4's `UNIQUE (project_id, language, slug)` is designed to allow
        // and §8.6.12 requires: a translation is a version, not a sibling
        // project.
        $this->english = $this->version($this->parent, 'v1', 'en');
        $this->japanese = $this->version($this->parent, 'v1', 'ja');

        (new TranslationGroup)->group([$this->english, $this->japanese]);

        $this->parent->forceFill(['default_version_id' => $this->english->id])->save();

        $this->collection = $this->collections->create(
            organisationId: $this->organisation->id,
            slug: 'platform-docs',
            name: 'Platform documentation',
            parent: $this->parent,
        );
    }

    protected function tearDown(): void
    {
        $this->context->forget();

        if (is_dir($this->fixtures)) {
            foreach ((array) glob($this->fixtures.'/*') as $file) {
                if (is_string($file)) {
                    @unlink($file);
                }
            }

            @rmdir($this->fixtures);
        }

        parent::tearDown();
    }

    // ------------------------------------------------------- exit criterion 1

    /**
     * 🛑 "A parent project plus two collection members plus a `/ja/`
     * translation serve under one domain with one flyout and correct
     * `hreflang`."
     */
    public function test_a_parent_two_members_and_a_translation_serve_under_one_domain(): void
    {
        [$api, $sdk] = $this->twoMembers();

        $this->publishEverything();

        // One domain, four documents.
        $this->getExactly("http://{$this->host}/en/v1/")->assertOk();
        $this->getExactly("http://{$this->host}/ja/v1/")->assertOk();
        $this->getExactly("http://{$this->host}/projects/api/en/v1/")->assertOk();
        $this->getExactly("http://{$this->host}/projects/sdk/en/v1/")->assertOk();

        /*
         * 🛑 §8.21.2's URL shape, literally. A Read the Docs subproject lives
         * at `/projects/<alias>/` and the importer's promise is that those
         * URLs keep resolving — which is a claim about these two paths and
         * nothing else.
         */
        $this->assertSame(
            'projects/api',
            DomainMount::query()->where('project_id', $api->id)->value('path_prefix'),
        );
        $this->assertSame(
            'projects/sdk',
            DomainMount::query()->where('project_id', $sdk->id)->value('path_prefix'),
        );
    }

    /**
     * 🛑 "one flyout" — the same collection from every URL in it.
     *
     * This is the difference from Read the Docs that §8.2.5 is for. There, a
     * subproject is a project and its flyout is its own, so a reader three
     * clicks into it has no way back. Here the member's flyout names the
     * collection, the parent and the sibling.
     */
    public function test_every_url_in_the_collection_yields_the_same_flyout(): void
    {
        $this->twoMembers();
        $this->publishEverything();

        $flyout = app(Flyout::class);

        $fromParent = $flyout->for(...$this->resolveFor("http://{$this->host}/en/v1/"));
        $fromMember = $flyout->for(...$this->resolveFor("http://{$this->host}/projects/api/en/v1/"));
        $fromJapanese = $flyout->for(...$this->resolveFor("http://{$this->host}/ja/v1/"));

        foreach ([$fromParent, $fromMember, $fromJapanese] as $view) {
            $this->assertSame('platform-docs', $view->collectionSlug);
            $this->assertSame(
                ['', 'api', 'sdk'],
                array_column($view->members, 'alias'),
                'the parent and both members, in presentation order',
            );
        }

        // 🛑 And the language switcher is the translation group's, available
        // from the member as well — one project's languages, one switcher.
        $this->assertSame(['en', 'ja'], array_column($fromParent->languages, 'language'));

        /*
         * 🛑 Each language points at the **same documentation**, not at
         * whatever version of that language sorted first. A switcher that
         * sent a reader on `/en/v1/` to another version of `/ja/` would look
         * like a language switch and be a version change, and the reader has
         * no way to tell.
         */
        $this->assertSame(
            [
                'https://'.$this->host.'/en/v1/',
                'https://'.$this->host.'/ja/v1/',
            ],
            array_column($fromParent->languages, 'href'),
        );
    }

    /** 🛑 And the switcher follows the group rather than the version list. */
    public function test_the_language_switcher_prefers_the_default_version_s_group(): void
    {
        // An older Japanese version that is NOT part of `v1`'s group, and
        // which sorts ahead of it by insertion order.
        $stray = $this->version($this->parent, 'v0', 'ja');
        $this->publish($stray, ['html/index.html']);

        $this->publishEverything();

        [, $version] = $this->resolveFor("http://{$this->host}/en/v1/");
        $flyout = app(Flyout::class)->for(...$this->resolveFor("http://{$this->host}/en/v1/"));

        $this->assertSame('v1', $version->slug);
        $this->assertSame(
            'https://'.$this->host.'/ja/v1/',
            $flyout->languages[1]['href'],
            'the switcher took the stray v0 instead of the translation of v1',
        );
    }

    /**
     * 🛑 "correct `hreflang`" — §8.11.6, across versions, mounts and domains.
     */
    public function test_hreflang_annotates_the_translation_on_the_canonical_mount(): void
    {
        $this->publishEverything();

        $link = $this->getExactly("http://{$this->host}/ja/v1/")->headers->get('Link');

        $this->assertIsString($link);

        // Self-referential, both directions, absolute, on the canonical host.
        $this->assertStringContainsString(
            '<https://'.$this->host.'/en/v1/>; rel="alternate"; hreflang="en"',
            $link,
        );
        $this->assertStringContainsString(
            '<https://'.$this->host.'/ja/v1/>; rel="alternate"; hreflang="ja"',
            $link,
        );

        // `x-default` follows §8.6.14's stored default-version pointer.
        $this->assertStringContainsString(
            '<https://'.$this->host.'/en/v1/>; rel="alternate"; hreflang="x-default"',
            $link,
        );
    }

    /**
     * 🛑 And a page that exists in only one language is **not** annotated as
     * if it existed in the other.
     *
     * An `hreflang` pointing at a missing page is §8.6.13's silent fallback
     * in the one place the reader cannot see it: it reaches a crawler, which
     * indexes the annotation and sends somebody to a 404.
     */
    public function test_an_untranslated_page_is_not_annotated(): void
    {
        $this->publishEverything();

        $link = (string) $this->getExactly("http://{$this->host}/en/v1/only-english.html")
            ->headers->get('Link');

        // No alternates. The canonical link is still there — Phase 18 put
        // §8.11.9 in the same header — and asserting the header is empty
        // would now be asserting that the canonical link is missing.
        $this->assertStringNotContainsString('hreflang', $link, 'a page with no translation has no alternates');
        $this->assertStringContainsString('rel="canonical"', $link);
    }

    /**
     * 🛑 "across versions, mounts **and** domains" — the domain axis.
     *
     * A second verified domain serving the same project gets alternates
     * pointing at the **canonical** host, not at itself. §8.11.9 already
     * points `rel=canonical` there "for N domains serving identical
     * content", and self-anchored alternates on an alias would annotate
     * pages the very same response tells a crawler to ignore.
     */
    public function test_a_serving_alias_annotates_the_canonical_domain(): void
    {
        $this->publishEverything();

        $alias = 'mirror-'.bin2hex(random_bytes(3)).'.'.$this->docsApex();
        $this->giveASecondSubdomain($this->parent, $alias);

        Cache::flush();

        $response = $this->getExactly("http://{$alias}/ja/v1/");
        $response->assertOk();

        $link = (string) $response->headers->get('Link');

        $this->assertStringContainsString('<https://'.$this->host.'/en/v1/>', $link);
        $this->assertStringNotContainsString($alias, $link, 'an alias must not annotate itself');

        // And the alias is `noindex`, which is what makes the two consistent:
        // §8.10.2 derives `is_indexable` from `mode = canonical`.
        $this->assertSame('noindex', $response->headers->get('X-Robots-Tag'));
    }

    /** A project with one language pays nothing: no group, no header. */
    public function test_an_untranslated_project_emits_no_link_header(): void
    {
        $loner = $this->project('loner-'.bin2hex(random_bytes(3)), AccessLevel::Public);
        $host = $loner->slug.'.'.$this->docsApex();
        $this->giveADefaultSubdomain($loner, $host);

        $only = $this->version($loner, 'v1', 'en');
        $loner->forceFill(['default_version_id' => $only->id])->save();
        $this->publish($only, ['html/index.html']);

        Cache::flush();

        /*
         * 🛑 No `hreflang`, rather than no `Link` at all. Phase 18 added
         * §8.11.9's `rel=canonical` to the same header, so asserting the
         * header is absent would now be asserting that the canonical link is
         * missing — which is a different claim, and a wrong one.
         */
        $link = (string) $this->getExactly("http://{$host}/en/v1/")->headers->get('Link');

        $this->assertStringNotContainsString('hreflang', $link);
        $this->assertStringContainsString('rel="canonical"', $link);
    }

    // ------------------------------------------------------- exit criterion 2

    /**
     * 🛑 "A collection alias colliding with a version slug … is rejected."
     *
     * The language-code and `/_/` halves are `CollectionAliasTest`'s, because
     * they need no database. This one does: it is a collision with a slug
     * that exists.
     */
    public function test_an_alias_colliding_with_a_version_slug_is_refused(): void
    {
        $member = $this->project('api-'.bin2hex(random_bytes(3)), AccessLevel::Public);

        $this->expectException(CollectionRefused::class);

        try {
            $this->collections->attach($this->collection, $member, 'v1');
        } catch (CollectionRefused $refused) {
            $this->assertSame(CollectionRejection::AliasCollidesWithVersion, $refused->rejection);

            throw $refused;
        }
    }

    /**
     * 🛑 And the prefix's own first segment, which is a different collision.
     *
     * A parent with a version slugged `projects` serves `/projects/` as a
     * version root; the default convention would mount a member at
     * `projects/<alias>`, which the resolver matches longest-first and which
     * therefore swallows a subtree of that version with no error anywhere.
     */
    public function test_a_prefix_shadowing_a_version_is_refused(): void
    {
        $this->version($this->parent, 'projects', 'en');

        $member = $this->project('api-'.bin2hex(random_bytes(3)), AccessLevel::Public);

        try {
            $this->collections->attach($this->collection, $member, 'guides');
            $this->fail('a prefix shadowing a version slug was accepted');
        } catch (CollectionRefused $refused) {
            $this->assertSame(CollectionRejection::PrefixShadowsVersion, $refused->rejection);
        }
    }

    /**
     * 🛑 Switching §8.2.6's convention re-validates every alias, because the
     * switch is where a safe alias becomes an ambiguous one.
     *
     * `api` is unambiguous at `/projects/api/` and indistinguishable from a
     * language code at `/api/`. The switch is refused rather than performed
     * and left to fail at serve time, and the refusal leaves the collection
     * on the convention it had.
     */
    public function test_switching_to_the_alias_convention_revalidates_every_alias(): void
    {
        $this->twoMembers();

        try {
            $this->collections->changeConvention($this->collection, 'alias');
            $this->fail('a language-shaped alias survived the switch');
        } catch (CollectionRefused $refused) {
            $this->assertSame(CollectionRejection::AliasReserved, $refused->rejection);
        }

        $this->assertSame('projects', $this->collection->refresh()->prefix_convention);
    }

    /** And a collection whose aliases are all safe switches, moving its mounts. */
    public function test_a_safe_collection_switches_convention_and_moves_its_mounts(): void
    {
        $member = $this->project('guides-'.bin2hex(random_bytes(3)), AccessLevel::Public);
        $this->collections->attach($this->collection, $member, 'guides');

        $this->collections->changeConvention($this->collection, 'alias');

        $this->assertSame('alias', $this->collection->refresh()->prefix_convention);
        $this->assertSame(
            'guides',
            DomainMount::query()->where('project_id', $member->id)->value('path_prefix'),
            'the mount followed the convention',
        );
    }

    /** 🛑 §4.2: the parent cannot be its own member. */
    public function test_the_parent_cannot_be_a_member_of_its_own_collection(): void
    {
        try {
            $this->collections->attach($this->collection, $this->parent, 'self');
            $this->fail('the parent was attached to its own collection');
        } catch (CollectionRefused $refused) {
            $this->assertSame(CollectionRejection::ParentCannotBeMember, $refused->rejection);
        }
    }

    /** §10.1's two unique indexes, reported as refusals rather than 500s. */
    public function test_an_alias_cannot_be_used_twice_in_one_collection(): void
    {
        $first = $this->project('api-'.bin2hex(random_bytes(3)), AccessLevel::Public);
        $second = $this->project('sdk-'.bin2hex(random_bytes(3)), AccessLevel::Public);

        $this->collections->attach($this->collection, $first, 'guides');

        try {
            $this->collections->attach($this->collection, $second, 'guides');
            $this->fail('one alias was used twice');
        } catch (CollectionRefused $refused) {
            $this->assertSame(CollectionRejection::AliasTaken, $refused->rejection);
        }
    }

    /**
     * And the other unique index, which reports a different refusal.
     *
     * The two are told apart by the index name in MySQL's message, so this
     * asserts the discrimination rather than merely that *something* was
     * refused — a branch that always answered `alias_taken` would tell an
     * operator to rename an alias that is not the problem.
     */
    public function test_a_project_cannot_join_one_collection_twice(): void
    {
        $member = $this->project('api-'.bin2hex(random_bytes(3)), AccessLevel::Public);

        $this->collections->attach($this->collection, $member, 'guides');

        try {
            $this->collections->attach($this->collection, $member, 'handbook');
            $this->fail('one project joined one collection twice');
        } catch (CollectionRefused $refused) {
            $this->assertSame(CollectionRejection::AlreadyMember, $refused->rejection);
        }
    }

    // ------------------------------------------------------- exit criterion 3

    /**
     * 🛑 "A missing page under `/ja/` returns 404 **plus a notification
     * banner**, never a silent fallback to `/en/`."
     *
     * The 404 is the requirement. The banner is what stops it being a blank
     * page, and the assertion on the English URL *not* being served is the
     * one that would fail if somebody ever added a "helpful" fallback.
     */
    public function test_a_missing_japanese_page_is_a_404_with_a_banner_and_no_fallback(): void
    {
        $this->publishEverything();

        $response = $this->getExactly("http://{$this->host}/ja/v1/only-english.html");

        // 🛑 404, not 200 with the English bytes.
        $response->assertNotFound();

        $notice = $response->headers->get(DocumentController::NOTICE_HEADER);
        $this->assertIsString($notice);
        $this->assertStringContainsString('translation.page_untranslated', $notice);
        $this->assertStringContainsString('requested=ja', $notice);
        $this->assertStringContainsString('available=en', $notice);

        // The banner names where the page does live, so the reader is not
        // simply told "no".
        $body = $response->getContent();
        $this->assertIsString($body);
        $this->assertStringContainsString('https://'.$this->host.'/en/v1/only-english.html', $body);

        /*
         * 🛑 And the English content is not in the response. The two
         * assertions above would both pass for a 404 page that had helpfully
         * inlined the English page's text, which is the same disclosure in a
         * different wrapper.
         */
        $this->assertStringNotContainsString('ENGLISH-ONLY-MARKER', $body);
    }

    /**
     * 🛑 §8.6.13's other case: the project publishes nothing in that language.
     */
    public function test_a_language_the_project_does_not_publish_is_a_404_with_a_banner(): void
    {
        $this->publishEverything();

        $response = $this->getExactly("http://{$this->host}/de/v1/");

        $response->assertNotFound();

        $notice = $response->headers->get(DocumentController::NOTICE_HEADER);
        $this->assertIsString($notice);
        $this->assertStringContainsString('translation.language_absent', $notice);
        $this->assertStringContainsString('available=en,ja', $notice);
    }

    /**
     * 🛑 §8.6.13: "Locale negotiation MUST be URL-only; `Vary:
     * Accept-Language` on documentation would destroy edge cacheability."
     *
     * Asserted in both directions: the header is never emitted, and sending
     * `Accept-Language: en` does not make the Japanese URL serve English.
     */
    public function test_the_reader_s_accept_language_changes_nothing(): void
    {
        $this->publishEverything();

        $request = Request::create("http://{$this->host}/ja/v1/", 'GET');
        $request->headers->set('Accept-Language', 'en-GB,en;q=0.9');

        /** @var TestResponse<Response> $response */
        $response = TestResponse::fromBaseResponse($this->app->handle($request));

        $response->assertOk();

        /*
         * 🛑 `Accept-Language` specifically, not `Vary` at all. §8.9.13's
         * pre-compressed sidecars make `Vary: Accept-Encoding` correct and
         * required; it is the language dimension that "would destroy edge
         * cacheability" because every documentation URL would fan out into
         * one cache entry per reader locale.
         */
        $this->assertStringNotContainsStringIgnoringCase(
            'accept-language',
            (string) $response->headers->get('Vary'),
        );

        $japanese = $this->getExactly("http://{$this->host}/ja/v1/")->getContent();
        $this->assertSame($japanese, $response->getContent(), 'the header changed the bytes');
    }

    // ------------------------------------------------------- exit criterion 4

    /**
     * 🛑 "A private member of a public collection is absent from the
     * collection index, indistinguishably from not existing."
     */
    public function test_a_private_member_is_absent_from_the_index(): void
    {
        [$api] = $this->twoMembers();

        $private = $this->project('internal-'.bin2hex(random_bytes(3)), AccessLevel::Members);
        $this->collections->attach($this->collection, $private, 'internal');

        $members = app(CollectionIndex::class)->publicMembersOf($this->collection);
        $aliases = array_column($members, 'alias');

        $this->assertContains('api', $aliases);
        $this->assertNotContains('internal', $aliases);

        /*
         * 🛑 "Indistinguishably from not existing" — nothing in the index
         * carries its slug, its name or a placeholder for it. Asserted on the
         * serialised index rather than on the fields, because the leak that
         * matters is whatever a template renders.
         */
        $encoded = (string) json_encode($members);
        $this->assertStringNotContainsString($private->slug, $encoded);
        $this->assertStringNotContainsString('internal', $encoded);

        // And the public one is genuinely there, so the assertion above is
        // not passing because the index is empty.
        $this->assertSame($api->slug, $members[1]->projectSlug);
    }

    /**
     * 🛑 §8.12.8's intersection, on the read side: a public project reached
     * through a narrowing mount is not a public page.
     */
    public function test_a_public_project_behind_a_narrowing_mount_is_absent_too(): void
    {
        $member = $this->project('api-'.bin2hex(random_bytes(3)), AccessLevel::Public);

        $this->collections->attach($this->collection, $member, 'api', mountExposure: 'members');

        $this->assertSame(
            [''],
            array_column(app(CollectionIndex::class)->publicMembersOf($this->collection), 'alias'),
            'only the parent is public',
        );

        $this->assertSame(
            AccessLevel::Members,
            MountExposure::effective(AccessLevel::Public, 'members'),
        );
    }

    /**
     * 🛑 §8.12.8: "Composition MUST NEVER widen access, **without
     * exception**", refused at write time.
     */
    public function test_a_widening_mount_exposure_is_refused_at_write_time(): void
    {
        $private = $this->project('internal-'.bin2hex(random_bytes(3)), AccessLevel::Members);

        try {
            $this->collections->attach($this->collection, $private, 'internal', mountExposure: 'public');
            $this->fail('a widening mount exposure was accepted');
        } catch (CollectionRefused $refused) {
            $this->assertSame(CollectionRejection::ExposureWidens, $refused->rejection);
        }

        $this->assertSame(
            0,
            DomainMount::query()->where('project_id', $private->id)->count(),
            'the refusal left no mount behind',
        );
    }

    // ---------------------------------------------------------------- helpers

    /**
     * Two public members, attached at `/projects/api/` and `/projects/sdk/`.
     *
     * @return array{0: Project, 1: Project}
     */
    private function twoMembers(): array
    {
        $api = $this->project('api-'.bin2hex(random_bytes(3)), AccessLevel::Public);
        $sdk = $this->project('sdk-'.bin2hex(random_bytes(3)), AccessLevel::Public);

        $this->collections->attach($this->collection, $api, 'api', position: 0);
        $this->collections->attach($this->collection, $sdk, 'sdk', position: 1);

        foreach ([$api, $sdk] as $member) {
            $version = $this->version($member, 'v1', 'en');
            $member->forceFill(['default_version_id' => $version->id])->save();
            $this->publish($version, ['html/index.html']);
        }

        return [$api, $sdk];
    }

    /**
     * The parent's two languages, published.
     *
     * English carries a page Japanese does not, which is the whole of
     * §8.6.13's case.
     */
    private function publishEverything(): void
    {
        $this->publish($this->english, [
            'html/index.html',
            'html/shared.html',
            'html/only-english.html',
        ], marker: 'ENGLISH-ONLY-MARKER');

        $this->publish($this->japanese, ['html/index.html', 'html/shared.html']);

        Cache::flush();
    }

    private function project(string $slug, AccessLevel $visibility): Project
    {
        return Project::query()->create([
            'slug' => $slug,
            'name' => ucfirst($slug),
            'visibility' => $visibility->value,
        ]);
    }

    private function version(Project $project, string $slug, string $language): ProjectVersion
    {
        $version = new ProjectVersion;

        $version->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'project_id' => $project->id,
            'slug' => $slug,
            'kind' => 'channel',
            'language' => $language,
            'active' => true,
            'listed' => true,
            'published' => false,
            'visibility' => $project->visibility->value,
        ])->save();

        return $version;
    }

    /**
     * A real ingested build on this version, mounted at its root.
     *
     * @param  list<string>  $paths
     */
    private function publish(ProjectVersion $version, array $paths, string $marker = 'x'): Build
    {
        $component = $this->components->register(
            organisationId: $this->organisation->id,
            key: 'c-'.bin2hex(random_bytes(5)),
            name: 'Component',
            minAccess: AccessLevel::Public,
        );

        $this->mounts->attach($version, $component, '', isPrimary: true);

        $writer = new ArchiveWriter;

        foreach ($paths as $path) {
            $writer->add($path, "<!doctype html><html><head></head><body>{$marker}</body></html>\n");
        }

        $build = app(Publisher::class)->publishUpload(
            $version,
            $writer->toTarGz($this->fixtures.'/t-'.bin2hex(random_bytes(4)).'.tar.gz'),
        )->build;

        $this->assertInstanceOf(Build::class, $build);

        return $build;
    }

    /**
     * The mount and version a URL resolves to, for a flyout assertion.
     *
     * Through the real loader and the real resolver: a flyout built from
     * hand-made snapshot objects would prove the assembler works and nothing
     * about whether a member's URL reaches it.
     *
     * @return array{0: SnapshotMount, 1: SnapshotVersion}
     */
    private function resolveFor(string $url): array
    {
        $request = Request::create($url, 'GET');

        $snapshot = app(RoutingSnapshotLoader::class)->load((string) $request->getHost());
        $route = app(Resolver::class)->resolveRoute($snapshot, (string) $request->getPathInfo());

        $this->assertNotNull($route->mount, $url.' did not resolve to a mount');
        $this->assertNotNull($route->version, $url.' did not resolve to a version');

        return [$route->mount, $route->version];
    }

    private function giveADefaultSubdomain(Project $project, string $host): string
    {
        $domainId = Uuid::v7();

        DB::table('domains')->insert([
            'id' => $domainId,
            'organisation_id' => $this->organisation->id,
            'host' => $host,
            'kind' => 'default_subdomain',
            'state' => 'active',
            'verified_at' => now(),
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        DB::table('domain_mounts')->insert([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'domain_id' => $domainId,
            'project_id' => $project->id,
            'path_prefix' => '',
            'mode' => 'canonical',
            'mount_exposure' => 'inherit',
            'position' => 0,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        return $domainId;
    }

    /**
     * A second verified host for the same project, serving rather than
     * canonical (§8.10.2's default for every domain after the first).
     */
    private function giveASecondSubdomain(Project $project, string $host): void
    {
        $domainId = Uuid::v7();

        DB::table('domains')->insert([
            'id' => $domainId,
            'organisation_id' => $this->organisation->id,
            'host' => $host,
            'kind' => 'default_subdomain',
            'state' => 'active',
            'verified_at' => now(),
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        DB::table('domain_mounts')->insert([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'domain_id' => $domainId,
            'project_id' => $project->id,
            'path_prefix' => '',
            'mode' => 'serve',
            'mount_exposure' => 'inherit',
            'position' => 1,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }

    private function docsApex(): string
    {
        $apex = config('docup.origins.docs');

        return is_string($apex) && $apex !== '' ? $apex : 'docup-docs.test';
    }

    /** @return TestResponse<Response> */
    private function getExactly(string $url): TestResponse
    {
        /** @var TestResponse<Response> */
        return TestResponse::fromBaseResponse($this->app->handle(Request::create($url, 'GET')));
    }
}
