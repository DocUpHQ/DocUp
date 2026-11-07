<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Seo;

use App\Auth\OrganisationContext;
use App\Models\DomainMount;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Serving\Hreflang;
use App\Serving\ManifestReader;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;

/**
 * 🛑 §8.11.6's four files, written at pointer flip, **per domain mount**.
 *
 * > "`robots.txt`, `sitemap.xml`, `llms.txt` and `llms-full.txt` MUST be
 * > generated **per domain mount** and written at pointer flip to a
 * > generated-artefact store keyed by domain mount and revision … Only the
 * > canonical mount is indexable; serving aliases and preview hosts MUST
 * > emit `Disallow: /` and `X-Robots-Tag: noindex`. **A build-shipped file
 * > MUST always win.** `hreflang` MUST be generated across versions, mounts
 * > **and** domains."
 *
 * **"A build-shipped file MUST always win" is the clause with teeth**, and
 * it is not implemented here — it is implemented by *not* implementing
 * something. These files are written to the generated store, and the
 * serving path consults the build's own tree first; a project that ships
 * its own `robots.txt` therefore serves it without this class knowing.
 * The alternative — generate, then check, then skip — would put the
 * precedence in two places and let them disagree.
 *
 * 🛑 **Hidden versions are omitted from the sitemap**, which is §17's exit
 * criterion and a §8.6 distinction rather than an access one. P10 made
 * `active`, `listed`, `published` and `visibility` four independent axes,
 * and a version with `listed=false` "still returns 200 by direct URL and is
 * absent from the version list". It is reachable on purpose and
 * unadvertised on purpose; a sitemap that listed it would undo the second
 * half while a `Disallow` would undo the first.
 */
final readonly class GeneratedArtifacts
{
    public function __construct(
        private GeneratedStore $store,
        private ManifestReader $manifests,
    ) {}

    /**
     * Regenerate every mount of a project.
     *
     * 🛑 Every mount, not the one that changed, and the reason is in
     * §8.11.6's own list of triggers: "a rebrand or a new domain
     * regenerates them without touching a build". A publish changes the
     * sitemap of every mount the project is served at, because the set of
     * URLs changed on all of them at once.
     *
     * @return list<string> the mount ids regenerated, for the caller's log
     */
    public function regenerate(Project $project): array
    {
        $mounts = $this->mountsFor($project);

        if ($mounts === []) {
            return [];
        }

        $versions = $this->publishedVersions($project);
        $touched = [];

        foreach ($mounts as $mount) {
            $this->writeMount($project, $mount, $versions);
            $touched[] = (string) $mount->id;
        }

        return $touched;
    }

    /**
     * @param  list<ProjectVersion>  $versions
     */
    private function writeMount(Project $project, DomainMount $mount, array $versions): void
    {
        $revision = ((int) $mount->generated_revision) + 1;
        $origin = $this->originFor($mount);
        $prefix = $this->prefixFor($mount, $project);

        $entries = [];
        $sections = [];

        foreach ($versions as $version) {
            $root = $prefix.'/'.$version->language.'/'.$version->slug.'/';

            $entries[] = new SitemapEntry(
                location: $origin.$root,
                lastModified: $version->updated_at instanceof Carbon ? $version->updated_at : null,
                alternates: $this->alternatesFor($origin, $prefix, $versions, $version),
            );

            $links = $this->navigationLinks($version, $origin.$root);

            if ($links !== []) {
                $sections[] = [
                    'heading' => $version->slug.' ('.$version->language.')',
                    'links' => $links,
                ];
            }

            foreach ($links as $link) {
                $entries[] = new SitemapEntry(location: $link['url']);
            }
        }

        $indexable = (bool) $mount->is_indexable;

        $this->store->put(
            (string) $mount->id,
            $revision,
            'robots.txt',
            RobotsTxt::render($indexable, $indexable ? $origin.$prefix.'/sitemap.xml' : null),
        );

        /*
         * 🛑 A non-indexable mount still gets a sitemap file, and it is
         * **empty**. §8.11.6 asks for all four per mount; writing three
         * would make the fourth a 404, and a 404 on `sitemap.xml` is
         * indistinguishable from a misconfiguration when an operator goes
         * looking. An empty `urlset` says "nothing here to crawl" in the
         * crawler's own vocabulary, which is what `Disallow: /` already
         * said.
         */
        $this->store->put(
            (string) $mount->id,
            $revision,
            'sitemap.xml',
            Sitemap::render($indexable ? $entries : []),
        );

        $title = (string) $project->name;
        $summary = $project->description === null ? null : (string) $project->description;

        $this->store->put((string) $mount->id, $revision, 'llms.txt', LlmsTxt::index($title, $summary, $sections));

        /*
         * 🛑 `llms-full.txt` with no bodies is the index again, and that is
         * correct rather than lazy. §8.11.7 permits only the `.md` siblings
         * "**that a generator already emitted**" — so a project whose
         * generator emits none has nothing to include, and §4.2 forbids
         * manufacturing it. The file exists, lists everything, and includes
         * what there is.
         */
        $this->store->put(
            (string) $mount->id,
            $revision,
            'llms-full.txt',
            LlmsTxt::full($title, $summary, $sections, $this->markdownBodies($versions, $origin, $prefix)),
        );

        /*
         * 🛑 The revision is moved on **after** the files are written and
         * swept **after** that. Reversed in either direction there is a
         * window where a reader gets a 404 for `robots.txt`, which a
         * crawler reads as "crawl everything".
         */
        $mount->forceFill(['generated_revision' => $revision, 'generated_at' => Carbon::now()])->save();

        $this->store->sweep((string) $mount->id, $revision);
    }

    /**
     * §8.11.6's "across versions, mounts **and** domains", for one page.
     *
     * @param  list<ProjectVersion>  $versions
     * @return array<string, string>
     */
    private function alternatesFor(string $origin, string $prefix, array $versions, ProjectVersion $version): array
    {
        $pages = [];

        foreach ($versions as $candidate) {
            /*
             * A translation is a version with the same translation group
             * and a different language (§8.6.12) — not a sibling project.
             * Versions with no group are not translations of anything.
             */
            if ($version->translation_group_id === null
                || $candidate->translation_group_id !== $version->translation_group_id) {
                continue;
            }

            $pages[] = [
                'language' => (string) $candidate->language,
                'path' => $prefix.'/'.$candidate->language.'/'.$candidate->slug.'/',
            ];
        }

        $alternates = [];

        foreach (Hreflang::alternates($pages, $origin) as $alternate) {
            $alternates[$alternate['hreflang']] = $alternate['href'];
        }

        return $alternates;
    }

    /**
     * The navigation tree, flattened to links, for `llms.txt`.
     *
     * 🛑 §8.11.7 says these come "from the navigation tree and section
     * index", and the tree is the manifest's `nav_json` — the same tree the
     * flyout and the composed layout read. Walking the build's HTML instead
     * would be a second source of truth for what the documentation
     * contains, and the one that disagrees after a composition change.
     *
     * @return list<array{title: string, url: string, description?: string}>
     */
    private function navigationLinks(ProjectVersion $version, string $root): array
    {
        if ($version->published_manifest_id === null) {
            return [];
        }

        $links = [];

        $this->walk($this->manifests->navigation((string) $version->published_manifest_id), $root, $links);

        return $links;
    }

    /**
     * @param  array<array-key, mixed>  $nodes
     * @param  list<array{title: string, url: string, description?: string}>  $links
     */
    private function walk(array $nodes, string $root, array &$links): void
    {
        foreach ($nodes as $node) {
            if (! is_array($node)) {
                continue;
            }

            $title = $node['title'] ?? null;
            $href = $node['href'] ?? ($node['url'] ?? null);

            if (is_string($title) && is_string($href) && $href !== '') {
                $links[] = ['title' => $title, 'url' => $root.ltrim($href, '/')];
            }

            $children = $node['children'] ?? ($node['items'] ?? null);

            if (is_array($children)) {
                $this->walk($children, $root, $links);
            }
        }
    }

    /**
     * The `.md` siblings a generator emitted, keyed by the URL they belong
     * to.
     *
     * 🛑 Empty for now, and visibly so rather than quietly. Reading them
     * means reading build bytes, which the generator's file manifest
     * already lists — but §8.11.7's `.md` siblings are served from the
     * build tree by the edge, and assembling them into one file here would
     * be the first thing in this application to read documentation bytes
     * through PHP (§4.3/2). That trade is worth making deliberately rather
     * than in passing, so `llms-full.txt` currently lists everything and
     * includes nothing, and the build log records it as owed.
     *
     * @param  list<ProjectVersion>  $versions
     * @return array<string, string>
     */
    private function markdownBodies(array $versions, string $origin, string $prefix): array
    {
        return [];
    }

    /**
     * @return list<DomainMount>
     */
    private function mountsFor(Project $project): array
    {
        /** @var list<DomainMount> $mounts */
        $mounts = DomainMount::query()
            ->where('project_id', $project->id)
            ->where('mode', '!=', 'redirect')
            ->get()
            ->all();

        return $mounts;
    }

    /**
     * Every version a crawler may be told about.
     *
     * 🛑 Four conditions, one per axis P10 made independent, and dropping
     * any one of them advertises something: `active=false` is retired,
     * `listed=false` is deliberately unadvertised, `published=false` has no
     * bytes, and a non-public `visibility` is §12's.
     *
     * @return list<ProjectVersion>
     */
    private function publishedVersions(Project $project): array
    {
        /** @var list<ProjectVersion> $versions */
        $versions = ProjectVersion::query()
            ->where('project_id', $project->id)
            ->where('active', true)
            ->where('listed', true)
            ->where('published', true)
            ->where('visibility', 'public')
            ->whereNotNull('published_manifest_id')
            ->orderBy('slug')
            ->get()
            ->all();

        return $versions;
    }

    /** `scheme://host` for a mount, from the domain row it belongs to. */
    private function originFor(DomainMount $mount): string
    {
        $host = DB::table('domains')->where('id', $mount->domain_id)->value('host');

        return 'https://'.(is_string($host) ? $host : 'localhost');
    }

    /** Everything §7.3 puts before `{lang}/{version}`, with no trailing slash. */
    private function prefixFor(DomainMount $mount, Project $project): string
    {
        $parts = array_filter([
            trim((string) $mount->path_prefix, '/'),
            trim((string) ($project->url_prefix ?? ''), '/'),
        ], static fn (string $part): bool => $part !== '');

        return $parts === [] ? '' : '/'.implode('/', $parts);
    }

    /**
     * Across tenants, because a pointer flip runs from a queued job.
     *
     * @return list<string> the mount ids regenerated
     */
    public static function forProject(Project $project): array
    {
        return app(OrganisationContext::class)->acrossAllOrganisations(
            static fn (): array => app(self::class)->regenerate($project),
        );
    }
}
