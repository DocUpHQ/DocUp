<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Config;

/**
 * §8.4.7's `html_context`, so that "Edit this page" works.
 *
 * > "The system MUST inject `html_context` equivalents so 'Edit this page'
 * > links work, **per component mount** — which in a composed project is
 * > harder than Read the Docs' version and more valuable."
 *
 * Harder, because on Read the Docs a page belongs to one repository and here
 * `/guide/intro.html` and `/api/client.html` can come from two different ones
 * mounted side by side. More valuable for the same reason: the link is right
 * on every page of a composed site, which is where a single repository-wide
 * edit URL is wrong on most of them.
 *
 * 🛑 **Every value here is component- or ref-scoped (§8.4.6).** The provider,
 * the repository, the ref and the path to the generator's configuration are
 * all facts about the source; none of them is a fact about a consuming
 * project, so injecting them costs no cross-project reuse and they are
 * already in the content key through `commit_sha` and the config digest.
 * `current_version`, `versions` and `slug` — which Read the Docs also puts in
 * `html_context` — are project-scoped and are **not** here. Those are emitted
 * at serve time (§8.11.9) by the side that knows which project is asking.
 *
 * 🛑 **Userinfo is stripped from the clone URL before anything is derived
 * from it.** A clone URL may legitimately carry `https://x-token:…@host/…`
 * from an operator's configuration, and an edit link is rendered into every
 * page of the published site.
 */
final readonly class HtmlContext
{
    private function __construct(
        public string $provider,
        public string $owner,
        public string $repository,
        public string $ref,
        public string $configurationPath,
        public string $host,
    ) {}

    /**
     * @param  string  $cloneUrl  as stored on the repository row
     * @param  string  $ref  the branch or tag this build is of
     * @param  string  $configurationPath  where the generator's config lives,
     *                                     relative to the repository root,
     *                                     with a trailing slash — Sphinx's
     *                                     `conf_py_path` is a directory
     */
    public static function fromCloneUrl(string $cloneUrl, string $ref, string $configurationPath = '/'): self
    {
        $host = '';
        $path = '';

        // `scp`-style SSH remotes (`git@github.com:owner/repo.git`) are not
        // URLs and `parse_url` reads them as a path with no host, so they are
        // normalised first rather than special-cased afterwards.
        if (preg_match('#^(?:[^@/]+@)?([A-Za-z0-9.-]+):(?!//)(.+)$#', $cloneUrl, $matches) === 1) {
            $host = $matches[1];
            $path = $matches[2];
        } else {
            $parts = parse_url($cloneUrl);

            if (is_array($parts)) {
                $host = is_string($parts['host'] ?? null) ? $parts['host'] : '';
                $path = is_string($parts['path'] ?? null) ? $parts['path'] : '';
            }
        }

        $path = trim($path, '/');
        $path = preg_replace('/\.git$/', '', $path) ?? $path;

        $segments = $path === '' ? [] : explode('/', $path);
        $repository = $segments === [] ? '' : (string) array_pop($segments);
        $owner = implode('/', $segments);

        return new self(
            provider: self::providerFor($host),
            owner: $owner,
            repository: $repository,
            ref: $ref,
            configurationPath: self::normalisePath($configurationPath),
            host: $host,
        );
    }

    /**
     * The context as Sphinx's `html_context`, which `sphinx-rtd-theme` and
     * the Furo, Book and Alabaster themes all read.
     *
     * @return array<string, string|bool>
     */
    public function forSphinx(): array
    {
        $flag = 'display_'.$this->provider;

        return [
            $flag => true,
            $this->provider.'_user' => $this->owner,
            $this->provider.'_repo' => $this->repository,
            $this->provider.'_version' => $this->ref,
            'conf_py_path' => $this->configurationPath,
        ];
    }

    /**
     * The same values as `sphinx-build -A` arguments.
     *
     * 🛑 `-A` rather than appending to the repository's `conf.py`. Read the
     * Docs rewrites the file; doing that would mean editing repository code
     * before running it, in a stage whose whole purpose is that we do not.
     * `-A` is Sphinx's own documented mechanism for exactly this and leaves
     * the checkout untouched, which also keeps the source digest honest.
     *
     * @return list<string>
     */
    public function sphinxArguments(): array
    {
        $arguments = [];

        foreach ($this->forSphinx() as $key => $value) {
            $arguments[] = '-A';
            $arguments[] = $key.'='.($value === true ? 'True' : (string) $value);
        }

        return $arguments;
    }

    /**
     * The generic form, for generators that are not Sphinx.
     *
     * Exposed to the build as one JSON environment variable rather than a
     * dozen names, because every generator spells its edit-link
     * configuration differently and a preset can pick what it needs out of
     * one documented object.
     *
     * @return array<string, string>
     */
    public function forEnvironment(): array
    {
        return [
            'DOCUP_VCS_PROVIDER' => $this->provider,
            'DOCUP_VCS_HOST' => $this->host,
            'DOCUP_VCS_OWNER' => $this->owner,
            'DOCUP_VCS_REPOSITORY' => $this->repository,
            'DOCUP_VCS_REF' => $this->ref,
            'DOCUP_CONF_PATH' => $this->configurationPath,
            'DOCUP_EDIT_URL_TEMPLATE' => $this->editUrlTemplate(),
        ];
    }

    /**
     * Where a page's source is edited, with `{path}` left for the renderer.
     *
     * Left as a template rather than resolved per page because the per-page
     * half belongs to whatever knows the page: the generator at build time,
     * or §8.15's addons at read time for a composed site, where the same URL
     * grammar has to serve pages from several repositories.
     */
    public function editUrlTemplate(): string
    {
        if ($this->host === '' || $this->owner === '' || $this->repository === '') {
            return '';
        }

        $base = 'https://'.$this->host.'/'.$this->owner.'/'.$this->repository;

        return match ($this->provider) {
            'bitbucket' => $base.'/src/'.$this->ref.'/{path}?mode=edit',
            default => $base.'/edit/'.$this->ref.'/{path}',
        };
    }

    /**
     * Which vocabulary the theme expects.
     *
     * Self-hosted Forgejo, Gitea and GitLab are all reached by host name, so
     * an unknown host falls back to `github` — not because it is GitHub, but
     * because `display_github` is the flag every Sphinx theme actually
     * implements, and the URL shape `/edit/<ref>/<path>` is the one Forgejo,
     * Gitea and GitLab share with it. A theme that honoured a `display_gitea`
     * nobody emits would render no link at all, which is strictly worse than
     * a correct link under a historical name.
     */
    private static function providerFor(string $host): string
    {
        $host = strtolower($host);

        if (str_contains($host, 'bitbucket')) {
            return 'bitbucket';
        }

        if (str_contains($host, 'gitlab')) {
            return 'gitlab';
        }

        return 'github';
    }

    /** Sphinx wants `/docs/` — leading and trailing slash, or just `/`. */
    private static function normalisePath(string $path): string
    {
        $trimmed = trim($path, '/');

        return $trimmed === '' ? '/' : '/'.$trimmed.'/';
    }
}
