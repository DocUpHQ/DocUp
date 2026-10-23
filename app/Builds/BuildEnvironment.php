<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds;

/**
 * The environment a build container receives: `DOCUP_*` and §8.4.13's fourteen
 * `READTHEDOCS_*` aliases, classified by §8.4.6's three scopes.
 *
 * > "Thousands of real `conf.py` files branch on these variables and
 * > `sphinx-rtd-theme` consumes them. The aliases are a documented
 * > compatibility shim with a stated deprecation policy, not an accident."
 *
 * 🛑 **The project scope is withheld, not emptied** (§8.4.6, §8.7.10). Phase
 * 06 implements the default `agnostic` mode only; §8.4.12's `project_bound`
 * opt-in arrives with the rest of the configuration contract in Phase 09.
 * Until then a build is reusable by every project that mounts the component,
 * which is the property §8.7.9's content key depends on — and injecting one
 * project's `READTHEDOCS_CANONICAL_URL` into an artifact served under another
 * project's domain is the concrete harm, not a theoretical one.
 *
 * 🛑 **`$DOCUP_OUTPUT` and `$READTHEDOCS_OUTPUT` are the same directory**
 * (§8.4.5). Not two directories that are merged afterwards — the same one, so
 * a generator writing to either is writing to the place `collect` will read.
 */
final readonly class BuildEnvironment
{
    /** Where the repository is checked out inside the build container. */
    public const REPOSITORY_PATH = '/workspace/source';

    /** §8.4.5's single output directory. */
    public const OUTPUT_PATH = '/workspace/output';

    /** Where a Python toolchain's virtualenv lives, for the alias that names it. */
    public const VIRTUALENV_PATH = '/workspace/venv';

    /**
     * @param  string  $componentKey  the component's `key`, never a project slug
     * @param  string  $versionLabel  derived from the ref, never from a project
     * @param  string  $versionType  `branch`, `tag` or `external`
     */
    public function __construct(
        public string $productionDomain,
        public string $componentKey,
        public string $cloneUrl,
        public string $refIdentifier,
        public string $commitSha,
        public string $versionLabel,
        public string $versionType = 'branch',
    ) {}

    /**
     * The variables, by scope.
     *
     * Returned as a scope map rather than a flat array so that
     * {@see forContainer()} can drop a whole scope and an architecture test
     * can assert which scope a name belongs to. A flat array would make
     * "which of these is project-scoped?" a question about string prefixes.
     *
     * @return array<string, array<string, string>>
     */
    public function byScope(): array
    {
        return [
            EnvironmentScope::Installation->value => [
                // The marker thousands of conf.py files branch on. The
                // literal string "True", because that is the exact value Read
                // the Docs sets and the exact value those files compare
                // against; anything else silently takes the other branch.
                'READTHEDOCS' => 'True',
                'READTHEDOCS_OUTPUT' => self::OUTPUT_PATH,
                'READTHEDOCS_VIRTUALENV_PATH' => self::VIRTUALENV_PATH,
                'READTHEDOCS_REPOSITORY_PATH' => self::REPOSITORY_PATH,
                'READTHEDOCS_PRODUCTION_DOMAIN' => $this->productionDomain,

                'DOCUP' => 'True',
                'DOCUP_OUTPUT' => self::OUTPUT_PATH,
                'DOCUP_VIRTUALENV_PATH' => self::VIRTUALENV_PATH,
                'DOCUP_REPOSITORY_PATH' => self::REPOSITORY_PATH,
                'DOCUP_PRODUCTION_DOMAIN' => $this->productionDomain,
            ],

            EnvironmentScope::Component->value => [
                'READTHEDOCS_GIT_CLONE_URL' => $this->cloneUrl,
                'READTHEDOCS_GIT_IDENTIFIER' => $this->refIdentifier,
                'READTHEDOCS_GIT_COMMIT_HASH' => $this->commitSha,

                /*
                 * 🛑 Component-scoped, not project-scoped, and the distinction
                 * is not obvious. `READTHEDOCS_VERSION_NAME` is the **ref's**
                 * label — `main`, `v2.1` — which the component owns.
                 * `READTHEDOCS_VERSION` is the **consuming project's** version
                 * slug, which it does not. Read the Docs can treat them as the
                 * same thing because there one build belongs to one project.
                 */
                'READTHEDOCS_VERSION_NAME' => $this->versionLabel,
                'READTHEDOCS_VERSION_TYPE' => $this->versionType,

                'DOCUP_COMPONENT' => $this->componentKey,
                'DOCUP_GIT_CLONE_URL' => $this->cloneUrl,
                'DOCUP_GIT_IDENTIFIER' => $this->refIdentifier,
                'DOCUP_GIT_COMMIT_HASH' => $this->commitSha,
                'DOCUP_VERSION_NAME' => $this->versionLabel,
                'DOCUP_VERSION_TYPE' => $this->versionType,
            ],

            /*
             * 🛑 Declared and never injected in the default mode. They are
             * listed rather than omitted so that the set is enumerable from
             * code — §8.4.13 owes a 14-variable table to the migration guide,
             * and a table assembled from a list that leaves out the forbidden
             * four would be wrong in the most misleading direction.
             */
            EnvironmentScope::Project->value => [
                'READTHEDOCS_PROJECT' => '',
                'READTHEDOCS_VERSION' => '',
                'READTHEDOCS_LANGUAGE' => '',
                'READTHEDOCS_CANONICAL_URL' => '',
            ],
        ];
    }

    /**
     * What actually enters the container.
     *
     * 🛑 §8.7.10, enforced here and asserted by
     * `ArchitectureTest::test_no_project_scoped_variable_reaches_a_build_container`.
     * The project scope is dropped entirely — the key is absent from the
     * returned array, not present with an empty value.
     *
     * @param  bool  $projectBound  §8.4.12's opt-in. Always false in Phase 06;
     *                              the parameter exists so Phase 09 adds a
     *                              caller rather than editing this method, and
     *                              so the forbidden case is testable now.
     * @return array<string, string>
     */
    public function forContainer(bool $projectBound = false): array
    {
        $scopes = $this->byScope();

        $environment = array_merge(
            $scopes[EnvironmentScope::Installation->value],
            $scopes[EnvironmentScope::Component->value],
        );

        if ($projectBound) {
            throw new \LogicException(
                'build_context_mode: project_bound arrives with the §8.4 contract in Phase 09 (§8.4.12)',
            );
        }

        return $environment;
    }

    /**
     * The fourteen `READTHEDOCS_*` names §8.4.13 owes the migration guide.
     *
     * Derived from {@see byScope()} rather than restated, so the count can
     * never drift from the thing that injects them.
     *
     * @return list<string>
     */
    public static function readTheDocsAliases(): array
    {
        $blank = new self('docs.example.com', 'c', 'https://example.com/r.git', 'main', str_repeat('0', 40), 'main');

        $names = [];

        foreach ($blank->byScope() as $variables) {
            foreach (array_keys($variables) as $name) {
                if (str_starts_with($name, 'READTHEDOCS')) {
                    $names[] = $name;
                }
            }
        }

        sort($names);

        return $names;
    }
}
