<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Composition;

use App\Artifacts\ArtifactIngestor;
use App\Artifacts\Publisher;
use App\Composition\Navigation\LayoutTree;
use App\Composition\Navigation\NavFragment;
use App\Models\Build;
use App\Models\Component;
use App\Models\ComponentMount;
use App\Models\ComponentSource;
use App\Models\ProjectVersion;
use App\Serving\ManifestReader;
use App\Support\Uuid;

/**
 * 🛑 One project version's whole composition, resolved (§8.7).
 *
 * This is where Phase 14's deliverables meet. §8.7.5's selectors say which
 * build each mount gets; §8.7.14 refuses the compositions where two of them
 * claim one URL; §8.7.15 turns the overridden overlaps into redirects;
 * §8.7.6 splices the navigation; §8.7.16 builds the cross-reference map and
 * records the references that do not land. All of it reads the same list of
 * mounts exactly once, because the alternative is five passes that can
 * disagree about what the composition is.
 *
 * 🛑 **Nothing here writes.** The plan is returned and the caller — which is
 * {@see Publisher} inside its compare-and-swap transaction —
 * decides whether it becomes a manifest revision. That separation is what
 * makes §8.7.20's "a published manifest and its builds MUST keep serving
 * unchanged" true for a failed publish: a composition that refuses has
 * written nothing to undo.
 */
final readonly class CompositionPlanner
{
    public function __construct(
        private SelectorResolver $selectors = new SelectorResolver,
        private CompositionCollisions $collisions = new CompositionCollisions,
        private ?ManifestReader $manifests = null,
    ) {}

    /**
     * Resolve the composition a version would publish.
     *
     * @param  Build|null  $justBuilt  the build this publish is about, which is
     *                                 not yet in a terminal state
     *
     * @throws CompositionRefused on §8.7.14's collision, §8.7.20's unresolved
     *                            required mount, or §8.7.6's unresolvable include
     */
    public function plan(ProjectVersion $version, ?Build $justBuilt = null): CompositionPlan
    {
        if ($version->project?->merge_policy === 'single_pass') {
            return $this->planSinglePass($version, $justBuilt);
        }

        $resolved = $this->resolveMounts($version, $justBuilt);

        $this->assertRequiredMountsResolved($resolved);

        $overlap = $this->collisions->inspect($resolved);
        $this->assertNoRefusedCollision($overlap, $resolved);

        $xref = $this->crossReferenceMap($resolved);

        return new CompositionPlan(
            mounts: $resolved,
            nav: $this->navigation($version, $resolved),
            xref: $xref,
            linkIssues: $this->linkIssues($resolved),
            shadowRedirects: $overlap->shadowRedirects,
            shadowOverflow: $overlap->shadowOverflow,
        );
    }

    /**
     * 🛑 §8.7.12's `single_pass`, where the composition happened in the
     * sandbox and the manifest has one thing to say.
     *
     * Four of §8.7.13's eight rows are decided here, and each one is an
     * absence rather than a different implementation — which is the point:
     *
     * - **the 404 chain** has one step, because there is one routing mount
     *   and therefore one file manifest for the whole version;
     * - **navigation** is "the one generator's own navigation for the whole
     *   site", so nothing is spliced and `nav_json` is empty — the nav is
     *   in the HTML the generator wrote;
     * - **cross-references** are "resolved inside the build by the
     *   generator's own mechanism", so the §8.7.16 map is empty and
     *   `/_/x/…` answers 404, which is the honest answer when there is
     *   nothing to redirect;
     * - **link issues** cannot exist, because an unresolved `xref:` is the
     *   generator's failure and failed the build.
     *
     * The non-primary mounts are not dropped from the record: the composed
     * build's `build_sources` rows name every contributing repository and
     * commit, which is what §8.7.21 reads. What they are not is **routing**
     * entries, because in this mode they do not route anything.
     *
     * @throws CompositionRefused when the primary mount cannot resolve
     */
    private function planSinglePass(ProjectVersion $version, ?Build $justBuilt): CompositionPlan
    {
        $primary = null;

        foreach ($this->resolveMounts($version, $justBuilt) as $mount) {
            if ($mount->mount->is_primary) {
                $primary = $mount;

                break;
            }
        }

        if (! $primary instanceof ResolvedMount) {
            /*
             * §8.7.3's primary mount is what owns the root, and in this
             * mode it owns everything. Refused with the same identifier
             * `Mounts::assertPublishable()` uses, because it is the same
             * fact: a version with no primary mount has no root.
             */
            throw CompositionRefused::of(
                CompositionRejection::PrimaryMountMissing,
                'a single_pass version serves one composed build and needs a primary mount to own it',
            );
        }

        if (! $primary->resolution->resolved()) {
            throw CompositionRefused::of(
                CompositionRejection::RequiredMountUnresolved,
                $primary->describe().' is the composed build and resolved to nothing ('
                    .$primary->resolution->outcome->value.')',
            );
        }

        return new CompositionPlan(
            mounts: [$primary],
            nav: [],
            xref: [],
            linkIssues: [],
            shadowRedirects: [],
        );
    }

    /**
     * @return list<ResolvedMount>
     */
    private function resolveMounts(ProjectVersion $version, ?Build $justBuilt): array
    {
        /** @var list<ComponentMount> $rows */
        $rows = array_values(
            ComponentMount::query()
                ->where('project_version_id', $version->id)
                ->orderBy('mount_path')
                ->get()
                ->all(),
        );

        $resolved = [];

        foreach ($rows as $mount) {
            $component = $mount->component;

            if (! $component instanceof Component) {
                /*
                 * §8.7.20: "A published manifest and its builds MUST keep
                 * serving unchanged when a component becomes orphaned". A
                 * mount whose component row has gone is skipped rather than
                 * fatal — the *existing* manifest keeps serving, and the
                 * required-mount check below is what fails a new publish if
                 * the edge mattered.
                 */
                continue;
            }

            $resolution = $this->selectors->resolve($mount, $version, $justBuilt);
            $build = $resolution->build;

            $resolved[] = new ResolvedMount(
                mount: $mount,
                component: $component,
                resolution: $resolution,
                files: $build instanceof Build ? $this->filesFor($build) : [],
                priority: $this->priorityFor($build),
            );
        }

        return $resolved;
    }

    /**
     * @return array<string, array{sha256: string, bytes: int, content_type: string}>
     */
    private function filesFor(Build $build): array
    {
        $reader = $this->manifests ?? app(ManifestReader::class);

        return $reader->files(Uuid::toText($build->id));
    }

    /**
     * §8.7.14's `component_sources.priority`, for the two permissive policies.
     *
     * Defaulted to the column's own default when the build names no source —
     * a direct upload has none — so a collision between an upload and a
     * built component is decided the same way as any other tie.
     */
    private function priorityFor(?Build $build): int
    {
        $sourceId = $build?->component_source_id;

        if (! is_string($sourceId)) {
            return 100;
        }

        $source = ComponentSource::query()->whereKey($sourceId)->first();

        return $source instanceof ComponentSource ? $source->priority : 100;
    }

    /**
     * 🛑 §8.7.20: "New publications MUST fail closed when a required mount
     * cannot resolve."
     *
     * Fail **closed** is the whole clause. The tempting behaviour is to
     * publish the mounts that did resolve and leave a gap, which looks like
     * a partial success and is actually a manual with a chapter missing and
     * nobody told.
     *
     * @param  list<ResolvedMount>  $mounts
     *
     * @throws CompositionRefused
     */
    private function assertRequiredMountsResolved(array $mounts): void
    {
        foreach ($mounts as $mount) {
            if (! $mount->mount->is_required || $mount->resolution->resolved()) {
                continue;
            }

            throw CompositionRefused::of(
                CompositionRejection::RequiredMountUnresolved,
                $mount->describe().' is required and its '
                    .$mount->resolution->kind->value.' selector resolved to nothing ('
                    .$mount->resolution->outcome->value.')',
            );
        }
    }

    /**
     * 🛑 §8.7.14, with both sources and the exact path in the message.
     *
     * @param  list<ResolvedMount>  $mounts
     *
     * @throws CompositionRefused
     */
    private function assertNoRefusedCollision(CompositionOverlap $overlap, array $mounts): void
    {
        foreach ($overlap->collisions as $collision) {
            /*
             * The policy is the **deeper** mount's component's, because that
             * is the one whose presence created the overlap. §8.7.14 says a
             * precedence strategy "MUST be selected explicitly per
             * component", and the component being added is the one making
             * the choice.
             */
            $policy = match ($collision->deeper->component->collision_policy) {
                'first_wins' => CollisionPolicy::FirstWins,
                'priority_wins' => CollisionPolicy::PriorityWins,

                // 🛑 Anything else is `fail`, including a value this
                // version of the code does not know. §8.7.14 makes refusal
                // the default and an unrecognised precedence strategy is
                // exactly the case where guessing is worst.
                default => CollisionPolicy::Fail,
            };

            if (! $policy->permitsOverlap()) {
                throw CompositionRefused::of(
                    CompositionRejection::PathCollision,
                    $collision->describe().' (collision_policy='.$policy->value.')',
                );
            }

            if (! $collision->winner($policy) instanceof ResolvedMount) {
                throw CompositionRefused::of(
                    CompositionRejection::CollisionPriorityTie,
                    $collision->describe().' and both sources have priority '
                        .$collision->deeper->priority,
                );
            }
        }
    }

    /**
     * 🛑 §8.7.6's two layers, spliced.
     *
     * @param  list<ResolvedMount>  $mounts
     * @return list<Navigation\NavNode>
     *
     * @throws CompositionRefused
     */
    private function navigation(ProjectVersion $version, array $mounts): array
    {
        $fragments = [];
        $required = [];

        foreach ($mounts as $mount) {
            $fragments[$mount->componentKey()] = $this
                ->fragmentFor($mount)
                ->withPrefix($mount->mountPath);

            $required[$mount->componentKey()] = $mount->mount->is_required;
        }

        return LayoutTree::splice($version->layout_json, $fragments, $required);
    }

    /**
     * 🛑 §8.7.6's "`.docup.yaml` `nav:` **or** the generator's own output",
     * with the precedence that sentence implies.
     *
     * `builds.nav_json` holds the first: the worker parses `.docup.yaml`
     * outside the sandbox (§8.4.9) and writes what it found there.
     * `nav/nav.json` in the artifact holds the second, because the
     * generator produced it inside the sandbox. Both are kept so an
     * operator debugging a wrong sidebar can see which one won; the
     * repository's explicit declaration wins, because an author who wrote
     * `nav:` meant it.
     *
     * Either way the bytes pass through {@see NavFragment::normalise()},
     * which is the trust boundary — both sources are repository content.
     */
    private function fragmentFor(ResolvedMount $mount): NavFragment
    {
        $build = $mount->resolution->build;

        if (! $build instanceof Build) {
            return NavFragment::empty();
        }

        $declared = $build->nav_json;

        if (is_array($declared) && $declared !== []) {
            return NavFragment::normalise($declared);
        }

        if (! isset($mount->files[ArtifactIngestor::NAV_LEAF])) {
            // §8.7.6: "A missing fragment degrades to a labelled section."
            return NavFragment::empty();
        }

        $reader = $this->manifests ?? app(ManifestReader::class);
        $bytes = $reader->navFragment(Uuid::toText($build->id));

        return $bytes === null ? NavFragment::empty() : NavFragment::decode($bytes);
    }

    /**
     * 🛑 §8.7.16's per-component cross-reference map.
     *
     * > "`objects.inv` and a per-component cross-reference map MUST be
     * > served **directly at a stable path with no redirect**, so Sphinx
     * > intersphinx never depends on redirect-following."
     *
     * Keyed by component key, because that is what a cross-reference names
     * and what `/_/x/{component_key}/{path}` carries. The build id is in it
     * so the serving endpoint can hand off `objects.inv` without a second
     * manifest read, and `objects_inv` says whether there is one — a
     * MkDocs component has none, and answering 404 from the map is cheaper
     * and more honest than handing off a key that is not there.
     *
     * @param  list<ResolvedMount>  $mounts
     * @return array<string, array{mount_path: string, build_id: string|null, objects_inv: bool}>
     */
    private function crossReferenceMap(array $mounts): array
    {
        $map = [];

        foreach ($mounts as $mount) {
            $build = $mount->resolution->build;

            $map[$mount->componentKey()] = [
                'mount_path' => $mount->mountPath,
                'build_id' => $build instanceof Build ? Uuid::toText($build->id) : null,
                'objects_inv' => $mount->serves('objects.inv'),
            ];
        }

        return $map;
    }

    /**
     * 🛑 §8.7.16's link issues, which never fail anything.
     *
     * > "Unresolved references MUST be recorded as publish-time link issues
     * > that **never fail a build and never block a publish** — one
     * > repository's typo must not break another repository's build."
     *
     * So this method returns rows and throws nothing, and the caller writes
     * them beside the manifest it has already decided to publish. The two
     * kinds are distinguished because the remedies are different: a
     * reference to a component this version does not mount is the
     * project's configuration, and a reference to a path that component
     * does not have is the referring repository's typo.
     *
     * @param  list<ResolvedMount>  $mounts
     * @return list<array{component_id: string, source_path: string, target_component_key: string, target_path: string, kind: string}>
     */
    private function linkIssues(array $mounts): array
    {
        $byKey = [];

        foreach ($mounts as $mount) {
            $byKey[$mount->componentKey()] = $mount;
        }

        $issues = [];

        foreach ($mounts as $mount) {
            foreach ($this->referencesOf($mount) as $reference) {
                $target = $byKey[$reference['component']] ?? null;

                if (! $target instanceof ResolvedMount) {
                    $issues[] = $this->issue($mount, $reference, 'component_not_mounted');

                    continue;
                }

                if (! $this->targetExists($target, $reference['path'])) {
                    $issues[] = $this->issue($mount, $reference, 'path_not_found');
                }
            }
        }

        return $issues;
    }

    /**
     * Whether a cross-reference target is a real page of that component.
     *
     * A directory reference — `guide/` or `guide` with an `index.html`
     * inside — resolves, because that is what the serving path does with
     * it (§8.9.7). Answered from the file manifest, never from storage,
     * for §8.4.18's reason.
     */
    private function targetExists(ResolvedMount $target, string $path): bool
    {
        if ($path === '' || str_ends_with($path, '/')) {
            return $target->serves($path.'index.html');
        }

        return $target->serves($path) || $target->serves($path.'/index.html');
    }

    /**
     * @param  array{component: string, path: string, source: string}  $reference
     * @return array{component_id: string, source_path: string, target_component_key: string, target_path: string, kind: string}
     */
    private function issue(ResolvedMount $mount, array $reference, string $kind): array
    {
        return [
            'component_id' => $mount->component->id,
            'source_path' => mb_strcut($reference['source'], 0, 512),
            'target_component_key' => mb_strcut($reference['component'], 0, 100),
            'target_path' => mb_strcut($reference['path'], 0, 512),
            'kind' => $kind,
        ];
    }

    /**
     * The `/_/x/…` references a mount's build made, as ingest recorded them.
     *
     * @return list<array{component: string, path: string, source: string}>
     */
    private function referencesOf(ResolvedMount $mount): array
    {
        $raw = $mount->resolution->build?->cross_references;

        if (! is_array($raw) || ! is_array($raw['references'] ?? null)) {
            return [];
        }

        $references = [];

        foreach ($raw['references'] as $reference) {
            if (! is_array($reference)) {
                continue;
            }

            $component = $reference['component'] ?? null;
            $path = $reference['path'] ?? null;
            $source = $reference['source'] ?? null;

            if (! is_string($component) || ! is_string($path)) {
                continue;
            }

            $references[] = [
                'component' => $component,
                'path' => $path,
                'source' => is_string($source) ? $source : '',
            ];
        }

        return $references;
    }
}
