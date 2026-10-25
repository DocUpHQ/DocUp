<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds;

use App\Automation\AutomationEngine;
use App\Automation\BuildRequestSink;
use App\Composition\SourceDirtiness;
use App\Models\BuildRequest;
use App\Models\ComponentMount;
use App\Models\ComponentSource;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Models\Repository;
use App\Versions\DiscoveredRef;
use App\Versions\RefKind;
use App\Versions\RefSync;
use App\Webhooks\PushEvent;

/**
 * §8.5.3's `repository_fanout` and `poll`: one repository change, every
 * project that consumes it.
 *
 * 🛑 **Capped**, by §8.20.3's `preview_fanout_cap` and `preview_policy`:
 * "one push to a shared component can otherwise trigger previews in every
 * consuming project." The same cap and the same policy govern an ordinary
 * push, because the problem is the same one and two settings would mean an
 * operator who capped their previews discovering that ordinary pushes were
 * never capped at all. §17 gives Phase 11 "repository-change fan-out with
 * the preview cap"; P32 reuses it for previews.
 *
 * The order of operations is §8.5.4's own:
 *
 *   1. **Sync the refs** for each consuming project, which is what creates
 *      a version for a newly pushed tag (§8.6.1).
 *   2. **Fire the automation rules** on what the sync created or lost
 *      (§8.6.8) — before any build request, because a rule may activate the
 *      version that is about to be built, or delete it.
 *   3. **Evaluate the skip rules** (§8.5.4 layer 2), per project, against
 *      the change.
 *   4. **Record a request** and enqueue, within the cap.
 *
 * 🛑 Step 3 before step 4 is what "pre-dispatch" means, and it is what the
 * exit criterion asserts: a skipped project leaves a `skipped`
 * `build_requests` row and **nothing in the queue**.
 */
final readonly class RepositoryFanout implements BuildRequestSink
{
    public function __construct(
        private RefSync $sync,
        private AutomationEngine $automation,
        private SkipRuleEvaluator $skipRules = new SkipRuleEvaluator,
        private BuildTrigger $trigger = new BuildTrigger,
        private SourceDirtiness $dirtiness = new SourceDirtiness,
    ) {}

    /**
     * Fan one push out to every project the repository feeds.
     *
     * @param  string  $triggerKind  one of §8.5.3's eight; `webhook` here
     * @param  string|null  $integrationId  raw 16 bytes, for §8.5.4's first layer
     */
    public function dispatch(
        Repository $repository,
        PushEvent $event,
        string $triggerKind = 'webhook',
        ?string $integrationId = null,
    ): FanoutOutcome {
        /*
         * 🛑 The pushed ref is handed to the sync rather than re-advertised.
         * A webhook payload already names the ref and its SHA, so an
         * `ls-remote` here would be a second round trip for information the
         * provider just sent — and §8.5.1 re-pins with `ls-remote` at `plan`
         * time anyway, which is where the pin has to be authoritative.
         *
         * 🛑 But NOT for a deleted ref. `sync()` treats its list as the
         * COMPLETE set of refs and deactivates everything absent from it,
         * so handing it one ref would deactivate every other version of the
         * project. A deletion therefore advertises properly, which is the
         * one case where the round trip buys something.
         */
        $refs = $event->refDeleted
            ? null
            : [new DiscoveredRef($event->refName, $event->refKind, $event->commitSha)];

        return $this->fanOut(
            $repository,
            $event,
            $refs,
            $triggerKind,
            $integrationId,
            fn (Project $project, array $snapshot): array => $this->versionsForPush($project, $event),
        );
    }

    /**
     * §8.5.3's `ls-remote` poll: advertise once, sync everywhere, build
     * what moved.
     *
     * 🛑 **One advertisement per repository, not one per project.** Forty
     * projects on one monorepo would otherwise be forty `ls-remote` calls
     * per tick against one provider, which is how a poll becomes the thing
     * that gets an installation rate-limited — and the poll exists for
     * repositories that have no other trigger, so losing it to a rate limit
     * costs them everything.
     *
     * @param  list<DiscoveredRef>|null  $refs  already-advertised refs, or null to advertise.
     *                                          The seam {@see RefSync::sync()} has for the same
     *                                          reason: what is under test here is what a poll
     *                                          does with refs, and driving that from a live
     *                                          repository would make it depend on somebody
     *                                          else's tagging habits.
     */
    public function poll(Repository $repository, ?array $refs = null): FanoutOutcome
    {
        $refs ??= $this->sync->discover($repository);

        /*
         * An advertisement carries refs and SHAs and says nothing about
         * files, so the synthesised change is marked truncated — §8.5.4's
         * case (c), "absence of the changed-file arrays altogether". A poll
         * therefore builds what the ref moved rather than what a path
         * filter thinks changed, which is the only honest reading.
         */
        $event = new PushEvent(
            deliveryId: null,
            event: 'poll',
            repositoryIdentifier: null,
            refName: '',
            refKind: RefKind::Branch,
            commitSha: '',
            payloadTruncated: true,
        );

        return $this->fanOut(
            $repository,
            $event,
            $refs,
            'poll',
            null,
            fn (Project $project, array $snapshot): array => $this->movedVersions($project, $refs, $snapshot),
            // Snapshotted before the sync overwrites `ref_commit_sha`.
            beforeSync: fn (Project $project): array => $this->shaSnapshot($project),
        );
    }

    /**
     * §8.6.8's `build` action, arriving through the {@see BuildRequestSink}
     * seam so the engine does not depend on this class.
     */
    public function requestBuild(ProjectVersion $version, string $trigger): BuildRequest
    {
        $request = $this->trigger->record(version: $version, trigger: $trigger);

        if (! $request->isTerminal()) {
            Jobs\RunBuild::dispatch($request->id);
        }

        return $request;
    }

    /**
     * Every project with a version mounting a component sourced from this
     * repository — narrowed to the ones this push could have changed.
     *
     * 🛑 §17 Phase 13's "path-filter rebuild gating", and its exit
     * criterion: "One push triggers exactly the matching projects, asserted
     * on enqueued jobs."
     *
     * The narrowing happens HERE, on the component sources, rather than in
     * `SkipRuleEvaluator`. The two are different questions and both run:
     * this one asks "did the push touch this component's subtree?", which
     * is a fact about `component_sources.source_path`; Phase 11's asks
     * "does this project want to build at all?", which is a fact about the
     * project's own rules. A monorepo needs the first — it is what makes
     * three components in one repository three independent build triggers —
     * and no per-project rule can express it, because the same project may
     * mount two components from the same repository.
     *
     * 🛑 §18.15 is the assumption this rests on, and its pre-decided
     * consequence if it fails is "default to rebuilding every component in
     * a repository on push". {@see SourceDirtiness} is written so that is
     * the behaviour whenever the evidence is incomplete.
     *
     * @param  PushEvent|null  $event  null means every source is in scope
     * @return list<Project>
     */
    public function consumingProjects(Repository $repository, ?PushEvent $event = null): array
    {
        /** @var list<ComponentSource> $sources */
        $sources = array_values(
            ComponentSource::query()
                ->where('repository_id', $repository->id)
                ->where('state', 'active')
                ->get()
                ->all(),
        );

        $componentIds = [];

        foreach ($sources as $source) {
            if ($this->dirtiness->isDirty($source, $event)) {
                $componentIds[] = $source->component_id;
            }
        }

        $componentIds = collect(array_values(array_unique($componentIds)));

        if ($componentIds->isEmpty()) {
            return [];
        }

        $versionIds = ComponentMount::query()
            ->whereIn('component_id', $componentIds)
            ->pluck('project_version_id');

        if ($versionIds->isEmpty()) {
            return [];
        }

        $projectIds = ProjectVersion::query()
            ->whereIn('id', $versionIds)
            ->pluck('project_id')
            ->unique();

        /** @var list<Project> $projects */
        $projects = array_values(
            Project::query()->whereIn('id', $projectIds)->orderBy('id')->get()->all(),
        );

        return $projects;
    }

    /**
     * The shared body of both entry points.
     *
     * @param  list<DiscoveredRef>|null  $refs  null advertises inside the sync
     * @param  \Closure(Project, array<string, string>): list<ProjectVersion>  $pick  which versions to build
     * @param  \Closure(Project): array<string, string>|null  $beforeSync  state to capture first
     */
    private function fanOut(
        Repository $repository,
        PushEvent $event,
        ?array $refs,
        string $triggerKind,
        ?string $integrationId,
        \Closure $pick,
        ?\Closure $beforeSync = null,
    ): FanoutOutcome {
        $enqueued = [];
        $skipped = [];
        $syncs = [];

        foreach ($this->consumingProjects($repository, $event) as $project) {
            // Captured before the sync, because the sync overwrites the
            // very column the poll compares against.
            $snapshot = $beforeSync === null ? [] : $beforeSync($project);

            $outcome = $this->sync->sync($project, $repository, $refs);
            $syncs[] = $outcome;

            $this->automation->apply($project, $outcome, $event);

            $decision = $this->skipRules->decide($project, $event);
            $cap = $this->capFor($project);
            $count = 0;

            foreach ($pick($project, $snapshot) as $version) {
                $request = $this->trigger->record(
                    version: $version,
                    trigger: $triggerKind,
                    integrationId: $integrationId,
                    deliveryId: $this->deliveryKeyFor($event, $version),
                    payloadTruncated: $event->payloadTruncated,
                );

                if ($request->isTerminal()) {
                    /*
                     * §8.5.17's governor refused, or this is a redelivery
                     * whose first attempt already settled. Either way
                     * there is nothing to enqueue.
                     */
                    $skipped[] = $request;

                    continue;
                }

                if ($decision->skips()) {
                    /*
                     * 🛑 §8.5.4: "resolving to `skipped` and never
                     * `failed`". The request is still RECORDED — the first
                     * question anybody asks about a project that stopped
                     * building is "did the webhook arrive?", and a skip
                     * that left no row answers it wrong.
                     */
                    $request->settle('skipped', $decision->identifier());
                    $skipped[] = $request;

                    continue;
                }

                if ($count >= $cap) {
                    /*
                     * Over the cap. Not an error and not a rule's doing, so
                     * it gets its own identifier: an operator looking at a
                     * version that did not build needs to tell "my rule
                     * said no" from "the cap was reached".
                     */
                    $request->settle('skipped', 'skipped.fanout_cap_reached');
                    $skipped[] = $request;

                    continue;
                }

                Jobs\RunBuild::dispatch($request->id);
                $enqueued[] = $request;
                $count++;
            }
        }

        return new FanoutOutcome($enqueued, $skipped, $syncs);
    }

    /**
     * Which of a project's versions one push should build.
     *
     * §8.20.3's three policies, applied to an ordinary push:
     *
     *   - `none` builds nothing; the push updates versions and fires rules
     *     and stops there.
     *   - `default_version_only` builds the default version (§8.6.14's
     *     stored pointer) when the push touched it, which is the sane
     *     default for a shared component.
     *   - `all_dependent_versions` builds every version whose ref the push
     *     moved — capped.
     *
     * @return list<ProjectVersion>
     */
    private function versionsForPush(Project $project, PushEvent $event): array
    {
        if ($project->preview_policy === 'none') {
            return [];
        }

        /*
         * 🛑 A disappeared ref builds nothing. §8.6.15 deactivates the
         * version and leaves its URLs serving; building it would fetch a
         * ref the provider no longer has and fail at `plan`, every time.
         */
        if ($event->refDeleted) {
            return [];
        }

        $pushed = ProjectVersion::query()
            ->where('project_id', $project->id)
            ->where('ref_name', $event->refName)
            ->where('ref_kind', $event->refKind->value)
            ->orderBy('id')
            ->get();

        if ($project->preview_policy === 'default_version_only') {
            /** @var list<ProjectVersion> $matching */
            $matching = array_values(
                $pushed->filter(
                    static fn (ProjectVersion $version): bool => $version->id === $project->default_version_id,
                )->all(),
            );

            return $matching;
        }

        /** @var list<ProjectVersion> $all */
        $all = array_values($pushed->all());

        return $all;
    }

    /**
     * Which of a project's versions a poll should build: the ones whose
     * commit changed, and the ones the sync has just created.
     *
     * 🛑 Not "every tracked version". §8.5.2's digest short-circuit would
     * resolve the unchanged ones to `unchanged` in under a second, so
     * building them all would be correct — and would write one
     * `build_requests` row per version per tick for ever, which turns an
     * operator's build history into noise and the table into the largest
     * one in the schema.
     *
     * @param  list<DiscoveredRef>  $refs
     * @param  array<string, string>  $snapshot  commit SHAs as they were before the sync
     * @return list<ProjectVersion>
     */
    private function movedVersions(Project $project, array $refs, array $snapshot): array
    {
        if ($project->preview_policy === 'none') {
            return [];
        }

        $advertised = [];

        foreach ($refs as $ref) {
            $advertised[$ref->kind->value.':'.$ref->name] = $ref->commitSha;
        }

        $moved = [];

        $versions = ProjectVersion::query()
            ->where('project_id', $project->id)
            ->whereNotNull('ref_name')
            ->orderBy('id')
            ->get();

        foreach ($versions as $version) {
            $key = (string) $version->ref_kind.':'.(string) $version->ref_name;

            if (! array_key_exists($key, $advertised)) {
                continue;
            }

            // Absent from the snapshot means the sync created it on this
            // tick, which is a change by definition.
            $before = $snapshot[$key] ?? null;

            if ($before === $advertised[$key]) {
                continue;
            }

            if ($project->preview_policy === 'default_version_only'
                && $version->id !== $project->default_version_id) {
                continue;
            }

            $moved[] = $version;
        }

        return $moved;
    }

    /**
     * `(kind:name) => commit sha`, read before the sync overwrites it.
     *
     * @return array<string, string>
     */
    private function shaSnapshot(Project $project): array
    {
        $snapshot = [];

        $versions = ProjectVersion::query()
            ->where('project_id', $project->id)
            ->whereNotNull('ref_name')
            ->get();

        foreach ($versions as $version) {
            $snapshot[(string) $version->ref_kind.':'.(string) $version->ref_name] = (string) $version->ref_commit_sha;
        }

        return $snapshot;
    }

    /**
     * §8.20.3's cap, read per project.
     *
     * 🛑 **Per project, bounding that project's own versions**, which is
     * where §10.4 puts the column and what "a per-project policy" implies.
     * The cross-project half of §8.20.3's concern — "one push to a shared
     * component can otherwise trigger previews in every consuming project"
     * — is answered by the POLICY rather than by this number: a project
     * that does not want a shared component's pushes rebuilding it sets
     * `none`. A second, installation-wide total would be a different
     * setting with a different failure mode, and P32 can add one for pull
     * requests if previews need it.
     *
     * Zero is a legitimate value meaning "never fan out", so the fallback
     * applies only when the column is absent — which is what a model built
     * in memory by a test looks like.
     */
    private function capFor(Project $project): int
    {
        /*
         * `getAttribute`, not the property, because the fallback is for a
         * model that does not CARRY the column — one built in memory by a
         * test, or loaded by a `select()` that did not ask for it. Reading
         * the typed property there returns null and PHPStan is right that
         * the typed read can never be anything else.
         */
        $cap = $project->getAttribute('preview_fanout_cap');

        return is_int($cap) ? $cap : 5;
    }

    /**
     * §8.5.4's first layer needs a key per (delivery, version).
     *
     * 🛑 One delivery fanning out to six projects is six build requests,
     * and `UNIQUE (integration_id, delivery_id)` would collapse five of
     * them into the first project's row. The version id makes the key
     * unique per request while keeping a REDELIVERY of the same push
     * colliding with its first attempt, which is what the layer is for.
     */
    private function deliveryKeyFor(PushEvent $event, ProjectVersion $version): ?string
    {
        return $event->deliveryId === null
            ? null
            : $event->deliveryId.':'.bin2hex($version->id);
    }
}
