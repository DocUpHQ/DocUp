<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds;

use App\Artifacts\ArtifactStore;
use App\Artifacts\Publisher;
use App\Artifacts\PublishOutcome;
use App\Artifacts\TarArchiveWriter;
use App\Audit\ActorType;
use App\Audit\Audit;
use App\Builds\Admission\Dispatcher;
use App\Builds\Fragments\FragmentCache;
use App\Builds\Fragments\FragmentDigest;
use App\Builds\Log\BuildLog;
use App\Builds\Log\BuildLogAppended;
use App\Builds\Log\BuildLogArchive;
use App\Builds\Log\LogLine;
use App\Builds\Runner\RunOutcome;
use App\Builds\Runner\Spool;
use App\Builds\Sandbox\SandboxPolicy;
use App\Builds\Toolchain\ToolchainPlan;
use App\Composition\Navigation\NavFragment;
use App\Config\ConfigDiscovery;
use App\Config\ConfigParser;
use App\Config\ConfigRefused;
use App\Config\ConfigRejection;
use App\Config\DocupConfig;
use App\Config\HtmlContext;
use App\Config\ShellSemantics;
use App\Config\YamlGate;
use App\Credentials\CredentialVault;
use App\Credentials\SecretRedactor;
use App\Models\Build;
use App\Models\BuildRequest;
use App\Models\BuildSource;
use App\Models\BuildStep;
use App\Models\Component;
use App\Models\ComponentMount;
use App\Models\ComponentSource;
use App\Models\ProjectVersion;
use App\Models\Repository;
use App\Support\Uuid;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;

/**
 * §8.5.6's twelve stages, driven from the worker.
 *
 * 🛑 **Nine stages run here and three run in containers**, and the split is
 * §11.2's trust zones rather than convenience. This class holds the database
 * credentials and the `APP_KEY`; it must therefore never execute repository
 * code, so `fetch`, `environment` and `build` are handed to the runner as
 * typed specifications (§8.5.13). The runner holds the container-runtime
 * socket and no credentials. Neither process holds both, which is the whole
 * of the containment argument and is asserted by `RunnerIsolationTest`.
 *
 * 🛑 **`plan` runs before anything is fetched, and that ordering is a
 * requirement, not an optimisation** (§8.5.1): "every contributing ref pinned
 * to an immutable commit SHA ... **before any repository code executes**". A
 * plan resolved afterwards is a plan the repository could have influenced.
 * §8.5.2 then adds that the short-circuit must happen "with no container
 * started", which is why {@see RefResolver} reaches the provider over HTTP
 * through the §8.3.9 client instead of running `git ls-remote` in a box.
 */
final class BuildPipeline
{
    public function __construct(
        private readonly RefResolver $refs,
        private readonly Spool $spool,
        private readonly Publisher $publisher,
        private readonly CredentialVault $vault,
        private readonly SecretRedactor $redactor,
        ?SandboxPolicy $policy = null,
        ?Dispatcher $dispatcher = null,
        ?BuildLogArchive $archive = null,
        private readonly BuildGovernor $governor = new BuildGovernor,
        ?FragmentCache $fragments = null,
    ) {
        $this->policy = $policy ?? SandboxPolicy::fromConfig();
        $this->dispatcher = $dispatcher ?? Dispatcher::fromConfig();
        $this->fragments = $fragments ?? new FragmentCache;

        /*
         * Resolved from the container, not constructed: §11.4's
         * `ArtifactStore` seam is how an installation chooses local or S3,
         * and a log archive that picked one itself would put a build's log
         * somewhere its artifacts are not.
         */
        $this->archive = $archive ?? new BuildLogArchive(app(ArtifactStore::class));
    }

    /** §10.3's `logs/<project>/<build>/log.ndjson.gz`, once the build ends. */
    private readonly BuildLogArchive $archive;

    /** §8.5.5's admission control, resolved once for the same reason. */
    private readonly Dispatcher $dispatcher;

    /**
     * The build's log, while one is running.
     *
     * 🛑 Held on the pipeline rather than passed through fifteen call
     * sites, because §8.5.21's redaction and §8.5.22's sequence numbering
     * are both properties of ONE writer. Two writers on the same build
     * would hand two different lines the same address, which is precisely
     * what every client cursor assumes cannot happen.
     */
    private ?BuildLog $log = null;

    /** The build being run, so the cancel check knows which row to read. */
    private ?Build $running = null;

    /** §8.4.6's scoped variables, resolved once per build. See {@see resolveBaseEnvironment()}. */
    private ?BuildEnvironment $baseEnvironment = null;

    /** §8.5.19's cache. One object, because it is the only reader of `fragments`. */
    private readonly FragmentCache $fragments;

    /**
     * 🛑 Resolved once per pipeline rather than read per stage.
     *
     * The failure this prevents is a build whose `fetch` ran under one
     * isolation posture and whose `build` ran under another because a
     * configuration cache was warmed in between — two halves of one build
     * in two trust zones, with nothing in the record to show it happened.
     */
    private readonly SandboxPolicy $policy;

    /**
     * Take a request to a terminal state.
     *
     * Returns the build, or null when the request settled without one — which
     * §8.5.2 and §8.5.4 both require to be possible and neither treats as a
     * failure.
     */
    public function run(BuildRequest $request, ?int $waitSeconds = null): ?Build
    {
        /*
         * 🛑 §8.1.7's hosting-only mode, refused at the top and before
         * anything is read. "with `DOCUP_BUILDS_ENABLED=false` the
         * application boots with no runner, and a build trigger is refused
         * with a stable identifier rather than queued forever."
         *
         * Queueing would be the kinder-looking failure and the worse one:
         * a request sitting in `queued` on an installation that has
         * deliberately removed its runner is indistinguishable from a busy
         * queue, and the author would wait for a build nothing will ever
         * claim.
         */
        if (! $this->policy->buildsEnabled) {
            $request->settle('rejected', 'rejected.builds_disabled');

            return null;
        }

        /*
         * 🛑 §8.5.12's verdict, read from the spool because this process
         * has no socket and cannot run the test itself. A sandbox that
         * failed its self-test is an installation whose isolation nobody
         * has verified, and §8.5.12 makes that a refusal rather than a
         * degraded mode.
         *
         * Absent is not the same as failed, and both refuse: no verdict
         * means no runner has started since this spool was created, so the
         * same thing is true — nothing has checked.
         */
        $selfTest = $this->spool->readSelfTest();

        if ($selfTest === null || ! $selfTest['passed']) {
            $request->settle('rejected', 'infra.sandbox_self_test_failed');

            return null;
        }

        $version = $request->version;

        if (! $version instanceof ProjectVersion) {
            $request->settle('rejected', 'rejected.version_missing');

            return null;
        }

        /*
         * 🛑 §8.5.10: "Fork-PR builds MUST be **off by default** with an
         * explicit opt-in and a written threat statement."
         *
         * Before the component, the source and the plan — before anything
         * at all is read on behalf of this request. A fork build that got
         * as far as `fetch` would already have asked a provider for a ref
         * on somebody else's behalf, and a policy refusal that depends on
         * a repository being attached is a policy refusal that reports
         * something else entirely when one is not.
         *
         * `credentialFor()` independently withholds every secret from a
         * fork build, so the two controls do not depend on each other
         * being right.
         */
        if ($request->from_fork === true && $version->project?->fork_builds_enabled !== true) {
            $request->settle('rejected', 'rejected.fork_builds_disabled');

            return null;
        }

        $component = $this->componentFor($request, $version);

        if (! $component instanceof Component) {
            $request->settle('rejected', 'rejected.no_component');

            return null;
        }

        $source = ComponentSource::query()
            ->where('component_id', $component->id)
            ->where('state', 'active')
            ->first();

        if (! $source instanceof ComponentSource) {
            // §8.3.2: a component with no attached repository is a component
            // nothing can build. Reported as a refusal rather than a failure,
            // because no build was ever possible.
            $request->settle('rejected', 'rejected.no_repository_attached');

            return null;
        }

        $repository = $source->repository;

        if (! $repository instanceof Repository) {
            $request->settle('rejected', 'rejected.no_repository_attached');

            return null;
        }

        // ------------------------------------------------------------ plan
        //
        // Before the build row exists, because its outcome may be that no
        // build should exist (§8.5.2).
        try {
            $plan = $this->resolvePlan($version, $source, $repository);
        } catch (BuildFailure $failure) {
            $request->settle('failed', $failure->identifier());

            return null;
        }

        if ($this->isUnchanged($version, $plan)) {
            /*
             * 🛑 §8.5.2's short-circuit: "a terminal `unchanged` state in
             * under a second, with no container started". Nothing below this
             * line has run, no volume exists, and the runner has not been
             * told anything.
             */
            $request->settle('unchanged', 'unchanged.plan_digest_matches_published');

            return null;
        }

        /*
         * 🛑 §8.7.9: "satisfied from an existing successful build with the
         * same key. This is what makes one repository feeding many projects
         * build **once**."
         *
         * Before the build row, because the whole point is that no build
         * row is created. A second project mounting a component another
         * project already built reaches here, finds that build, publishes
         * it, and starts no container at all — which is the difference
         * between a monorepo feeding forty projects being affordable and
         * not.
         *
         * Distinct from §8.5.2's `unchanged` immediately above, and the two
         * are easy to confuse: `unchanged` says "this version's published
         * build already has these inputs, so do nothing"; this says "some
         * build somewhere already has these inputs, so publish THAT one
         * here". The first produces no publish and the second produces one.
         */
        $reusable = $this->reusableBuildFor($version, $component, $source, $plan);

        if ($reusable instanceof Build) {
            return $this->publishReused($request, $version, $reusable);
        }

        $build = $this->openBuild($request, $version, $component, $source, $plan);

        if ($build === null) {
            /*
             * 🛑 Two different indexes can refuse here, and they mean
             * different things.
             *
             * §10.3's `inflight` index: another build for THIS version is
             * already queued or running — §8.5.4's fourth deduplication
             * layer, enforced by the database rather than by a check that
             * two jobs in one batch would both pass.
             *
             * §8.7.9's `content_key` index: another project's build of the
             * SAME component, with the same inputs, got there first. That
             * is not a supersession — nothing about this request is stale —
             * and the race is a normal consequence of a monorepo push
             * fanning out to three projects at once. So the reuse check is
             * re-run: if that build has finished in the interval, this
             * version publishes it, which is the outcome §8.7.9 asks for
             * and the one a plain `superseded` would have silently denied.
             */
            $raced = $this->reusableBuildFor($version, $component, $source, $plan);

            if ($raced instanceof Build) {
                return $this->publishReused($request, $version, $raced);
            }

            /*
             * Still running, or genuinely superseded. Settled with an
             * identifier that says which, because "my project did not
             * publish and another did" is a question an operator will ask
             * and `superseded.build_already_in_flight` does not answer it.
             *
             * 🛑 **Owed, and stated rather than hidden:** this version is
             * not published by the build it was waiting on. The next
             * trigger — the §8.5.3 schedule, the next push, a manual build
             * — finds that build published and reuses it in under a
             * second. A pending-publish queue would close the gap and is
             * P14's, where several mounts per version make it necessary
             * anyway.
             */
            $concurrent = Build::query()
                ->where('organisation_id', $version->organisation_id)
                ->where('content_key', $this->contentKeyFor($version, $component, $source, $plan) ?? '')
                ->whereIn('state', ['queued', 'running'])
                ->exists();

            $request->settle(
                'superseded',
                $concurrent
                    ? 'superseded.identical_build_in_flight_elsewhere'
                    : 'superseded.build_already_in_flight',
            );

            return null;
        }

        $steps = (new StepRecorder('pipeline'))->createPipeline($build);
        $recorder = StepRecorder::forThisProcess();

        // One conversion, used everywhere the spool is addressed. The run
        // specification is built from the same value, so the worker and the
        // runner cannot disagree about a job's name.
        $buildHex = bin2hex($build->id);

        /*
         * 🛑 Opened before the first stage, so a build that fails in
         * `admit` still has a log saying so. A log that only exists once a
         * container has started is a log that is absent for exactly the
         * failures an author cannot otherwise explain.
         */
        $this->log = BuildLog::open($buildHex, $this->redactor);
        $this->running = $build;
        $this->narrate('build '.$buildHex.' accepted');

        try {
            $this->stage($recorder, $steps, Stage::Admit, function () use ($build): void {
                $this->admit($build);
            });

            // Recorded against the step that produced it, after the fact: the
            // work happened above, because its result decides whether there
            // is a build to record it against at all.
            $this->stage($recorder, $steps, Stage::Plan, function () use ($build, $plan, $source, $repository, $component, $version): void {
                $this->recordPlan($build, $plan, $source, $repository);
                $this->resolveBaseEnvironment($component, $repository, $plan, $this->mountFor($version, $component));
            });

            $fetch = $this->stage($recorder, $steps, Stage::Fetch, fn (): RunOutcome => $this->fetch(
                $build,
                $repository,
                $source,
                $plan->sources[0]['commit_sha'],
                $plan->sources[0]['ref'],
                $waitSeconds,
            ));

            /*
             * The §8.4 resolution: the file, the schema, the preset and the
             * two scripts. Captured by reference because every stage after
             * this one is a function of it and PHP closures bind by value.
             */
            $toolchain = null;

            $this->stage($recorder, $steps, Stage::ValidateConfig, function () use ($build, $fetch, $plan, $repository, &$toolchain): void {
                $toolchain = $this->validateConfig($build, $fetch, $plan, $repository);
            });

            /*
             * `stage()` rethrows anything the closure threw, so reaching
             * here means it returned — but the binding is by reference and
             * nothing in the type system says so. Thrown rather than
             * asserted: `assert()` compiles out under
             * `zend.assertions=-1`, which is the production setting, so the
             * one environment where a null would do real damage is the one
             * where the check would not run.
             */
            if (! $toolchain instanceof ToolchainPlan) {
                throw new \LogicException('validate_config returned no toolchain (§8.4)');
            }

            /*
             * 🛑 §8.5.25's component variables, read once and never during
             * `fetch`. A fork build gets nothing at all — "withheld entirely
             * from fork and pull-request builds regardless of the `public`
             * flag".
             */
            $variables = ComponentEnvironment::forComponent(
                $component,
                $build->buildRequest?->from_fork === true,
            );

            $fragment = $this->fragmentFor($plan, $toolchain, $variables);
            $cached = $this->fragments->lookup($repository->id, $fragment->bytes());

            if ($variables->makesFragmentUncacheable()) {
                // 🛑 §8.5.19: a configuration that referenced a secret may not
                // be served from the cache either, so the hit is discarded
                // rather than merely not recorded.
                $cached = null;
            }

            if ($cached instanceof Build) {
                /*
                 * 🛑 §8.5.19: "A cache hit skips the environment and build
                 * stages entirely — this is what makes a shared API
                 * repository feeding 40 projects affordable." Those two and
                 * no others: `collect`, `store` and `publish` still run,
                 * because this version needs its own artifacts and §8.21.6
                 * allows exactly one way to produce them.
                 */
                $recorder->skip($steps[Stage::Environment->value], 'skipped.fragment_cache_hit');
                $recorder->skip($steps[Stage::Build->value], 'skipped.fragment_cache_hit');

                $this->narrate('fragment cache hit: reusing build '.bin2hex($cached->id).' (§8.5.19)');
                $this->fragments->recordHit($build, $repository->id, $fragment->bytes());

                $archive = $this->rehydrate($cached, $buildHex);
            } else {
                $this->runEnvironmentStage($recorder, $steps, $build, $toolchain, $variables, $waitSeconds);

                $this->stage($recorder, $steps, Stage::Build, fn (): RunOutcome => $this->build(
                    $build,
                    $component,
                    $repository,
                    $plan,
                    $toolchain,
                    $variables,
                    $waitSeconds,
                ));

                /*
                 * 🛑 The HEX form, which is what the run specification
                 * carried. `getRawOriginal('id')` is the raw 16 bytes
                 * (§9.1.1), and using it here built a filename that could
                 * never match the one the runner wrote — so a build that had
                 * succeeded and produced a 2 MB tar was reported as
                 * `contract.no_output_directory`, which is the one failure
                 * identifier guaranteed to send an author looking at their
                 * own `mkdocs.yml`.
                 */
                $archive = $this->spool->output($buildHex.'-build');

                $this->fragments->remember(
                    $build,
                    $repository->id,
                    $fragment->bytes(),
                    cacheable: ! $variables->makesFragmentUncacheable(),
                );

                $this->fragments->link($build, $repository->id, $fragment->bytes(), wasHit: false);
            }

            $this->stage($recorder, $steps, Stage::Collect, function () use ($archive): void {
                if (! is_file($archive) || filesize($archive) === 0) {
                    throw BuildFailure::of(FailureClass::Contract, 'no_output_directory', Stage::Collect);
                }
            });

            // One component in Phase 06; §8.7's composition is Phase 13-15.
            $recorder->skip($steps[Stage::Compose->value], 'skipped.single_component');

            $outcome = $this->stage(
                $recorder,
                $steps,
                Stage::Store,
                fn () => $this->publish($build, $version, $archive, $request, $plan),
            );

            /*
             * Narrated by hand, because this step is marked succeeded
             * directly rather than through `stage()` — the work happened
             * inside `store`, which owns the compare-and-swap. Without
             * this line the log skips straight from `store` to
             * `finalise` and an author reading it cannot tell whether a
             * publish was attempted.
             */
            $recorder->succeed($steps[Stage::Publish->value]);
            $this->narrate('publish: ok');

            // §8.16's index arrives in Phase 29.
            $recorder->skip($steps[Stage::Index->value], 'skipped.search_index_phase_29');

            $this->stage($recorder, $steps, Stage::Finalise, function () use ($build, $outcome): void {
                /*
                 * 🛑 §8.8.4: losing the compare-and-swap is not failing. The
                 * artifacts are valid and selectable; this build simply is
                 * not the one being served, and `success_unpublished` is the
                 * state §10.3 gives it so that nobody chases a phantom error
                 * every time two builds finish together.
                 */
                $build->forceFill([
                    'state' => $outcome->published ? 'published' : 'success_unpublished',
                    'finished_at' => now(),
                ])->save();
            });

            $this->narrate($outcome->published
                ? 'published — the version now serves this build'
                : 'succeeded, but another build won the pointer (§8.8.4)');

            $request->forceFill(['state' => 'completed', 'build_id' => $build->id])->save();

            return $build->refresh();
        } catch (BuildFailure $failure) {
            $this->failBuild($build, $request, $failure, $recorder, $steps);

            return $build->refresh();
        } finally {
            /*
             * 🛑 The log is sealed in the `finally`, so it happens on every
             * path — success, failure, and the `BuildFailure` that is
             * rethrown above. A log archived only on success is a log
             * missing from every build anybody wants to read.
             */
            $this->sealLog($build);

            /*
             * 🛑 §8.5.17's governor sees EVERY terminal build, including
             * the ones that failed, which is the whole point: it counts
             * consecutive failures. In the `finally` so that a build which
             * threw on its way out is still counted — a governor that only
             * saw the builds that reached the end of `run()` would be
             * blind to exactly the failures it exists to notice.
             */
            $this->governor->record($build->refresh());

            $this->spool->discard($buildHex.'-fetch');
            $this->spool->discard($buildHex.'-build');
        }
    }

    /**
     * Record the log's shape on the build row and archive it (§10.3).
     *
     * 🛑 The metadata is written BEFORE the archive, because the archive
     * can fail — an S3 outage, a write-once refusal on a re-run — and a
     * build whose log exists but whose row says it has none is unreadable
     * through the API. The row describing a log that could not be stored
     * is merely wrong about where it is, which `BuildLogArchive` reports.
     */
    private function sealLog(Build $build): void
    {
        $log = $this->log;
        $this->log = null;
        $this->running = null;

        if (! $log instanceof BuildLog) {
            return;
        }

        $build->forceFill([
            'log_lines' => $log->lineCount(),
            'log_bytes' => $log->byteCount(),
            'log_capped' => $log->wasCapped(),
        ])->save();

        /*
         * The last event a listener receives, and the one that tells it to
         * stop. Sent before the archive, because archiving can fail and a
         * client left polling a finished build for ever is a worse outcome
         * than a log that is briefly only in its live file.
         */
        BuildLogAppended::dispatch(bin2hex($build->id), $log->lineCount() + 1, true);

        $this->archive->archive($build, $log);
    }

    /**
     * §8.5.1: pin every ref, before anything runs.
     *
     * @throws BuildFailure
     */
    private function resolvePlan(ProjectVersion $version, ComponentSource $source, Repository $repository): BuildPlan
    {
        $ref = $this->refFor($source, $repository);
        $sha = $this->refs->resolve($repository->clone_url, $ref);

        return new BuildPlan(
            versionId: $version->id,
            sources: [[
                'source_id' => $source->id,
                'repository_id' => $repository->id,
                'ref' => $ref,
                'commit_sha' => $sha,
                'source_path' => $source->source_path,
            ]],

            /*
             * 🛑 Empty before `fetch`, and that is correct rather than a gap.
             * The configuration file lives in the repository at the commit
             * just pinned, so its digest is a *function* of that commit — two
             * plans with identical SHAs necessarily have identical config
             * digests. {@see isUnchanged()} therefore borrows the published
             * build's recorded digest when every SHA matches, which is the
             * only case in which the comparison could succeed anyway. Fetching
             * the file first to learn its digest would start a container,
             * which is precisely what §8.5.2 forbids.
             */
            configDigest: '',
            envDigest: $this->envDigest(),
        );
    }

    /**
     * §8.5.2's comparison.
     *
     * @see resolvePlan() for why the config digest is borrowed rather than computed
     */
    private function isUnchanged(ProjectVersion $version, BuildPlan $plan): bool
    {
        $published = Build::query()
            ->where('project_version_id', $version->id)
            ->where('state', 'published')
            ->latest('finished_at')
            ->first();

        if (! $published instanceof Build || $published->plan_digest === null) {
            return false;
        }

        $candidate = new BuildPlan(
            versionId: $plan->versionId,
            sources: $plan->sources,
            configDigest: (string) $published->config_digest,
            envDigest: $plan->envDigest,
            pipelineVersion: $plan->pipelineVersion,
        );

        return $candidate->matches((string) $published->plan_digest);
    }

    /**
     * §8.5.2's `env_digest`, which §8.5.14 requires to include the image
     * digest.
     *
     * Without the image in it, a security fix to the toolchain would never
     * reach a project whose inputs had not changed — the short-circuit would
     * refuse every rebuild, for ever, and the fix would sit in a registry.
     */
    private function envDigest(): string
    {
        /** @var array<string, array<string, string|null>> $images */
        $images = (array) config('builds.images');

        return hash('sha256', json_encode([
            'images' => $images,
            'limits' => config('builds.limits'),
        ], JSON_THROW_ON_ERROR));
    }

    /**
     * §8.7.9's "existing successful build with the same key", or null.
     *
     * 🛑 `published` **or** `success_unpublished`. A build that succeeded and
     * lost the §8.8.4 compare-and-swap is still a complete, validated
     * artifact; refusing to reuse it would mean a second project rebuilding
     * a component because a race it had nothing to do with went the other
     * way. `failed` and `cancelled` are excluded for the obvious reason, and
     * `running` because its bytes do not exist yet.
     *
     * Scoped to the organisation by the content key itself, not by a `where`
     * — see {@see ContentKey} for why the organisation is inside the hash.
     * The `where` is here as well, because a key collision across tenants
     * would be a cross-tenant artifact disclosure and "the hash makes that
     * impossible" is a claim this query should not have to rely on.
     */
    private function reusableBuildFor(
        ProjectVersion $version,
        Component $component,
        ComponentSource $source,
        BuildPlan $plan,
    ): ?Build {
        $key = $this->contentKeyFor($version, $component, $source, $plan);

        if ($key === null) {
            return null;
        }

        return Build::query()
            ->where('organisation_id', $version->organisation_id)
            ->where('content_key', $key)
            ->whereIn('state', ['published', 'success_unpublished'])
            ->orderBy('finished_at')
            ->first();
    }

    /**
     * §8.7.9's key for the build this request would produce.
     *
     * Null when the plan pinned no commit, which `resolvePlan()` does not
     * produce — narrowed rather than asserted, because the consequence of a
     * wrong key is two projects sharing bytes and the consequence of a null
     * is one extra build.
     */
    private function contentKeyFor(
        ProjectVersion $version,
        Component $component,
        ComponentSource $source,
        BuildPlan $plan,
    ): ?string {
        /*
         * 🛑 `orderedSources()` is a list of `sourceId:sha` STRINGS for the
         * plan digest, not the rows — so the commit is read from `sources`
         * directly. Phase 13 has exactly one source per build (§17 defers
         * more than one component per version to P14); when P14 lifts that,
         * this becomes the ordered set and the key covers all of them,
         * which is why it is taken from the plan rather than from the
         * `component_sources` row.
         */
        $commit = $plan->sources[0]['commit_sha'] ?? null;

        if (! is_string($commit) || $commit === '') {
            return null;
        }

        unset($source);

        return ContentKey::compute(
            organisationId: $version->organisation_id,
            componentId: $component->id,
            commitSha: $commit,
            configDigest: $plan->configDigest,
            envDigest: $plan->envDigest,
            pipelineVersion: $plan->pipelineVersion,
            mountPath: ContentKey::mountPathFor($this->mountFor($version, $component), $component),
        );
    }

    /**
     * This version's mount of this component, where one exists.
     *
     * 🛑 The MOUNT's `base_url_mode` is what decides both §8.7.9's key and
     * §8.7.11's `$DOCUP_BASE_PATH`, so both read it through here. §8.7.11
     * lets a mount override the component's default, and a key computed
     * from the component's default while the container saw the mount's
     * would be two answers to one question.
     *
     * Null is ordinary: a build can be triggered before the version is
     * composed, and §8.7.20 keeps a published version serving when a mount
     * is detached.
     */
    private function mountFor(ProjectVersion $version, Component $component): ?ComponentMount
    {
        return ComponentMount::query()
            ->where('project_version_id', $version->id)
            ->where('component_id', $component->id)
            ->first();
    }

    /**
     * Publish a reused build onto this version and settle the request.
     *
     * 🛑 The request settles `completed`, not `unchanged`. Something did
     * happen: this version was not published and now is. `unchanged` is
     * §8.5.2's "the inputs match what is ALREADY published here", and
     * reporting a first publish as `unchanged` would tell an operator
     * watching a new project that nothing had happened when their
     * documentation had just gone live.
     */
    private function publishReused(BuildRequest $request, ProjectVersion $version, Build $reused): Build
    {
        $this->publisher->publishExistingBuild($version, $reused);

        $request->forceFill([
            'state' => 'completed',
            'outcome_identifier' => 'completed.reused_existing_build',
            'build_id' => $reused->id,
        ])->save();

        Audit::record(
            action: 'build.reused',
            actorType: ActorType::System,
            organisationId: $version->organisation_id,
            subjectType: 'build',
            subjectId: $reused->id,
            payload: [
                'project_version' => Uuid::toText($version->id),
                'content_key' => $reused->content_key,
            ],
        );

        return $reused;
    }

    /** Create the build row, or null when §10.3's `inflight` index refuses. */
    private function openBuild(
        BuildRequest $request,
        ProjectVersion $version,
        Component $component,
        ComponentSource $source,
        BuildPlan $plan,
    ): ?Build {
        $buildId = Uuid::v7();

        try {
            $build = new Build;
            $build->forceFill([
                'id' => $buildId,
                'organisation_id' => $version->organisation_id,
                'project_version_id' => $version->id,
                'component_id' => $component->id,
                'component_source_id' => $source->id,
                'build_request_id' => $request->id,
                /*
                 * 🛑 §8.7.9's key, falling back to one derived from the
                 * build id when the plan pinned no commit.
                 *
                 * The fallback is not a shortcut: `content_key` is `UNIQUE`
                 * and `NOT NULL`, and a build that cannot be identified by
                 * its inputs must still have a key that collides with
                 * nothing. Deriving it from the build id gives exactly that
                 * — a key no other build can ever match, so an
                 * unidentifiable build is never reused rather than being
                 * reused by accident.
                 */
                'content_key' => $this->contentKeyFor($version, $component, $source, $plan)
                    ?? hash('sha256', 'docup.build:'.bin2hex($buildId)),
                'plan_digest' => $plan->digestBytes(),
                'env_digest' => $plan->envDigest,
                'pipeline_version' => $plan->pipelineVersion,
                'kind' => 'full',
                'state' => 'running',
                'queued_at' => now(),
                'started_at' => now(),
            ])->save();

            return $build;
        } catch (QueryException $collision) {
            // 1062 is the unique-constraint violation. Any other query error
            // is not ours to interpret as "already in flight".
            if (! str_contains($collision->getMessage(), '1062')) {
                throw $collision;
            }

            return null;
        }
    }

    private function recordPlan(Build $build, BuildPlan $plan, ComponentSource $source, Repository $repository): void
    {
        foreach ($plan->sources as $pinned) {
            $row = new BuildSource;
            $row->forceFill([
                'organisation_id' => $build->organisation_id,
                'build_id' => $build->id,
                'component_source_id' => $source->id,
                'repository_id' => $repository->id,
                'ref' => $pinned['ref'],
                'commit_sha' => $pinned['commit_sha'],
                'source_path' => $pinned['source_path'],
            ])->save();
        }

        $build->forceFill(['commit_sha' => $plan->sources[0]['commit_sha']])->save();
    }

    /**
     * §8.5.7's credential-free fetch, as one or two runner jobs.
     *
     * 🛑 **Two passes, and §8.4.11 is the reason.** The `sparse` key decides
     * what to check out and lives inside the file being checked out, so the
     * only ordering in which a declarative sparse key can affect the build
     * that declares it is: clone without a working tree, read the four §8.4.1
     * candidates out of the object store, parse them **in this process**
     * (§8.4.9's "outside any sandbox"), then check out. The clone happens
     * once; the second pass is a container start against the workspace the
     * first left behind.
     *
     * 🛑 **The pre-parse here cannot fail the build.** A configuration that
     * does not parse is a `validate_config` failure with its own identifier
     * and its own step row; swallowing it here and letting that stage say so
     * is what keeps `fetch` a statement about the source and nothing else.
     */
    private function fetch(
        Build $build,
        Repository $repository,
        ComponentSource $source,
        string $commitSha,
        string $ref,
        ?int $waitSeconds,
    ): RunOutcome {
        $probe = $this->fetchPass($build, $repository, $source, $ref, 'probe', [], $waitSeconds);

        $sparse = $this->sparsePatternsFrom($probe);

        $outcome = $this->fetchPass($build, $repository, $source, $ref, 'checkout', $sparse, $waitSeconds);

        if ($sparse !== []) {
            $this->narrate('sparse checkout: '.implode(' ', $sparse).' (§8.4.11)');
        }

        $this->recordFetchFacts($build, $outcome, $commitSha);

        return $outcome;
    }

    /**
     * §8.4.11's patterns, from a configuration nothing has validated yet.
     *
     * Deliberately forgiving: anything that is not a clean parse yielding a
     * `sparse` list means no narrowing, and `validate_config` will report
     * whatever was actually wrong. The one thing this must not do is throw.
     *
     * @return list<string>
     */
    private function sparsePatternsFrom(RunOutcome $probe): array
    {
        $bytes = $this->configBytesFrom($probe);

        if ($bytes === null) {
            return [];
        }

        try {
            return ConfigParser::parse($bytes, 'probe')->sparse();
        } catch (ConfigRefused) {
            return [];
        }
    }

    /** The configuration file's bytes as the fetcher carried them, or null. */
    private function configBytesFrom(RunOutcome $outcome): ?string
    {
        $encoded = $outcome->facts['config_b64'] ?? null;

        if (! is_string($encoded) || $encoded === '') {
            return null;
        }

        $decoded = base64_decode($encoded, true);

        return $decoded === false ? null : $decoded;
    }

    /**
     * One pass of the fetcher.
     *
     * @param  list<string>  $sparse
     */
    private function fetchPass(
        Build $build,
        Repository $repository,
        ComponentSource $source,
        string $ref,
        string $mode,
        array $sparse,
        ?int $waitSeconds,
    ): RunOutcome {
        $buildId = bin2hex($build->id);

        $spec = new RunSpecification(
            buildId: $buildId,
            stage: Stage::Fetch,
            imageKey: 'fetch',
            /*
             * 🛑 `.` rather than `''` for a component at the repository root.
             * `RunSpecification` refuses an empty argv element — rightly, an
             * empty argument is almost always a bug and occasionally an
             * injection — so the empty source path is spelled as the
             * directory it means. Found by the credential-isolation test,
             * which uses a root-level component where the end-to-end test
             * uses a sub-path; the pipeline would have thrown on the first
             * repository whose documentation lives at the top level.
             */
            command: [
                $repository->clone_url,
                $ref,
                '/workspace/source',
                $source->source_path === '' ? '.' : $source->source_path,
                $mode,
                ...$sparse,
            ],
            environment: [],
            volume: BuildConfig::string('volume_prefix', 'docup-build-').$buildId,
            workdir: '/workspace',
            timeoutSeconds: Stage::Fetch->timeoutSeconds(),

            /*
             * 🛑 `fetch` is the one stage that cannot work without egress,
             * so it takes the §8.5.9 allowlist even where the installation
             * has narrowed the build stage to `none`. The git hosts are on
             * the same allowlist as the package indexes and the clone goes
             * through the same CONNECT tunnel — verified on all five
             * providers in ADR 0011, with the filter honoured.
             */
            egress: $this->policy->egressFor(Stage::Fetch),
            acceptsStdin: true,

            /*
             * 🛑 The two §8.4.11 passes get two job identifiers. Sharing one
             * meant the second pass read the first's leftover result the
             * moment it was submitted and returned it as its own — so the
             * checkout never ran, the worktree stayed empty, and the
             * generator failed on a missing configuration file that looked
             * exactly like the author's mistake. See
             * {@see RunSpecification::$pass}.
             */
            pass: $mode,
        );

        $outcome = $this->dispatch($spec, $this->credentialFor($repository, $build), $waitSeconds);

        if (! $outcome->succeeded()) {
            /*
             * 🛑 §8.4.11: exit 64 is the fetcher saying sparse checkout was
             * requested and narrowed nothing — "MUST fail loudly rather than
             * silently falling back to a full clone". Classed `config`
             * rather than `source`, because the patterns came from the
             * author's file and the author is who can fix it.
             */
            if ($outcome->exitCode === 64) {
                throw BuildFailure::of(
                    FailureClass::Config,
                    ConfigRejection::SparseCheckoutFailed->value,
                    Stage::Fetch,
                    $outcome->exitCode,
                );
            }

            throw BuildFailure::of(
                FailureClass::tryFrom((string) $outcome->failureClass) ?? FailureClass::Source,
                $outcome->failureReason ?? 'clone_failed',
                Stage::Fetch,
                $outcome->exitCode,
            );
        }

        return $outcome;
    }

    /**
     * ADR 0010 / §18.14's "filter honoured" flag, and §8.5.1's pin check.
     *
     * 🛑 The SHA the fetcher actually checked out is compared against the one
     * `plan` pinned. They can differ — the branch moved between the
     * advertisement and the clone, which is an ordinary race on an active
     * repository — and a build that silently used a different commit from the
     * one its plan digest describes would make the digest a lie.
     */
    private function recordFetchFacts(Build $build, RunOutcome $outcome, string $plannedSha): void
    {
        $source = BuildSource::query()->where('build_id', $build->id)->first();

        if (! $source instanceof BuildSource) {
            return;
        }

        $facts = $outcome->facts;

        $source->forceFill([
            'filter_honoured' => isset($facts['filter_honoured']) ? (bool) $facts['filter_honoured'] : null,
            'partial_clone_filter' => is_string($facts['partial_clone_filter'] ?? null) ? $facts['partial_clone_filter'] : null,
            'shallow' => isset($facts['shallow']) ? (bool) $facts['shallow'] : null,
            'worktree_files' => is_int($facts['worktree_files'] ?? null) ? $facts['worktree_files'] : null,
            'fetched_bytes' => is_int($facts['fetched_bytes'] ?? null) ? $facts['fetched_bytes'] : null,
        ])->save();

        $actual = is_string($facts['commit_sha'] ?? null) ? $facts['commit_sha'] : null;

        if ($actual !== null && $actual !== $plannedSha) {
            throw BuildFailure::of(FailureClass::Source, 'ref_moved_during_fetch', Stage::Fetch);
        }
    }

    /**
     * §8.4.9's configuration read, outside any sandbox and under hard caps.
     *
     * > "The system MUST parse configuration **outside any sandbox** under
     * > hard caps: ≤256 KiB, nesting depth ≤32, YAML aliases disabled, single
     * > document, validated against a published JSON Schema."
     *
     * 🛑 **This method runs in the worker, which holds the database
     * credentials and the `APP_KEY`, and that is the specified place.**
     * {@see Stage::executesRepositoryCode()} answers false for this stage:
     * a YAML parser is not an execution engine, and the caps are what make
     * the statement true rather than hopeful — {@see YamlGate}
     * refuses the bytes before {@see ConfigParser} builds anything from them.
     *
     * Returns the resolved §11.4 toolchain, because every stage after this
     * one is a function of it.
     *
     * @throws BuildFailure
     */
    private function validateConfig(
        Build $build,
        RunOutcome $fetch,
        BuildPlan $plan,
        Repository $repository,
    ): ToolchainPlan {
        $digest = is_string($fetch->facts['config_digest'] ?? null)
            ? $fetch->facts['config_digest']
            : hash('sha256', '');

        /*
         * 🛑 The plan digest is **re-stored** here, now that the config
         * digest exists. §8.5.2's formula includes `config_digest`, and the
         * digest written at `plan` could not have — the configuration file
         * lives in the repository at a commit that had not been fetched yet.
         *
         * Without this the stored digest is a different number from the one
         * {@see isUnchanged()} computes for an identical later trigger, so
         * the short-circuit never fires and every rebuild of unchanged
         * inputs runs a container. Found by the test that asserts a second
         * trigger is `unchanged`, which is the only way this was ever going
         * to show up: the first build looks perfect either way.
         */
        $complete = new BuildPlan(
            versionId: $plan->versionId,
            sources: $plan->sources,
            configDigest: $digest,
            envDigest: $plan->envDigest,
            pipelineVersion: $plan->pipelineVersion,
        );

        $build->forceFill([
            'config_digest' => $digest,
            'plan_digest' => $complete->digestBytes(),
        ])->save();

        try {
            return $this->resolveToolchain($build, $fetch, $plan, $repository);
        } catch (ConfigRefused $refused) {
            /*
             * 🛑 The author reads the sentence, the operator's alert reads
             * the identifier, and neither reads the other's. `userMessage()`
             * appends the offending key — a key, never a value, because the
             * message goes into a log whose redaction has not yet seen this
             * file (see {@see ConfigRefused}).
             */
            $this->narrate($refused->userMessage());

            throw BuildFailure::of(
                FailureClass::Config,
                $refused->rejection->value,
                Stage::ValidateConfig,
            );
        }
    }

    /**
     * The §8.4 file, the §11.4 preset and the two scripts.
     *
     * @throws ConfigRefused
     */
    private function resolveToolchain(
        Build $build,
        RunOutcome $fetch,
        BuildPlan $plan,
        Repository $repository,
    ): ToolchainPlan {
        if (($fetch->facts['config_oversize'] ?? null) === true) {
            // The fetcher refused to read it, so there are no bytes to
            // refuse here; the cap is §8.4.9's and the identifier is the
            // same one `YamlGate` would have produced.
            throw ConfigRefused::of(ConfigRejection::TooLarge, 'over '.ConfigRejection::MAX_BYTES.' bytes');
        }

        $bytes = $this->configBytesFrom($fetch);
        $filename = is_string($fetch->facts['config_file'] ?? null) ? $fetch->facts['config_file'] : '';

        $config = $bytes === null || $filename === ''
            ? DocupConfig::absent()
            : ConfigParser::parse($bytes, $filename);

        if ($config->isPresent()) {
            $this->narrate('configuration: '.$filename
                .(ConfigDiscovery::isCompatibilityName($filename) ? ' (Read the Docs compatibility name, §20.5)' : ''));
        }

        /*
         * 🛑 §8.5.14: images are pre-baked and a build container has no
         * capabilities and a read-only root, so `build.apt_packages` cannot
         * be installed by anybody. Said at the TOP of the log rather than
         * left for the generator to fail over a missing binary thirty
         * seconds later — §8.4.2 preserves the key for compatibility, and
         * refusing the build outright would reject a great many repositories
         * that list packages they do not actually need.
         */
        if ($config->aptPackages() !== []) {
            $this->narrate(
                'build.apt_packages is accepted but NOT installed: build images are pre-baked (§8.5.14) '
                .'and run with no capabilities, so no package manager can run inside one. Listed: '
                .implode(', ', $config->aptPackages()),
            );
        }

        $component = $build->component;

        $toolchain = ToolchainPlan::resolve(
            config: $config,
            sourcePath: $plan->sources[0]['source_path'],
            presentFiles: $this->filesFrom($fetch),
            htmlContext: HtmlContext::fromCloneUrl(
                $repository->clone_url,
                $plan->sources[0]['ref'],
                dirname('/'.ltrim((string) $config->generatorConfiguration(
                    $config->declaredToolchain() ?? 'mkdocs',
                ), '/')),
            ),
            semantics: ShellSemantics::fromStored($component?->shell_semantics),
        );

        $this->narrate('toolchain: '.$toolchain->preset->name
            .($config->declaredToolchain() === null && ! $config->hasCommands()
                ? ' (inferred from the checkout; name it with `toolchain: '.$toolchain->preset->key.'` to be explicit)'
                : '')
            .($toolchain->semantics === ShellSemantics::Legacy
                ? ' — 🛑 legacy shell semantics: a failing command will NOT fail the build (§8.4.10)'
                : ''));

        $this->recordDeclaredNavigation($build, $config);

        return $toolchain;
    }

    /**
     * §8.7.6's first nav source: the repository's own `nav:` declaration.
     *
     * > "lifted from `.docup.yaml` `nav:` or the generator's own output"
     *
     * Stored on the build row because this is the only place in the system
     * that holds the parsed configuration — §8.4.9 puts the parse in the
     * worker, outside any sandbox, and the generator never sees the result.
     * The alternative sources land in the artifact at `nav/nav.json`,
     * written by the preset inside the sandbox; the composition planner
     * prefers this one, which is what makes §8.7.6's "or" an ordering.
     *
     * 🛑 Stored **raw**, exactly as the author wrote it. Normalising here
     * would put the trust boundary in two places, and
     * {@see NavFragment} is the one that reads
     * both sources.
     */
    private function recordDeclaredNavigation(Build $build, DocupConfig $config): void
    {
        $nav = $config->nav();

        if ($nav === []) {
            return;
        }

        $build->forceFill(['nav_json' => $nav])->save();

        $this->narrate('navigation: '.count($nav).' top-level entries declared in `nav:` (§8.7.6)');
    }

    /**
     * The shallow file list the fetcher reported, for preset detection.
     *
     * @return list<string>
     */
    private function filesFrom(RunOutcome $fetch): array
    {
        $files = [];

        foreach (is_array($fetch->facts['files'] ?? null) ? $fetch->facts['files'] : [] as $file) {
            if (is_string($file)) {
                $files[] = $file;
            }
        }

        return $files;
    }

    /**
     * §8.5.19's digest for this build.
     *
     * 🛑 The repository is not an input — it is the lookup scope, and
     * {@see FragmentDigest} explains why that
     * distinction is kept visible rather than folded into a hash.
     */
    private function fragmentFor(
        BuildPlan $plan,
        ToolchainPlan $toolchain,
        ComponentEnvironment $variables,
    ): FragmentDigest {
        $image = BuildConfig::map('images')[$toolchain->preset->image] ?? [];
        $imageDigest = is_array($image) && is_string($image['digest'] ?? null) ? $image['digest'] : null;

        return new FragmentDigest(
            sourceDigest: FragmentDigest::sourceDigestFor(
                $plan->sources[0]['commit_sha'],
                $plan->sources[0]['source_path'],
            ),
            envDigest: FragmentDigest::envDigestFor(
                $toolchain->preset->image,
                $imageDigest,
                $toolchain->preset->key,
            ),
            configDigest: FragmentDigest::configDigestFor(
                $toolchain->config->digest,
                $toolchain->semantics->value,
                'agnostic',
                $toolchain->configuration,
            ),
            publicEnv: $variables->public,

            /*
             * 🛑 §8.7.11's prefix, taken from the environment that was
             * actually resolved for this build — the same value the
             * container sees and the same one §8.7.9's content key uses.
             *
             * Reading it from `$this->baseEnvironment` rather than
             * recomputing it is the point: three places deciding whether
             * a prefix applies is two chances for the digest to describe a
             * build that did not happen.
             */
            basePath: $this->baseEnvironment?->basePath,
        );
    }

    /**
     * §8.5.6's `environment` stage: install what the build needs.
     *
     * 🛑 Skipped rather than run empty when there is nothing to install.
     * Phase 06 recorded `skipped.toolchain_prebaked` here and that was
     * honest; a preset with no install step and a repository with no
     * `python.install` and no hooks is still that case, and a container
     * started to run `true` is a second of every build spent proving it.
     *
     * @param  array<string, BuildStep>  $steps
     */
    private function runEnvironmentStage(
        StepRecorder $recorder,
        array $steps,
        Build $build,
        ToolchainPlan $toolchain,
        ComponentEnvironment $variables,
        ?int $waitSeconds,
    ): void {
        $script = $toolchain->environmentScript();

        if ($script === null) {
            $recorder->skip($steps[Stage::Environment->value], 'skipped.nothing_to_install');

            return;
        }

        $this->stage($recorder, $steps, Stage::Environment, fn (): RunOutcome => $this->environment(
            $build,
            $toolchain,
            $variables,
            $script,
            $waitSeconds,
        ));
    }

    /** The install, with the §8.5.9 allowlist and no credentials. */
    private function environment(
        Build $build,
        ToolchainPlan $toolchain,
        ComponentEnvironment $variables,
        string $script,
        ?int $waitSeconds,
    ): RunOutcome {
        $buildId = bin2hex($build->id);

        $spec = new RunSpecification(
            buildId: $buildId,
            stage: Stage::Environment,
            imageKey: $toolchain->preset->image,
            command: [],
            environment: array_merge(
                $this->containerEnvironment($toolchain),
                $variables->forStage(Stage::Environment),
            ),
            volume: BuildConfig::string('volume_prefix', 'docup-build-').$buildId,
            workdir: $toolchain->sourceDir,
            timeoutSeconds: Stage::Environment->timeoutSeconds(),
            egress: $this->policy->egressFor(Stage::Environment),
            script: $script,
            shell: $toolchain->semantics->shell(),
        );

        $outcome = $this->dispatch($spec, null, $waitSeconds);

        if (! $outcome->succeeded()) {
            throw BuildFailure::of(
                FailureClass::tryFrom((string) $outcome->failureClass) ?? FailureClass::User,
                $outcome->failureReason ?? 'dependency_install_failed',
                Stage::Environment,
                $outcome->exitCode,
            );
        }

        return $outcome;
    }

    /**
     * §8.4.6's scoped variables plus §8.4.7's `html_context`, for a container.
     *
     * @return array<string, string>
     */
    private function containerEnvironment(ToolchainPlan $toolchain): array
    {
        $base = $this->baseEnvironment ?? throw new \LogicException(
            'the build environment is resolved in run(), before any container stage',
        );

        return array_merge($base->forContainer(), $toolchain->environment());
    }

    /**
     * §8.4.6's scoped variables for this build, resolved once.
     *
     * 🛑 The clone URL is stripped of userinfo before it goes anywhere near
     * a container. `READTHEDOCS_GIT_CLONE_URL` is read by `conf.py` files
     * and printed into build logs, and an operator's `https://x:TOKEN@host/…`
     * remote would be in both.
     */
    private function resolveBaseEnvironment(
        Component $component,
        Repository $repository,
        BuildPlan $plan,
        ?ComponentMount $mount = null,
    ): void {
        $this->baseEnvironment = new BuildEnvironment(
            productionDomain: is_string(config('docup.origins.docs')) ? config('docup.origins.docs') : '',
            componentKey: $component->key,
            cloneUrl: self::withoutUserinfo($repository->clone_url),
            refIdentifier: $plan->sources[0]['ref'],
            commitSha: $plan->sources[0]['commit_sha'],
            versionLabel: $plan->sources[0]['ref'],

            /*
             * 🛑 §8.7.11's `$DOCUP_BASE_PATH`, from the same function that
             * decides whether the mount path enters §8.7.9's content key.
             *
             * One function for both, because the two must agree exactly: a
             * build that saw the path and did not put it in the key would
             * be shared across mounts it cannot serve, and a build that put
             * it in the key and did not export it would be unshared for no
             * benefit. `ContentKey::mountPathFor()` returning null means
             * neither happens.
             */
            basePath: ContentKey::mountPathFor($mount, $component),
        );
    }

    /** `https://user:pass@host/x` becomes `https://host/x`. */
    private static function withoutUserinfo(string $url): string
    {
        return (string) preg_replace('#^([a-z][a-z0-9+.-]*://)[^/@]*@#i', '$1', $url);
    }

    /**
     * Rebuild a cached fragment's tree into an archive the §8.21.6 path can
     * ingest.
     *
     * 🛑 Through `PublishSource`, not around it. §8.21.6: "The built-in
     * runner MUST be implemented as the **first consumer** of this path, not
     * a privileged special case." A cache hit that wrote into the store
     * directly would be exactly the second, privileged route that
     * requirement exists to forbid — and it would skip the §8.8.2
     * validations and the §8.4.5 contract check with it.
     */
    private function rehydrate(Build $cached, string $buildHex): string
    {
        $store = app(ArtifactStore::class);

        // The RAW 16 bytes, not the hex. `prefixFor()` renders canonical
        // UUID text and is ADR 0006's presentation boundary; handing it hex
        // throws rather than producing a wrong key, which is the right way
        // round but still a thing to get right at the call site.
        $prefix = $store->prefixFor($cached->id);
        $keys = $store->list($prefix);

        if ($keys === []) {
            throw BuildFailure::of(FailureClass::Infra, 'fragment_artifacts_missing', Stage::Collect);
        }

        $path = $this->spool->output($buildHex.'-build');
        $entries = [];

        foreach ($keys as $key) {
            $relative = ltrim(substr($key, strlen($prefix)), '/');

            /*
             * Only the published tree. The cached build's own manifest and
             * provenance are facts about *that* build and are re-emitted for
             * this one by the ingest — copying them would attribute this
             * build's output to the other build's plan.
             */
            if (! str_starts_with($relative, 'html/')) {
                continue;
            }

            $contents = $store->get($key);

            if ($contents !== null) {
                $entries[$relative] = $contents;
            }
        }

        ksort($entries);

        TarArchiveWriter::write($path, $entries);

        $this->narrate('reused '.count($entries).' files from the cached fragment');

        return $path;
    }

    /** The generator, with no network and no credentials. */
    private function build(
        Build $build,
        Component $component,
        Repository $repository,
        BuildPlan $plan,
        ToolchainPlan $toolchain,
        ComponentEnvironment $variables,
        ?int $waitSeconds,
    ): RunOutcome {
        $buildId = bin2hex($build->id);

        $spec = new RunSpecification(
            buildId: $buildId,
            stage: Stage::Build,

            /*
             * 🛑 Still a KEY into §8.5.14's allowlist, and still never a
             * reference. Phase 06 hard-coded `mkdocs`; the preset now
             * chooses, and `ToolchainPresets` only loads from the shipped
             * directory — so "a new generator is a data file" (§11.4) has
             * not become "a new image is a YAML value".
             */
            imageKey: $toolchain->preset->image,

            // Empty: the commands are in the script file the runner writes.
            command: [],

            // 🛑 §8.7.10: the project scope is absent, not empty.
            environment: array_merge(
                $this->containerEnvironment($toolchain),
                $variables->forStage(Stage::Build),
            ),
            volume: BuildConfig::string('volume_prefix', 'docup-build-').$buildId,
            workdir: $toolchain->sourceDir,
            timeoutSeconds: Stage::Build->timeoutSeconds(),

            /*
             * §8.5.9's allowlist, which Phase 07 built. Phase 06 gave the
             * generator no network at all because an allowlist that did not
             * exist must not be approximated by leaving the network open;
             * now it exists, the generator gets the mode the operator
             * declared, and `none` remains a supported — stricter — choice.
             */
            egress: $this->policy->egressFor(Stage::Build),
            exportPath: BuildEnvironment::OUTPUT_PATH,
            releaseWorkspace: true,
            script: $toolchain->buildScript(),
            shell: $toolchain->semantics->shell(),
        );

        $outcome = $this->dispatch($spec, null, $waitSeconds);

        if (! $outcome->succeeded()) {
            throw BuildFailure::of(
                FailureClass::tryFrom((string) $outcome->failureClass) ?? FailureClass::User,
                $outcome->failureReason ?? 'build_command_failed',
                Stage::Build,
                $outcome->exitCode,
            );
        }

        return $outcome;
    }

    /** §8.21.6: the runner publishes through the upload path, not beside it. */
    private function publish(
        Build $build,
        ProjectVersion $version,
        string $archive,
        BuildRequest $request,
        BuildPlan $plan,
    ): PublishOutcome {
        $source = new RunnerArtifact(
            archivePath: $archive,
            version: $version,
            actorId: is_string($request->requested_by) ? $request->requested_by : null,
            provenance: $plan->toArray(),
        );

        return $this->publisher->publishFrom($source, $build);
    }

    /**
     * Submit to the runner and wait.
     *
     * 🛑 The runner is a separate process with no database, so "wait" is a
     * poll of the spool rather than anything cleverer. The lease on the step
     * row is what makes the wait safe: if this worker dies while waiting, the
     * step is reclaimed rather than left running for ever.
     */
    private function dispatch(RunSpecification $spec, ?string $credential, ?int $waitSeconds): RunOutcome
    {
        /*
         * 🛑 The channel is opened before the job is published, and closed
         * however this method leaves. A runner that claimed the job first
         * would find no socket and fetch anonymously — for a private
         * repository that is an authentication failure reported as a
         * missing ref, which is the least useful true thing we could say.
         */
        $channel = $credential === null
            ? null
            : $this->spool->openCredentialChannel($this->spool->jobId($spec), $credential);

        try {
            $jobId = $this->spool->submit($spec);
            $deadline = microtime(true) + ($waitSeconds ?? ($spec->timeoutSeconds + 120));
            $ingested = 0;

            while (microtime(true) < $deadline) {
                /*
                 * The credential hand-over rides in the loop that was
                 * already here. `serveOnce()` is a non-blocking accept, so
                 * this costs one syscall per tick and cannot stall the
                 * wait — which is the whole reason a unix socket works
                 * where §8.5.7's FIFO deadlocked (see `CredentialChannel`).
                 */
                $channel?->serveOnce();

                /*
                 * 🛑 §8.5.21's "stream build logs line by line", from this
                 * side. The runner appends to a file in the spool as it
                 * reads the container; this pulls whatever is new, redacts
                 * it against the FULL secret list — which only this side
                 * has — and appends it to the log an API will serve. Five
                 * times a second, in the loop that was already waiting.
                 */
                $ingested = $this->ingestLiveLog($jobId, $ingested);

                $this->relayCancellation($jobId);

                $result = $this->spool->readResult($jobId);

                if ($result !== null) {
                    $this->ingestLiveLog($jobId, $ingested);

                    return $result;
                }

                usleep(200_000);
            }
        } finally {
            $channel?->close();
        }

        throw BuildFailure::of(FailureClass::Infra, 'runner_did_not_answer', $spec->stage);
    }

    /**
     * Pull new lines out of the runner's live file into the build log.
     *
     * 🛑 **Redaction happens on this side of the spool**, because this is
     * the side that knows every secret (§8.5.21: "before persistence or
     * broadcast"). The runner scrubs the one credential it was handed;
     * everything else — a component's environment secret, a token the
     * vault opened for another stage — is known only here.
     *
     * Returns how many of the runner's lines have been consumed, so the
     * next pass starts where this one stopped. Counting the runner's own
     * sequence rather than a byte offset means a partially written final
     * line is simply skipped and picked up whole next time.
     */
    private function ingestLiveLog(string $jobId, int $consumed): int
    {
        if (! $this->log instanceof BuildLog) {
            return $consumed;
        }

        $handle = @fopen($this->spool->liveLog($jobId), 'rb');

        if ($handle === false) {
            return $consumed;
        }

        $appended = false;

        try {
            while (($raw = fgets($handle)) !== false) {
                $line = LogLine::decode($raw);

                if ($line === null || $line->seq <= $consumed) {
                    continue;
                }

                $this->log->append($line->text, $line->stream);
                $consumed = $line->seq;
                $appended = true;
            }
        } finally {
            fclose($handle);
        }

        /*
         * 🛑 §8.5.22's optional WebSocket profile, broadcast ONCE PER
         * TICK rather than once per line. A chatty build produces tens of
         * thousands of lines and a listener needs to know that there is
         * more, not how much — and an event per line would make the
         * optional profile the most expensive thing in the pipeline.
         *
         * Under the default `null` connection this is a no-op, which is
         * what keeps the profile optional (§19/22).
         */
        if ($appended && $this->running instanceof Build) {
            BuildLogAppended::dispatch(
                bin2hex($this->running->id),
                $this->log->lineCount() + 1,
                false,
            );
        }

        return $consumed;
    }

    /**
     * §8.5.23: carry a cancellation request across to the runner.
     *
     * 🛑 The worker is the only process that can see both halves — the
     * `builds` row a dashboard wrote to and the spool the runner reads —
     * so the relay belongs here. It is one indexed read per 200 ms tick
     * against a row already in memory's reach, which is the price of
     * "within 5 seconds" without giving the runner a database.
     */
    private function relayCancellation(string $jobId): void
    {
        if (! $this->running instanceof Build || $this->spool->cancelRequested($jobId)) {
            return;
        }

        $requested = DB::table('builds')->where('id', $this->running->id)->value('cancel_requested_at');

        if ($requested !== null) {
            $this->spool->requestCancel($jobId);
            $this->narrate('cancellation requested — stopping the container');
        }
    }

    /**
     * §8.5.5's admission, and §8.22.11's audit of an unsandboxed run.
     *
     * 🛑 The build is already in `running` by the time this stage executes —
     * §10.3's `inflight` index put it there, which is what stops a second
     * build for the same version existing at all. So admission here asks
     * the narrower question the index cannot: is there room at the
     * installation and organisation ceilings, and is this build next in the
     * fair order? A refusal leaves the build queued rather than failing it.
     *
     * @throws BuildFailure when the installation has no room right now
     */
    private function admit(Build $build): void
    {
        $decision = $this->dispatcher->admit($build);

        if (! $decision->admitted && $decision->reason !== 'admission.not_queued') {
            /*
             * `conflict` rather than `rejected`: the build is legitimate and
             * will run, which is what §8.5.15's `conflict` class means and
             * what makes it safe to retrigger. A `rejected` build is one
             * that could never have run.
             */
            throw BuildFailure::of(FailureClass::Conflict, 'queued_behind_capacity', Stage::Admit);
        }

        /*
         * 🛑 §8.5.11's "writes an audit event", recorded per BUILD rather
         * than per boot. A boot event would be written once by whoever
         * restarted the service and never again; what an auditor actually
         * needs to answer later is "which builds ran with the kernel shared
         * and the network open", and that is one row per build.
         */
        if ($this->policy->requiresUnsandboxedAudit()) {
            Audit::record(
                action: 'build.admitted_unsandboxed',
                actorType: ActorType::System,
                organisationId: $build->organisation_id,
                subjectType: 'build',
                subjectId: $build->id,
                payload: [
                    'isolation' => $this->policy->isolation,
                    'egress' => $this->policy->egress->value,
                    'flag' => 'DOCUP_ACKNOWLEDGE_UNSANDBOXED',
                ],
            );
        }
    }

    /**
     * The credential-helper body for a private repository, or null.
     *
     * 🛑 Opened here and handed straight to the spool's FIFO. It is never
     * assigned to a property, never logged, and never written to a file by
     * this process — §8.5.7's "never argv, never the remote URL, never the
     * environment" plus the obvious fourth, never at rest.
     */
    private function credentialFor(Repository $repository, Build $build): ?string
    {
        /*
         * 🛑 §8.5.10, as the second of two independent controls: "Fork and
         * pull-request builds MUST receive **no secrets at all**."
         *
         * `run()` already refuses a fork build the project has not opted
         * in to. This one applies to the builds that WERE opted in to —
         * a project may accept fork builds and still never hand a fork's
         * code the organisation's git credential, which is the whole point
         * of the opt-in being survivable. Two controls rather than one,
         * because the refusal and the withholding fail differently and
         * neither should be the only thing standing there.
         */
        if ($build->buildRequest?->from_fork === true) {
            return null;
        }

        $credential = $repository->credential;

        if ($credential === null) {
            return null;
        }

        $opened = $this->vault->open($credential);

        $username = isset($opened['username']) ? $opened['username']->reveal() : 'x-access-token';
        $secret = $opened['token'] ?? $opened['access_token'] ?? null;

        if ($secret === null) {
            return null;
        }

        return "username={$username}\npassword={$secret->reveal()}\n";
    }

    private function refFor(ComponentSource $source, Repository $repository): string
    {
        if (is_string($repository->default_branch) && $repository->default_branch !== '') {
            return $repository->default_branch;
        }

        return $this->refs->defaultBranch($repository->clone_url)
            ?? throw BuildFailure::of(FailureClass::Source, 'no_default_branch', Stage::Plan);
    }

    private function componentFor(BuildRequest $request, ProjectVersion $version): ?Component
    {
        if (is_string($request->component_id)) {
            return Component::query()->find($request->component_id);
        }

        $mount = $version->mounts()->where('is_primary', true)->first();

        return $mount?->component;
    }

    /**
     * Run one stage under its step row.
     *
     * @template T
     *
     * @param  array<string, BuildStep>  $steps
     * @param  \Closure(): T  $work
     * @return T
     *
     * @throws BuildFailure
     */
    private function stage(StepRecorder $recorder, array $steps, Stage $stage, \Closure $work): mixed
    {
        $step = $steps[$stage->value];

        if ($recorder->claim($step) === null) {
            throw BuildFailure::of(FailureClass::Conflict, 'step_claimed_elsewhere', $stage);
        }

        $this->narrate($stage->value.': started');

        try {
            $result = $work();
        } catch (BuildFailure $failure) {
            $recorder->fail($step, $failure);
            $this->narrate($stage->value.': '.$failure->identifier().' — '.$failure->userMessage());

            throw $failure;
        } catch (\Throwable $unexpected) {
            $failure = BuildFailure::of(FailureClass::Infra, 'unexpected_error', $stage);
            $recorder->fail($step, $failure);

            logger()->error('build stage failed unexpectedly', [
                'stage' => $stage->value,
                // §8.5.21: the scrubber runs before anything is persisted.
                'error' => $this->redactor->scrub($unexpected->getMessage()),
            ]);

            throw $failure;
        }

        $recorder->succeed($step);
        $this->narrate($stage->value.': ok');

        return $result;
    }

    /**
     * The pipeline speaking for itself, on the `docup` stream.
     *
     * 🛑 Stage boundaries belong in the log an author reads, not only in
     * the step rows. A build that failed at `collect` reads very
     * differently from one that failed at `build`, and a reader scrolling
     * ten thousand lines of generator output has no other way to tell
     * where one ended and the next began.
     */
    private function narrate(string $text): void
    {
        $this->log?->append($text, 'docup');
    }

    /** @param  array<string, BuildStep>  $steps */
    private function failBuild(
        Build $build,
        BuildRequest $request,
        BuildFailure $failure,
        StepRecorder $recorder,
        array $steps,
    ): void {
        foreach ($steps as $step) {
            if ($step->fresh()?->state === 'pending') {
                $recorder->skip($step, 'skipped.earlier_stage_failed');
            }
        }

        $build->forceFill(array_merge($failure->columns(), [
            'state' => 'failed',
            'finished_at' => now(),
        ]))->save();

        $request->forceFill([
            'state' => 'failed',
            'outcome_identifier' => $failure->identifier(),
            'build_id' => $build->id,
        ])->save();

        Audit::record(
            action: 'build.failed',
            actorType: ActorType::System,
            organisationId: $build->organisation_id,
            subjectType: 'build',
            subjectId: $build->id,
            payload: ['failure' => $failure->identifier()],
        );
    }
}
