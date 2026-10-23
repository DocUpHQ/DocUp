<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds;

use App\Artifacts\Publisher;
use App\Artifacts\PublishOutcome;
use App\Audit\ActorType;
use App\Audit\Audit;
use App\Builds\Runner\RunOutcome;
use App\Builds\Runner\Spool;
use App\Credentials\CredentialVault;
use App\Credentials\SecretRedactor;
use App\Models\Build;
use App\Models\BuildRequest;
use App\Models\BuildSource;
use App\Models\BuildStep;
use App\Models\Component;
use App\Models\ComponentSource;
use App\Models\ProjectVersion;
use App\Models\Repository;
use App\Support\Uuid;
use Illuminate\Database\QueryException;

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
    ) {}

    /**
     * Take a request to a terminal state.
     *
     * Returns the build, or null when the request settled without one — which
     * §8.5.2 and §8.5.4 both require to be possible and neither treats as a
     * failure.
     */
    public function run(BuildRequest $request, ?int $waitSeconds = null): ?Build
    {
        $version = $request->version;

        if (! $version instanceof ProjectVersion) {
            $request->settle('rejected', 'rejected.version_missing');

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

        $build = $this->openBuild($request, $version, $component, $source, $plan);

        if ($build === null) {
            // The §10.3 `inflight` unique index refused: another build for
            // this version is already queued or running. §8.5.4's fourth
            // deduplication layer, enforced by the database rather than by a
            // check that two jobs in one batch would both pass.
            $request->settle('superseded', 'superseded.build_already_in_flight');

            return null;
        }

        $steps = (new StepRecorder('pipeline'))->createPipeline($build);
        $recorder = StepRecorder::forThisProcess();

        // One conversion, used everywhere the spool is addressed. The run
        // specification is built from the same value, so the worker and the
        // runner cannot disagree about a job's name.
        $buildHex = bin2hex($build->id);

        try {
            $this->stage($recorder, $steps, Stage::Admit, fn () => null);

            // Recorded against the step that produced it, after the fact: the
            // work happened above, because its result decides whether there
            // is a build to record it against at all.
            $this->stage($recorder, $steps, Stage::Plan, function () use ($build, $plan, $source, $repository): void {
                $this->recordPlan($build, $plan, $source, $repository);
            });

            $fetch = $this->stage($recorder, $steps, Stage::Fetch, fn (): RunOutcome => $this->fetch(
                $build,
                $repository,
                $source,
                $plan->sources[0]['commit_sha'],
                $plan->sources[0]['ref'],
                $waitSeconds,
            ));

            $this->stage($recorder, $steps, Stage::ValidateConfig, function () use ($build, $fetch, $plan): void {
                $this->validateConfig($build, $fetch, $plan);
            });

            /*
             * 🛑 Skipped, honestly. §8.5.14 requires images to be pre-baked,
             * so in Phase 06 there is nothing to install and the stage has no
             * work — and `skipped` with a reason says that, where a green
             * `succeeded` would claim a dependency install happened. Phase 09's
             * `python.install` is what gives this stage something to do.
             */
            $recorder->skip($steps[Stage::Environment->value], 'skipped.toolchain_prebaked');

            $this->stage($recorder, $steps, Stage::Build, fn (): RunOutcome => $this->build(
                $build,
                $component,
                $repository,
                $plan,
                $waitSeconds,
            ));

            /*
             * 🛑 The HEX form, which is what the run specification carried.
             * `getRawOriginal('id')` is the raw 16 bytes (§9.1.1), and using
             * it here built a filename that could never match the one the
             * runner wrote — so a build that had succeeded and produced a
             * 2 MB tar was reported as `contract.no_output_directory`, which
             * is the one failure identifier guaranteed to send an author
             * looking at their own `mkdocs.yml`.
             */
            $archive = $this->spool->output($buildHex.'-build');

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

            $recorder->succeed($steps[Stage::Publish->value]);

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

            $request->forceFill(['state' => 'completed', 'build_id' => $build->id])->save();

            return $build->refresh();
        } catch (BuildFailure $failure) {
            $this->failBuild($build, $request, $failure, $recorder, $steps);

            return $build->refresh();
        } finally {
            $this->spool->discard($buildHex.'-fetch');
            $this->spool->discard($buildHex.'-build');
        }
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
                'content_key' => hash('sha256', 'docup.build:'.bin2hex($buildId)),
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

    /** §8.5.7's credential-free fetch, as a runner job. */
    private function fetch(
        Build $build,
        Repository $repository,
        ComponentSource $source,
        string $commitSha,
        string $ref,
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
            ],
            environment: [],
            volume: BuildConfig::string('volume_prefix', 'docup-build-').$buildId,
            workdir: '/workspace',
            timeoutSeconds: Stage::Fetch->timeoutSeconds(),
            networkEnabled: true,
            acceptsStdin: true,
        );

        $outcome = $this->dispatch($spec, $this->credentialFor($repository), $waitSeconds);

        if (! $outcome->succeeded()) {
            throw BuildFailure::of(
                FailureClass::tryFrom((string) $outcome->failureClass) ?? FailureClass::Source,
                $outcome->failureReason ?? 'clone_failed',
                Stage::Fetch,
                $outcome->exitCode,
            );
        }

        $this->recordFetchFacts($build, $outcome, $commitSha);

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
     * Phase 06 needs only enough to know the project is MkDocs and to digest
     * the file for §8.5.2; the full contract is §8.4 and arrives in Phase 09.
     * The fetcher reports what it found, so nothing here opens an archive or
     * runs a parser over attacker-controlled bytes beyond a bounded YAML read.
     */
    private function validateConfig(Build $build, RunOutcome $fetch, BuildPlan $plan): void
    {
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

        if (($fetch->facts['config_found'] ?? null) === false) {
            throw BuildFailure::of(FailureClass::Config, 'no_mkdocs_configuration', Stage::ValidateConfig);
        }
    }

    /** The generator, with no network and no credentials. */
    private function build(
        Build $build,
        Component $component,
        Repository $repository,
        BuildPlan $plan,
        ?int $waitSeconds,
    ): RunOutcome {
        $buildId = bin2hex($build->id);
        $sourcePath = trim($plan->sources[0]['source_path'], '/');
        $workdir = '/workspace/source'.($sourcePath === '' ? '' : '/'.$sourcePath);

        $environment = new BuildEnvironment(
            productionDomain: is_string(config('docup.origins.docs')) ? config('docup.origins.docs') : '',
            componentKey: $component->key,
            cloneUrl: $repository->clone_url,
            refIdentifier: $plan->sources[0]['ref'],
            commitSha: $plan->sources[0]['commit_sha'],
            versionLabel: $plan->sources[0]['ref'],
        );

        $spec = new RunSpecification(
            buildId: $buildId,
            stage: Stage::Build,
            imageKey: 'mkdocs',
            command: ['mkdocs', 'build', '--strict', '--site-dir', BuildEnvironment::OUTPUT_PATH.'/html'],

            // 🛑 §8.7.10: the project scope is absent, not empty.
            environment: $environment->forContainer(),
            volume: BuildConfig::string('volume_prefix', 'docup-build-').$buildId,
            workdir: $workdir,
            timeoutSeconds: Stage::Build->timeoutSeconds(),

            // 🛑 Phase 06 gives the generator no network at all. Stricter than
            // §8.5.9's allowlisted proxy, which arrives in Phase 07 — and an
            // allowlist that does not exist must not be approximated by
            // leaving the network open.
            networkEnabled: false,
            exportPath: BuildEnvironment::OUTPUT_PATH,
            releaseWorkspace: true,
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
        $jobId = $this->spool->submit($spec);

        if ($credential !== null) {
            $this->spool->writeCredential($jobId, $credential);
        }

        $deadline = microtime(true) + ($waitSeconds ?? ($spec->timeoutSeconds + 120));

        while (microtime(true) < $deadline) {
            $result = $this->spool->readResult($jobId);

            if ($result !== null) {
                return $result;
            }

            usleep(200_000);
        }

        throw BuildFailure::of(FailureClass::Infra, 'runner_did_not_answer', $spec->stage);
    }

    /**
     * The credential-helper body for a private repository, or null.
     *
     * 🛑 Opened here and handed straight to the spool's FIFO. It is never
     * assigned to a property, never logged, and never written to a file by
     * this process — §8.5.7's "never argv, never the remote URL, never the
     * environment" plus the obvious fourth, never at rest.
     */
    private function credentialFor(Repository $repository): ?string
    {
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

        try {
            $result = $work();
        } catch (BuildFailure $failure) {
            $recorder->fail($step, $failure);

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

        return $result;
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
