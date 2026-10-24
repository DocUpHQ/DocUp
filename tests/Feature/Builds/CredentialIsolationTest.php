<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Builds;

use App\Builds\Runner\DockerRunnerDriver;
use App\Builds\RunSpecification;
use App\Builds\Sandbox\EgressMode;
use App\Builds\Stage;
use Tests\Support\RequiresBuildImages;
use Tests\TestCase;

/**
 * 🛑 Phase 06's third exit criterion:
 *
 * > "`build.jobs.post_checkout` provably executes in the **build** sandbox,
 * > not the fetcher — a fixture that reads the credential environment finds
 * > nothing."
 *
 * §8.5.7 states the rule and names the precedent: "All user-defined hooks
 * **including `post_checkout`** MUST run in the build sandbox, never the
 * fetcher. Read the Docs runs `post_checkout` in the credentialed context;
 * doing so voids the entire credential separation."
 *
 * 🛑 **What this test is and is not.** `build.jobs` itself is §8.4.3 and
 * arrives with the configuration contract in Phase 09; Phase 06 ships no
 * parser for it. What Phase 06 does ship — and what the criterion actually
 * turns on — is the **boundary** that makes running a hook in the build
 * sandbox safe. So the fixture here is a command run in the build container
 * exactly as a `post_checkout` hook would be, searching every place a
 * credential could have been left. If it finds nothing, a hook running there
 * finds nothing.
 *
 * The test is skipped without the images and the Docker socket; as with
 * `EndToEndBuildTest`, `DOCUP_E2E=1` turns the skip into a failure.
 */
final class CredentialIsolationTest extends TestCase
{
    use RequiresBuildImages;

    private const CREDENTIAL = 'ghp_PHASE06SENTINELvalue0123456789abcd';

    private ?DockerRunnerDriver $driver = null;

    private ?string $volume = null;

    protected function tearDown(): void
    {
        if ($this->driver !== null && $this->volume !== null) {
            $this->driver->destroyWorkspace($this->volume);
        }

        parent::tearDown();
    }

    public function test_the_build_sandbox_cannot_see_the_fetch_credential(): void
    {
        /*
         * 🛑 This test runs in the **runner** container, not the application
         * one, and that is the point rather than an inconvenience. §8.5.13
         * keeps the Docker client out of every image but the runner's, so a
         * test that could drive containers from the application container
         * would be evidence that the separation had been lost.
         *
         *     docker compose exec -e DOCUP_E2E=1 runner ./vendor/bin/pest          *         --filter=CredentialIsolationTest
         *
         * It also needs no database, which is the other half of the runner's
         * isolation: a test that passes in there is a test that passed
         * without credentials of any kind.
         */
        $this->requireBuildImages(['docup/fetch:1', 'docup/build-mkdocs:1']);

        $this->driver = new DockerRunnerDriver;
        $buildId = bin2hex(random_bytes(16));

        try {
            $this->volume = $this->driver->createWorkspace($buildId);
        } catch (\RuntimeException $unavailable) {
            $this->skipOrFailForImages('no container runtime: '.$unavailable->getMessage());
        }

        // ------------------------------------------------- the credentialed stage
        //
        // A real clone of a real public repository, handed a credential it
        // does not need. The credential travels on stdin, which is the only
        // channel §8.5.7 permits.
        $fetch = $this->driver->run(
            new RunSpecification(
                buildId: $buildId,
                stage: Stage::Fetch,
                imageKey: 'fetch',
                command: ['https://github.com/mkdocs/mkdocs', 'master', '/workspace/source', '.'],
                environment: [],
                volume: (string) $this->volume,
                workdir: '/workspace',
                timeoutSeconds: 300,
                egress: EgressMode::Allowlist,
                acceptsStdin: true,
            ),
            "username=x-access-token\npassword=".self::CREDENTIAL."\n",
        );

        if (! $fetch->succeeded()) {
            $this->skipOrFailForImages('the fetch stage did not run: '.implode(' | ', array_slice($fetch->log, 0, 3)));
        }

        // ------------------------------------------- the fixture, in the sandbox
        //
        // Everything a `post_checkout` hook could reach, in one command:
        // its own environment, the credential tmpfs the fetcher used, the
        // shared workspace, and git's own configuration — which is where a
        // credential helper would have left a usable remote.
        /*
         * One line, joined with `;`. `RunSpecification` refuses an argv
         * element containing a newline — correctly: a newline in an argument
         * is how one command becomes two in anything that logs or re-parses
         * argv. A multi-line `build.jobs` hook will therefore have to reach
         * the sandbox as a file in the workspace rather than as an argument,
         * which is Phase 09's problem and is better than the alternative.
         */
        $probe = implode('; ', [
            'echo "ENV>"', 'env | sort',
            'echo "RUN>"', 'ls -la /run 2>&1',
            'echo "CRED>"', 'cat /run/cred 2>&1',
            'echo "GIT>"', 'ls -la /workspace/source/.git 2>&1',
            'echo "CFG>"', 'cat /workspace/source/.git/config 2>&1',
            'echo "GREP>"', "grep -ri 'ghp_' /workspace 2>/dev/null | head -5",
            'echo "DONE>"',
        ]);

        $build = $this->driver->run(new RunSpecification(
            buildId: $buildId,
            stage: Stage::Build,
            imageKey: 'mkdocs',
            command: ['sh', '-c', $probe],
            environment: ['DOCUP_COMPONENT' => 'probe'],
            volume: (string) $this->volume,
            workdir: '/workspace',
            timeoutSeconds: 120,
            egress: EgressMode::None,
        ));

        $output = implode("\n", $build->log);

        $this->assertStringContainsString('DONE>', $output, 'the probe did not run to completion');

        // 🛑 The criterion, in one assertion.
        $this->assertStringNotContainsString(
            self::CREDENTIAL,
            $output,
            'the build sandbox can see the credential the fetcher was given (§8.5.7)',
        );

        $this->assertStringNotContainsString('x-access-token', $output);

        // And the places it could have survived, named individually so a
        // regression says which one leaked rather than only that one did.
        $this->assertStringNotContainsString(
            'password=',
            $output,
            'a credential-helper response reached the build sandbox',
        );

        $this->assertMatchesRegularExpression(
            '/CRED>\s*(cat: )?can\'t open|CRED>\s*cat: .*No such file/',
            $output,
            '/run/cred exists in the build sandbox; the fetcher tmpfs is not supposed to be there',
        );

        /*
         * 🛑 `.git` is gone too, and that is a separate property worth its
         * own assertion. The fetcher removes it before the volume is handed
         * on: a `.git/config` carries the remote URL, and a credential
         * helper left behind there would be usable by anything running in
         * the sandbox afterwards.
         */
        $this->assertStringNotContainsString('[remote "origin"]', $output);

        // The control: the probe really did see the workspace, so the
        // assertions above are about absence rather than about a container
        // that failed to look.
        $this->assertStringContainsString('DOCUP_COMPONENT=probe', $output);
    }
}
