<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Support;

/**
 * The guard the three Phase 06 container tests share.
 *
 * 🛑 **A missing image is a skip; a present image that misbehaves is a
 * failure.** The distinction is the whole value of this trait. CI has a
 * Docker daemon — GitHub's runners do — but none of DocUp's build images and
 * no `runner` service, so a guard that only asked "is there a daemon?" would
 * let these tests run, watch `docker run` fail to pull `docup/fetch:1`, and
 * report a red build for an environment that was never asked to have one.
 *
 * 🛑 And a skip is not a pass. `DOCUP_E2E=1` turns every skip here into a
 * failure, which is the mode the phase's exit criteria were demonstrated in.
 * Without that switch a broken pipeline and an absent one look identical,
 * which is exactly the failure mode the build log is meant to make
 * impossible.
 */
trait RequiresBuildImages
{
    /** @param  list<string>  $images */
    protected function requireBuildImages(array $images = ['docup/fetch:1', 'docup/build-mkdocs:1']): void
    {
        if (! $this->dockerClientAvailable()) {
            /*
             * Always a skip, even under DOCUP_E2E. No client means the test
             * is in the wrong container: §8.5.13 keeps the Docker client out
             * of every image but the runner's, so running the suite from the
             * application container is the normal case and says nothing
             * about the code.
             */
            $this->markTestSkipped('run this in the `runner` container: docker compose exec runner ./vendor/bin/pest');
        }

        $missing = [];

        foreach ($images as $image) {
            if (! $this->imagePresent($image)) {
                $missing[] = $image;
            }
        }

        if ($missing !== []) {
            $this->skipOrFailForImages('missing build images: '.implode(', ', $missing));
        }
    }

    protected function dockerClientAvailable(): bool
    {
        return $this->runQuietly(['docker', 'version', '--format', '{{.Server.Version}}']) === 0;
    }

    protected function imagePresent(string $image): bool
    {
        return $this->runQuietly(['docker', 'image', 'inspect', $image]) === 0;
    }

    protected function skipOrFailForImages(string $reason): never
    {
        if (getenv('DOCUP_E2E') === '1') {
            $this->fail($reason);
        }

        $this->markTestSkipped($reason.' — build them with deploy/Dockerfile.fetch and deploy/Dockerfile.mkdocs');
    }

    /** @param  list<string>  $argv */
    private function runQuietly(array $argv): int
    {
        $descriptors = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
        $process = @proc_open($argv, $descriptors, $pipes);

        if (! is_resource($process)) {
            return -1;
        }

        /*
         * Drained before closing. Closing an unread stdout pipe hands the
         * child an EPIPE, which `docker version` turns into a non-zero exit —
         * so the probe reported "no docker client" on a machine where the
         * client works perfectly. Found the hard way.
         */
        foreach ($pipes as $pipe) {
            if (is_resource($pipe)) {
                stream_get_contents($pipe);
                fclose($pipe);
            }
        }

        return proc_close($process);
    }
}
