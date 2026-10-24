<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Builds;

use App\Builds\Runner\ArgvTemplate;
use App\Builds\Runner\SandboxPlacement;
use App\Builds\RunSpecification;
use App\Builds\Sandbox\EgressMode;
use App\Builds\Stage;
use Tests\TestCase;

/**
 * §8.5.13: "There MUST be no code path from a webhook, a YAML value or an HTTP
 * request to an arbitrary runtime call."
 *
 * 🛑 The tests below are the adversarial half of that sentence. Each one takes
 * a value an attacker would plausibly get into a `.docup.yaml` or a webhook
 * payload and asserts it cannot become a `docker run` flag — either because
 * the specification refuses to be constructed, or because the rendered argv
 * puts it in a position Docker does not read as a flag.
 */
final class RunSpecificationTest extends TestCase
{
    /** @param  array<string, mixed>  $overrides */
    private function spec(array $overrides = []): RunSpecification
    {
        return new RunSpecification(
            buildId: $overrides['buildId'] ?? str_repeat('a', 32),
            stage: $overrides['stage'] ?? Stage::Build,
            imageKey: $overrides['imageKey'] ?? 'mkdocs',
            command: $overrides['command'] ?? ['mkdocs', 'build', '--site-dir', '/workspace/output/html'],
            environment: $overrides['environment'] ?? ['DOCUP_OUTPUT' => '/workspace/output'],
            volume: $overrides['volume'] ?? 'docup-build-test',
            workdir: $overrides['workdir'] ?? '/workspace/source',
            timeoutSeconds: $overrides['timeoutSeconds'] ?? 600,
            egress: $overrides['egress'] ?? EgressMode::None,
            readOnlyRoot: $overrides['readOnlyRoot'] ?? true,
            acceptsStdin: $overrides['acceptsStdin'] ?? false,
        );
    }

    /**
     * 🛑 §8.5.14: the image is an allowlist **key**, so a YAML value naming an
     * image — or naming an image plus two flags — never reaches argv.
     */
    public function test_an_image_outside_the_allowlist_is_refused(): void
    {
        foreach ([
            'ubuntu',
            'ubuntu:latest',
            'alpine --privileged',
            'ubuntu -v /:/host',
            '--privileged',
            'docup/fetch:1',   // a reference, not a key: still refused
            '',
        ] as $hostile) {
            try {
                $this->spec(['imageKey' => $hostile]);
                $this->fail('accepted an image outside the allowlist: '.$hostile);
            } catch (\InvalidArgumentException $refused) {
                $this->assertStringContainsString('unknown build image', $refused->getMessage());
            }
        }
    }

    /** A control: the two allowlisted keys are accepted. */
    public function test_the_allowlisted_keys_are_accepted(): void
    {
        $this->assertSame('mkdocs', $this->spec(['imageKey' => 'mkdocs'])->imageKey);
        $this->assertSame(
            'fetch',
            $this->spec(['imageKey' => 'fetch', 'stage' => Stage::Fetch])->imageKey,
        );
    }

    /**
     * 🛑 A command argument that looks like a flag is still only an argument,
     * because the image is the last flag-position element.
     */
    public function test_a_flag_shaped_command_argument_lands_after_the_image(): void
    {
        $spec = $this->spec(['command' => ['--privileged', '-v', '/:/host']]);
        $argv = (new ArgvTemplate)->render($spec, 'docup/build-mkdocs:1', '/tmp/env', SandboxPlacement::isolated());

        $imagePosition = array_search('docup/build-mkdocs:1', $argv, true);
        $this->assertIsInt($imagePosition);

        foreach (['--privileged', '-v', '/:/host'] as $argument) {
            $position = array_search($argument, $argv, true);

            $this->assertIsInt($position);
            $this->assertGreaterThan(
                $imagePosition,
                $position,
                $argument.' reached a flag position, where docker would read it',
            );
        }
    }

    /** Control characters never reach argv, in a command or in the environment. */
    public function test_control_characters_are_refused(): void
    {
        foreach ([
            ['command' => ['mkdocs', "build\n--privileged"]],
            ['command' => ['mkdocs', "build\x00--rm"]],
            ['environment' => ['DOCUP_OUTPUT' => "/workspace\nEXTRA=1"]],
        ] as $hostile) {
            $this->expectNotToPerformAssertions();

            try {
                $this->spec($hostile);
                $this->fail('accepted a control character');
            } catch (\InvalidArgumentException) {
                // expected
            }
        }
    }

    /** An environment name that is not a name cannot become a flag either. */
    public function test_a_hostile_environment_name_is_refused(): void
    {
        foreach (['--privileged', 'a b', 'lower', '', '1LEADING'] as $name) {
            try {
                $this->spec(['environment' => [$name => 'x']]);
                $this->fail('accepted an environment name: '.$name);
            } catch (\InvalidArgumentException $refused) {
                $this->assertStringContainsString('environment variable name', $refused->getMessage());
            }
        }
    }

    public function test_a_hostile_volume_or_workdir_is_refused(): void
    {
        foreach ([
            ['volume' => '../../etc'],
            ['volume' => '/etc/passwd'],
            ['volume' => 'Name With Spaces'],
            ['workdir' => 'relative/path'],
            ['workdir' => '/workspace/../etc'],
            ['workdir' => '/work space'],
        ] as $hostile) {
            try {
                $this->spec($hostile);
                $this->fail('accepted '.json_encode($hostile));
            } catch (\InvalidArgumentException) {
                $this->addToAssertionCount(1);
            }
        }
    }

    /**
     * 🛑 §8.5.7: only `fetch` may read a credential from stdin. A
     * specification that opened stdin for the build stage would be the
     * credential separation quietly undone, and it is refused at construction
     * rather than noticed in review.
     */
    public function test_only_the_fetch_stage_may_read_a_credential(): void
    {
        $fetch = $this->spec(['stage' => Stage::Fetch, 'imageKey' => 'fetch', 'acceptsStdin' => true]);
        $this->assertTrue($fetch->acceptsStdin);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('only the fetch stage may read a credential');

        $this->spec(['stage' => Stage::Build, 'acceptsStdin' => true]);
    }

    /** Stages the worker runs in PHP cannot be handed to the runner at all. */
    public function test_a_non_container_stage_is_refused(): void
    {
        foreach ([Stage::Plan, Stage::Collect, Stage::Store, Stage::Publish, Stage::Finalise] as $stage) {
            try {
                $this->spec(['stage' => $stage]);
                $this->fail($stage->value.' was accepted as a container stage');
            } catch (\InvalidArgumentException $refused) {
                $this->assertStringContainsString('does not run in a container', $refused->getMessage());
            }
        }
    }

    /**
     * 🛑 §8.5.8's flags are present, and the one that is easiest to forget —
     * `--memory-swap` equal to `--memory`, which is how Docker spells "swap
     * disabled" — is asserted by value rather than by presence.
     */
    public function test_the_rendered_argv_carries_the_hardening_flags(): void
    {
        $argv = (new ArgvTemplate)->render($this->spec(), 'docup/build-mkdocs:1', '/tmp/env', SandboxPlacement::isolated());
        $rendered = implode(' ', $argv);

        $this->assertStringContainsString('--cap-drop ALL', $rendered);
        $this->assertStringContainsString('--security-opt no-new-privileges', $rendered);
        $this->assertStringContainsString('--read-only', $rendered);
        $this->assertStringContainsString('--pids-limit', $rendered);
        $this->assertStringContainsString('noexec,nosuid,nodev', $rendered);

        $memory = $argv[array_search('--memory', $argv, true) + 1];
        $swap = $argv[array_search('--memory-swap', $argv, true) + 1];

        $this->assertSame($memory, $swap, 'swap is only disabled when --memory-swap equals --memory');
    }

    /**
     * 🛑 §8.5.9's three placements, each rendering to a different namespace.
     *
     * The one that matters is the middle row: `container:<warden>` puts the
     * build inside a namespace whose nftables ruleset was installed before
     * it started and which it has no capability to change (ADR 0011).
     * Phase 06 could only render `none` or `bridge`, because there was no
     * proxy to point at.
     */
    public function test_each_placement_renders_its_own_network_namespace(): void
    {
        $template = new ArgvTemplate;
        $spec = $this->spec(['egress' => EgressMode::None]);

        $cases = [
            'none' => SandboxPlacement::isolated(),
            'container:docup-warden-1-build' => SandboxPlacement::inWarden('docup-warden-1-build'),
            'bridge' => SandboxPlacement::unrestricted(),
        ];

        foreach ($cases as $expected => $placement) {
            $argv = $template->render($spec, 'img', '/tmp/env', $placement);

            $this->assertSame($expected, $argv[array_search('--network', $argv, true) + 1]);
        }
    }

    /**
     * 🛑 §8.5.11's declaration reaches `--runtime`, and only from the
     * allowlist.
     *
     * A placement with no runtime emits no flag at all rather than naming
     * `runc` explicitly: a development host with no `runsc` registered is a
     * supported configuration, and a flag naming a runtime that is not
     * installed is a container that will not start.
     */
    public function test_the_runtime_flag_appears_only_when_one_is_declared(): void
    {
        $template = new ArgvTemplate;
        $spec = $this->spec(['egress' => EgressMode::None]);

        $undeclared = $template->render($spec, 'img', '/tmp/env', SandboxPlacement::isolated());
        $this->assertNotContains('--runtime', $undeclared);

        $declared = $template->render($spec, 'img', '/tmp/env', SandboxPlacement::isolated('runsc'));
        $this->assertSame('runsc', $declared[array_search('--runtime', $declared, true) + 1]);
    }

    /**
     * 🛑 A warden name is validated before it becomes `--network`.
     *
     * The name is the runner's own and never repository input, but
     * `--network container:$x` is a flag value that joins a namespace, and
     * the day it does come from somewhere else is the day nobody remembers
     * it was unchecked.
     */
    public function test_a_malformed_warden_name_is_refused(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        SandboxPlacement::inWarden('--privileged');
    }

    /**
     * 🛑 The environment goes in a file, never in argv.
     *
     * `docker inspect` returns `Config.Env` to anyone who can reach the
     * socket, and `/proc/<pid>/cmdline` is world-readable. §8.5.25 requires
     * component secrets to be absent from both.
     */
    public function test_the_environment_never_reaches_argv(): void
    {
        $spec = $this->spec(['environment' => ['DOCUP_OUTPUT' => '/workspace/output', 'DOCUP_COMPONENT' => 'guides']]);
        $argv = (new ArgvTemplate)->render($spec, 'img', '/run/env', SandboxPlacement::isolated());

        $this->assertNotContains('-e', $argv);
        $this->assertNotContains('--env', $argv);
        $this->assertContains('--env-file', $argv);

        $rendered = implode(' ', $argv);
        $this->assertStringNotContainsString('DOCUP_COMPONENT', $rendered);
        $this->assertStringNotContainsString('guides', $rendered);

        // And the file itself is the plain `NAME=value` Docker parses.
        $this->assertSame(
            "DOCUP_OUTPUT=/workspace/output\nDOCUP_COMPONENT=guides\n",
            (new ArgvTemplate)->renderEnvFile($spec),
        );
    }

    /** The spool round-trip re-validates, because a spool file is a file. */
    public function test_a_spool_document_is_revalidated_on_the_way_in(): void
    {
        $spec = $this->spec();
        $round = RunSpecification::fromArray($spec->toArray());

        $this->assertEquals($spec->toArray(), $round->toArray());

        $tampered = $spec->toArray();
        $tampered['image_key'] = 'ubuntu';

        $this->expectException(\InvalidArgumentException::class);
        RunSpecification::fromArray($tampered);
    }
}
