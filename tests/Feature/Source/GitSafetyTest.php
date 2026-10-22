<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Source;

use App\Source\GitSafety;
use App\Source\SourceRefused;
use App\Source\SourceRejection;
use Tests\TestCase;

/**
 * §8.3.4's git configuration and §8.3.5's submodule rule.
 *
 * 🛑 **These are assertions about a configuration nothing runs yet**, and
 * §18.18's lesson says that is weak evidence. It is stated plainly rather
 * than dressed up: Phase 05 does not clone (§17), so the strongest available
 * check is that the configuration says what §8.3.4 requires. Phase 06 runs
 * git for the first time, and it is Phase 06 that owes a test driving a real
 * `git ls-remote` at a hostile remote and asserting the refusal.
 *
 * What these tests *do* buy is the one thing a later phase cannot recover:
 * they fix the configuration as a committed expectation, so a Phase 06 change
 * that drops `protocol.allow=never` to make something work fails here rather
 * than passing quietly.
 */
final class GitSafetyTest extends TestCase
{
    /** 🛑 Deny everything, then name the two §8.3.4 permits. */
    public function test_it_denies_every_protocol_and_permits_only_https_and_ssh(): void
    {
        $config = GitSafety::configuration();

        $this->assertSame('never', $config['protocol.allow'], 'the default must be deny, not a deny list');
        $this->assertSame('always', $config['protocol.https.allow']);
        $this->assertSame('always', $config['protocol.ssh.allow']);

        // Named explicitly even though `never` already covers them, so a
        // later edit to the default cannot make RCE and local file
        // disclosure reachable as a side effect.
        $this->assertSame('never', $config['protocol.ext.allow']);
        $this->assertSame('never', $config['protocol.file.allow']);
        $this->assertSame('never', $config['protocol.git.allow']);
        $this->assertSame('never', $config['protocol.http.allow']);
    }

    /** §8.3.4: "MUST disable redirects". */
    public function test_it_disables_git_redirect_following(): void
    {
        $this->assertSame('false', GitSafety::configuration()['http.followRedirects']);
    }

    /** §8.3.5: never recursive, at any layer. */
    public function test_it_disables_submodule_recursion_in_configuration(): void
    {
        $config = GitSafety::configuration();

        $this->assertSame('false', $config['submodule.recurse']);
        $this->assertSame('false', $config['fetch.recurseSubmodules']);
    }

    /**
     * 🛑 The environment is where `insteadOf` would otherwise undo every
     * check above.
     *
     * A `url.<base>.insteadOf` rule in a system or user config rewrites the
     * remote **after** validation: the policy approves `https://github.com/x`
     * and git contacts something else. Pointing both config files at nothing
     * is the only way to be sure the validated URL is the used URL.
     */
    public function test_it_removes_every_inherited_git_configuration(): void
    {
        $environment = GitSafety::environment();

        $this->assertSame('/dev/null', $environment['GIT_CONFIG_GLOBAL']);
        $this->assertSame('/dev/null', $environment['GIT_CONFIG_SYSTEM']);
        $this->assertSame('https:ssh', $environment['GIT_ALLOW_PROTOCOL']);

        // What makes git apply its stricter policy to a URL it should not
        // trust — which is every URL DocUp hands it.
        $this->assertSame('0', $environment['GIT_PROTOCOL_FROM_USER']);

        // Nothing may block on a prompt.
        $this->assertSame('0', $environment['GIT_TERMINAL_PROMPT']);
        $this->assertSame('', $environment['GIT_ASKPASS']);

        // §8.5.7: credentials arrive through a file descriptor and nothing
        // else, so an inherited helper chain is cleared rather than extended.
        $this->assertSame('', GitSafety::configuration()['credential.helper']);
    }

    /** Every setting reaches argv, in `-c key=value` pairs. */
    public function test_the_configuration_reaches_argv(): void
    {
        $arguments = GitSafety::configurationArguments();
        $config = GitSafety::configuration();

        $this->assertCount(count($config) * 2, $arguments);

        foreach ($config as $key => $value) {
            $position = array_search($key.'='.$value, $arguments, true);

            $this->assertIsInt($position, $key.' is not passed to git');
            $this->assertSame('-c', $arguments[$position - 1]);
        }
    }

    /**
     * 🛑 git_url-017: submodules are opt-in and never recursive.
     *
     * The recursion request is **refused loudly** rather than silently
     * downgraded. Quietly doing the safe thing would leave the caller
     * believing recursion happened, and a caller who believes that will
     * eventually depend on it.
     */
    public function test_submodules_are_opt_in_and_recursion_is_refused(): void
    {
        $this->assertSame([], GitSafety::submoduleArguments(enabled: false));

        $arguments = GitSafety::submoduleArguments(enabled: true);

        $this->assertSame(['submodule', 'update', '--init', '--depth', '1'], $arguments);
        $this->assertNotContains('--recursive', $arguments);

        try {
            GitSafety::submoduleArguments(enabled: true, recursive: true);
            $this->fail('recursion was accepted');
        } catch (SourceRefused $refused) {
            $this->assertSame(SourceRejection::SubmoduleRecursionForbidden, $refused->rejection);
        }

        // Refused even when submodules are off, so the answer does not depend
        // on which flag the caller got wrong.
        $this->expectException(SourceRefused::class);
        GitSafety::submoduleArguments(enabled: false, recursive: true);
    }

    /** The §8.3.5 CVEs are reached through symlinks and malformed objects. */
    public function test_it_closes_the_submodule_cve_primitives(): void
    {
        $config = GitSafety::configuration();

        $this->assertSame('false', $config['core.symlinks'], 'CVE-2023-22490 needs a symlinked work-tree path');
        $this->assertSame('true', $config['transfer.fsckObjects']);
        $this->assertSame('true', $config['fetch.fsckObjects']);
        $this->assertSame('/dev/null', $config['core.hooksPath']);
    }
}
