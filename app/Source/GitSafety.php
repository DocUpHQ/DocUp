<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Source;

/**
 * The git configuration every DocUp invocation of git runs under (§8.3.4,
 * §8.3.5).
 *
 * 🛑 Phase 05 does not clone — §17 says so explicitly — so this class produces
 * the configuration and nothing executes it yet. That is deliberate rather
 * than premature: Phase 06's fetcher is the first thing to run git, and a
 * fetcher that has to *remember* to pass these flags is a fetcher that one day
 * does not. The configuration is data, it is tested as data, and Phase 06 can
 * only use it by using this class.
 *
 * 🛑 **`protocol.allow=never` plus explicit allowances, not a deny list.**
 * §8.3.4 specifies the shape and the reason is worth stating: git ships new
 * remote helpers, and a deny list is wrong on the day one arrives. Starting
 * from `never` means a helper nobody here has heard of is refused by default,
 * and the two we do want are named.
 *
 * 🛑 **`GIT_PROTOCOL_FROM_USER=0`** is the clause most easily missed. git
 * applies a *stricter* protocol policy to URLs it believes came from an
 * untrusted source, and it decides that from this variable. Left unset, a URL
 * that reached us from a repository's `.gitmodules` is treated as if the
 * operator typed it.
 */
final class GitSafety
{
    /**
     * The `-c key=value` configuration for every git invocation.
     *
     * @return array<string, string>
     */
    public static function configuration(): array
    {
        return [
            // ------------------------------------------------- §8.3.4 protocols
            //
            // Deny everything, then name the two §8.3.4 permits. `file` and
            // `ext` are additionally denied **by name** even though `never`
            // already covers them: if the default above is ever edited, the
            // two protocols that are remote code execution and local file
            // disclosure must not become reachable as a side effect.
            'protocol.allow' => 'never',
            'protocol.https.allow' => 'always',
            'protocol.ssh.allow' => 'always',
            'protocol.file.allow' => 'never',
            'protocol.ext.allow' => 'never',
            'protocol.git.allow' => 'never',
            'protocol.http.allow' => 'never',

            // ------------------------------------------------- §8.3.4 redirects
            //
            // git's own redirect following, disabled at the same place the
            // §8.3.9 client disables cURL's. A clone is not routed through
            // that client, so this is not redundant with it.
            'http.followRedirects' => 'false',

            // ------------------------------------------------ §8.3.5 submodules
            //
            // Never recursive, whatever a command line or a `.gitmodules`
            // asks for. CVE-2025-48384 and CVE-2023-22490 are both reached
            // through recursion into a submodule the operator never named.
            'submodule.recurse' => 'false',
            'fetch.recurseSubmodules' => 'false',

            // ------------------------------------------------------ code paths
            //
            // A clone does not install the remote's hooks, but a *subsequent*
            // git command in a tree an attacker influenced can still find one.
            // Pointing hooksPath at a path that holds nothing executable
            // removes the question.
            'core.hooksPath' => '/dev/null',

            // §8.3.5's CVE-2023-22490 is reached through a symlinked path in
            // the work tree. Checking symlinks out as plain files removes the
            // primitive; documentation sources have no legitimate need of them.
            'core.symlinks' => 'false',

            // Malformed objects are refused on arrival rather than discovered
            // when something later tries to read them.
            'transfer.fsckObjects' => 'true',
            'fetch.fsckObjects' => 'true',

            // ----------------------------------------------------- credentials
            //
            // 🛑 An empty helper **clears** any inherited chain rather than
            // adding to it. §8.5.7 supplies credentials through a file
            // descriptor and nothing else; a helper inherited from the image
            // or the home directory would be a second, unaudited source.
            'credential.helper' => '',

            // Nothing may prompt. A fetcher blocked on a terminal prompt is a
            // build that hangs until its timeout, with no useful error.
            'core.askPass' => '',

            // Housekeeping during a fetch is unbounded work on a clock we do
            // not control.
            'gc.auto' => '0',
        ];
    }

    /**
     * Environment for every git invocation.
     *
     * 🛑 `GIT_CONFIG_GLOBAL` and `GIT_CONFIG_SYSTEM` are pointed at nothing on
     * purpose. A `url.<base>.insteadOf` rule in a system or user config
     * **rewrites the remote URL after we have validated it** — the policy
     * approves `https://github.com/x`, git substitutes something else, and
     * every check above was performed on a URL that was never contacted. The
     * only way to be sure the URL we validated is the URL git uses is to
     * remove the files that could rewrite it.
     *
     * @return array<string, string>
     */
    public static function environment(): array
    {
        return [
            'GIT_CONFIG_GLOBAL' => '/dev/null',
            'GIT_CONFIG_SYSTEM' => '/dev/null',

            // The env-variable form of the protocol allowlist. Redundant with
            // `protocol.*.allow` above, and kept because the two are read by
            // different code paths inside git and a future version may honour
            // one where it ignores the other.
            'GIT_ALLOW_PROTOCOL' => 'https:ssh',

            // 🛑 See the class docblock: this is what makes git treat the URL
            // as untrusted, which is what it is.
            'GIT_PROTOCOL_FROM_USER' => '0',

            // No interactive prompt, ever.
            'GIT_TERMINAL_PROMPT' => '0',
            'GIT_ASKPASS' => '',
        ];
    }

    /**
     * The configuration as argv, ready to precede a git subcommand.
     *
     * @return list<string>
     */
    public static function configurationArguments(): array
    {
        $arguments = [];

        foreach (self::configuration() as $key => $value) {
            $arguments[] = '-c';
            $arguments[] = $key.'='.$value;
        }

        return $arguments;
    }

    /**
     * The submodule arguments for a repository, honouring §8.3.5.
     *
     * 🛑 `--recursive` is not a parameter of this function and cannot be
     * requested. §8.3.5 is unconditional — "non-recursively and only on
     * explicit per-repository opt-in" — so recursion is not a setting with a
     * safe default but a capability that does not exist. `$recursive` is
     * accepted only so that a caller asking for it is **refused loudly**
     * rather than silently given the safe thing and left believing recursion
     * happened.
     *
     * @param  bool  $enabled  the per-repository opt-in, `repositories.submodules_enabled`
     * @return list<string> empty when submodules are off
     *
     * @throws SourceRefused when recursion is requested
     */
    public static function submoduleArguments(bool $enabled, bool $recursive = false): array
    {
        if ($recursive) {
            throw new SourceRefused(SourceRejection::SubmoduleRecursionForbidden);
        }

        if (! $enabled) {
            return [];
        }

        return ['submodule', 'update', '--init', '--depth', '1'];
    }
}
