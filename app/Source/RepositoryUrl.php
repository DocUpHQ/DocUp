<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Source;

/**
 * A repository URL that has passed §8.3.4's **shape** checks.
 *
 * Shape only. Whether the host resolves anywhere we are allowed to reach is
 * {@see GitUrlPolicy}'s job, and the split matters: shape is pure and total,
 * so every one of its refusals is unit-testable without a resolver, and the
 * network checks cannot be reached by a string that never parsed.
 *
 * 🛑 **The scp-like form is normalised, not rejected.** `git@github.com:org/repo.git`
 * is neither `https://` nor `ssh://`, so §8.3.4 read literally refuses it —
 * and it is the form every provider's UI offers for copying, so refusing it
 * would send operators to find a workaround. It is instead rewritten to its
 * `ssh://` equivalent **before** validation, so that the string this class
 * validates is the string git would act on. Parsing one form and executing
 * another is the §8.9.6 class of bug that Phase 04 spent a day on.
 */
final readonly class RepositoryUrl
{
    private function __construct(
        public string $scheme,
        public ?string $user,
        public string $host,
        public ?int $port,
        public string $path,
        public string $canonical,
        public string $normalised,
    ) {}

    /**
     * @throws SourceRefused when the URL's shape violates §8.3.4
     */
    public static function parse(string $input): self
    {
        $raw = trim($input);

        if ($raw === '') {
            throw new SourceRefused(SourceRejection::Malformed);
        }

        /*
         * 🛑 **The two named attacks are recognised first, and the order is
         * not cosmetic.** `ext::sh -c id` contains spaces — because it is a
         * command line — so a generic "no whitespace in a URL" check placed
         * above this one swallows it and reports `git_url.malformed`. The
         * input would still be refused, which is why the mistake survives a
         * careless test; what is lost is the one thing Phase 05's exit
         * criteria ask for, namely that the five controls are
         * distinguishable. An operator seeing "malformed" tidies the URL and
         * tries again; an operator seeing "remote helper forbidden" has been
         * told that something tried to run a command on their build host.
         *
         * Caught in the first run of `ExitCriteriaRefusalsTest`, and the
         * generic check below is deliberately left underneath rather than
         * removed.
         */
        self::refuseRemoteHelper($raw);
        self::refuseLocalPath($raw);

        /*
         * Control characters and whitespace. git splits a command line;
         * `parse_url` does not; and a newline inside a remote URL is how a
         * second git option gets smuggled in behind the first.
         */
        if (preg_match('/[\x00-\x20\x7f]/', $raw) === 1) {
            throw new SourceRefused(SourceRejection::Malformed);
        }

        $raw = self::rewriteScpSyntax($raw);

        $parts = parse_url($raw);

        if ($parts === false || ! isset($parts['scheme'], $parts['host'])) {
            throw new SourceRefused(SourceRejection::Malformed);
        }

        $scheme = strtolower((string) $parts['scheme']);

        if ($scheme === 'file') {
            throw new SourceRefused(SourceRejection::LocalPathForbidden);
        }

        // §8.3.4: "MUST reject repository URLs that are not `https://` or `ssh://`".
        if (! in_array($scheme, ['https', 'ssh'], true)) {
            throw new SourceRefused(SourceRejection::SchemeNotAllowed, null, ['scheme' => $scheme]);
        }

        /*
         * A password in the authority is always a credential. A *username* is
         * only a credential over https — `git@` over ssh is the conventional
         * account name for every provider in §8.3.1 and carries no secret.
         */
        if (isset($parts['pass']) || ($scheme === 'https' && isset($parts['user']))) {
            throw new SourceRefused(SourceRejection::CredentialsInUrl);
        }

        $host = strtolower((string) $parts['host']);

        if (preg_match('/^[a-z0-9.\-\[\]:]+$/', $host) !== 1) {
            // Punycode is accepted as-is; §8.10.7's confusable rules are Phase 18.
            throw new SourceRefused(SourceRejection::NonAsciiHost);
        }

        $port = isset($parts['port']) ? (int) $parts['port'] : null;
        $path = self::normalisePath((string) ($parts['path'] ?? ''));

        if ($path === '') {
            throw new SourceRefused(SourceRejection::Malformed, $host);
        }

        $user = isset($parts['user']) ? (string) $parts['user'] : null;
        $authority = ($user !== null ? $user.'@' : '').$host.($port !== null ? ':'.$port : '');

        return new self(
            scheme: $scheme,
            user: $user,
            host: $host,
            port: $port,
            path: $path,
            canonical: $scheme.'://'.$authority.'/'.$path,
            normalised: self::normalisedKey($scheme, $host, $port, $path),
        );
    }

    /** The default port for this URL's scheme, when none was given. */
    public function effectivePort(): int
    {
        return $this->port ?? ($this->scheme === 'https' ? 443 : 22);
    }

    /**
     * The §8.3.8 fallback key: **scheme-independent**, so the `https` and
     * `ssh` forms of one repository are one key.
     *
     * 🛑 Case is preserved in the path and lost in the host, which looks
     * inconsistent and is not. Hostnames are case-insensitive by RFC;
     * repository paths are case-**sensitive** on Gitea and Forgejo, where
     * `Docs` and `docs` are two repositories. Lower-casing the path would
     * merge them, and merging two repositories under one key is the failure
     * this key exists to prevent. The cost is that GitHub's case-insensitive
     * `Octo/Repo` and `octo/repo` produce two keys — acceptable, because on
     * GitHub the stable identifier is the real key and this one is a fallback.
     */
    private static function normalisedKey(string $scheme, string $host, ?int $port, string $path): string
    {
        $default = $scheme === 'https' ? 443 : 22;
        $suffix = ($port !== null && $port !== $default) ? ':'.$port : '';

        return $host.$suffix.'/'.$path;
    }

    /** Trim slashes and the `.git` suffix, which is optional at every provider. */
    private static function normalisePath(string $path): string
    {
        $path = trim($path, '/');

        if (str_ends_with($path, '.git')) {
            $path = substr($path, 0, -4);
        }

        return trim($path, '/');
    }

    /**
     * 🛑 `ext::sh -c id` and every other `<transport>::<address>` remote.
     *
     * Checked on the **raw** string, before `parse_url` is given a chance to
     * interpret it, because `parse_url('ext::sh -c id')` does not report a
     * scheme of `ext` and a later check would therefore never see it. git, by
     * contrast, sees it immediately and runs `git-remote-ext`, which runs the
     * rest as a shell command.
     *
     * The pattern matches any `word::` prefix rather than `ext::` alone:
     * §8.3.4 requires `protocol.allow=never` with explicit allowances exactly
     * because a deny list of helper names has to be kept current with git, and
     * is wrong the first time a new one ships.
     */
    private static function refuseRemoteHelper(string $raw): void
    {
        if (preg_match('/^[A-Za-z][A-Za-z0-9+.\-]*::/', $raw) === 1) {
            throw new SourceRefused(SourceRejection::RemoteHelperForbidden);
        }
    }

    /**
     * `file://`, an absolute or relative local path, a Windows drive, a UNC
     * share — every spelling of "read the local disk".
     */
    private static function refuseLocalPath(string $raw): void
    {
        $lower = strtolower($raw);

        if (str_starts_with($lower, 'file:')) {
            throw new SourceRefused(SourceRejection::LocalPathForbidden);
        }

        if (str_starts_with($raw, '/') || str_starts_with($raw, './') || str_starts_with($raw, '../')) {
            throw new SourceRefused(SourceRejection::LocalPathForbidden);
        }

        if (str_starts_with($raw, '~') || str_starts_with($raw, '\\\\')) {
            throw new SourceRefused(SourceRejection::LocalPathForbidden);
        }

        // `C:\repo` and `C:/repo`. One letter, a colon, a separator — which is
        // also why the scp rewrite below must not be allowed to see it first.
        if (preg_match('#^[A-Za-z]:[\\\\/]#', $raw) === 1) {
            throw new SourceRefused(SourceRejection::LocalPathForbidden);
        }
    }

    /**
     * `git@host:org/repo.git` → `ssh://git@host/org/repo.git`.
     *
     * 🛑 There is **no port** in scp syntax: git reads `host:1234/repo` as the
     * path `1234/repo`, not as port 1234. The rewrite therefore puts the whole
     * right-hand side in the path, which is what git would do. Treating it as
     * a port would mean DocUp validating a different endpoint from the one git
     * would contact — the parse-one-thing-execute-another bug again.
     */
    private static function rewriteScpSyntax(string $raw): string
    {
        if (str_contains($raw, '://')) {
            return $raw;
        }

        if (preg_match('#^(?:([A-Za-z0-9._\-]+)@)?([A-Za-z0-9.\-]+):(?!/)(.+)$#', $raw, $m) !== 1) {
            return $raw;
        }

        $user = $m[1] !== '' ? $m[1].'@' : '';

        return 'ssh://'.$user.$m[2].'/'.ltrim($m[3], '/');
    }
}
