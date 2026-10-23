<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds;

use App\Egress\EgressRefused;
use App\Egress\EgressRejection;
use App\Egress\HardenedEgressClient;

/**
 * `git ls-remote`, without git and without a container (§8.5.1).
 *
 * > "every contributing ref pinned to an immutable commit SHA by
 * > `git ls-remote` **before any repository code executes**"
 *
 * and §8.5.2:
 *
 * > "MUST short-circuit a trigger whose digest equals the published build's to
 * > a terminal `unchanged` state in under a second, **with no container
 * > started**"
 *
 * 🛑 Those two requirements together rule out the obvious implementation. The
 * digest needs the commit SHAs, the short-circuit must beat a container start,
 * and the application image deliberately has no git in it — the one image that
 * does is the credential-free fetcher, and starting it is the thing §8.5.2
 * forbids. So the ref advertisement is fetched over git's smart HTTP
 * transport, which is a plain `GET`, **through the §8.3.9 egress client**.
 *
 * That choice pays twice. It is fast enough for "under a second", and it means
 * ref resolution inherits every control the hardened client already has:
 * scheme allowlist, resolve-then-pin, denial of private and metadata
 * addresses, refused redirects and a response cap. A bespoke HTTP call here
 * would have been a second egress path, which §8.3.9 exists to forbid.
 *
 * 🛑 **Known limit, stated rather than hidden.** This uses protocol v1, whose
 * advertisement lists *every* ref, against §8.3.9's 256 KiB cap — roughly five
 * thousand refs. A repository with more is refused with
 * `source.ref_advertisement_too_large` rather than silently truncated, and the
 * remedy is protocol v2's `ls-refs` with a `ref-prefix`, which needs a POST
 * body the egress client does not yet carry. Owed when a real repository hits
 * it; a silent truncation here would pin the wrong commit, which is worse than
 * a loud refusal.
 */
final readonly class RefResolver
{
    public function __construct(private HardenedEgressClient $client) {}

    /**
     * Resolve one ref to its commit SHA.
     *
     * @param  string  $cloneUrl  the canonical `https://` form from `RepositoryUrl`
     * @param  string  $ref  a branch or tag name, unqualified (`main`, `v2.1`)
     *
     * @throws BuildFailure when the ref cannot be resolved
     */
    public function resolve(string $cloneUrl, string $ref): string
    {
        $refs = $this->advertise($cloneUrl);

        /*
         * Branch before tag. A repository with both `refs/heads/v2` and
         * `refs/tags/v2` is unusual and legal, and picking the branch
         * matches what `git clone --branch v2` does — so DocUp builds what
         * the author would get locally rather than what a different ordering
         * would have chosen.
         */
        foreach (['refs/heads/'.$ref, 'refs/tags/'.$ref, $ref] as $candidate) {
            if (isset($refs[$candidate])) {
                return $refs[$candidate];
            }
        }

        /*
         * An annotated tag advertises `refs/tags/x^{}` for the commit it
         * points at. Without this a tag build pins the tag *object*, which is
         * not a commit and which `git clone --branch` would resolve
         * differently — a mismatch between the recorded SHA and the one
         * actually built.
         */
        if (isset($refs['refs/tags/'.$ref.'^{}'])) {
            return $refs['refs/tags/'.$ref.'^{}'];
        }

        throw BuildFailure::of(FailureClass::Source, 'ref_not_found', Stage::Plan);
    }

    /**
     * The repository's default branch, for a component with no ref configured.
     *
     * Read from the `HEAD` symref capability the advertisement carries, which
     * is what git itself uses. Guessing `main` would be wrong on every
     * repository old enough to say `master`, and wrong invisibly: the build
     * would fail with "ref not found" on a repository that has a perfectly
     * good default.
     */
    public function defaultBranch(string $cloneUrl): ?string
    {
        $refs = $this->advertise($cloneUrl);

        foreach (array_keys($refs) as $name) {
            if (str_starts_with($name, 'symref=HEAD:refs/heads/')) {
                return substr($name, strlen('symref=HEAD:refs/heads/'));
            }
        }

        return null;
    }

    /**
     * The ref advertisement, parsed.
     *
     * @return array<string, string> ref name => commit SHA, plus any
     *                               `symref=` capability as a pseudo-entry
     *
     * @throws BuildFailure
     */
    public function advertise(string $cloneUrl): array
    {
        $url = rtrim($cloneUrl, '/').'/info/refs?service=git-upload-pack';

        try {
            $response = $this->client->get($url, [
                // git's own content negotiation. Without it a server may
                // answer with the dumb protocol, whose format is different
                // and whose parse would produce nonsense rather than an error.
                'Accept' => 'application/x-git-upload-pack-advertisement',
                'User-Agent' => 'git/2.0 (DocUp)',

                /*
                 * 🛑 Protocol v1, deliberately, and NOT `Git-Protocol:
                 * version=2`. In v2 this endpoint answers with capabilities
                 * only and no refs at all — the refs come from a separate
                 * POST — so asking for v2 here returns a perfectly valid
                 * response containing nothing this class can use. Found by
                 * the first live call, which parsed cleanly and resolved
                 * zero refs.
                 */
            ]);
        } catch (EgressRefused $refused) {
            throw BuildFailure::of(
                FailureClass::Source,
                $refused->rejection === EgressRejection::ResponseTooLarge
                    ? 'ref_advertisement_too_large'
                    : 'remote_unreachable',
                Stage::Plan,
            );
        }

        if ($response->status === 401 || $response->status === 403) {
            throw BuildFailure::of(FailureClass::Source, 'credential_required', Stage::Plan);
        }

        if (! $response->successful()) {
            throw BuildFailure::of(FailureClass::Source, 'remote_refused_the_advertisement', Stage::Plan);
        }

        return $this->parse($response->body);
    }

    /**
     * Parse git's pkt-line framing.
     *
     * Each packet is four hex digits of length (including the four) followed
     * by the payload; `0000` is a flush. The first packet is the service
     * banner, and the first ref line carries the capability list after a NUL.
     *
     * @return array<string, string>
     */
    private function parse(string $body): array
    {
        $refs = [];
        $offset = 0;
        $length = strlen($body);

        while ($offset + 4 <= $length) {
            $header = substr($body, $offset, 4);

            if (preg_match('/^[0-9a-f]{4}$/i', $header) !== 1) {
                break;
            }

            $packet = (int) hexdec($header);
            $offset += 4;

            // A flush packet. The advertisement uses one after the banner and
            // one at the end, so this is not a terminator.
            if ($packet === 0) {
                continue;
            }

            if ($packet < 4) {
                break;
            }

            $payload = substr($body, $offset, $packet - 4);
            $offset += $packet - 4;

            $payload = rtrim($payload, "\n");

            if ($payload === '' || str_starts_with($payload, '# service=')) {
                continue;
            }

            /*
             * The first ref line is `<sha> <name>\0<capabilities>`. The
             * capabilities carry `symref=HEAD:refs/heads/main`, which is the
             * only authoritative statement of the default branch, so they are
             * kept rather than discarded with the NUL.
             */
            $capabilities = '';

            if (($nul = strpos($payload, "\0")) !== false) {
                $capabilities = substr($payload, $nul + 1);
                $payload = substr($payload, 0, $nul);
            }

            if (preg_match('/^([0-9a-f]{40}) (.+)$/', $payload, $matches) === 1) {
                $refs[$matches[2]] = $matches[1];
            }

            foreach (explode(' ', $capabilities) as $capability) {
                if (str_starts_with($capability, 'symref=HEAD:')) {
                    $refs[$capability] = '';
                }
            }
        }

        if ($refs === []) {
            throw BuildFailure::of(FailureClass::Source, 'empty_ref_advertisement', Stage::Plan);
        }

        return $refs;
    }
}
