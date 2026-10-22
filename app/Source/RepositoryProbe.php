<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Source;

use App\Egress\EgressRefused;
use App\Egress\HardenedEgressClient;

/**
 * Is this repository reachable, and does the origin behave?
 *
 * 🛑 **This is not a fetch.** §17 puts cloning in Phase 06 and says "nothing
 * is fetched yet"; what happens here is one bounded request through the
 * §8.3.9 client to the repository's own URL, to answer two questions an
 * operator needs answered at attach time: does the host exist and speak TLS,
 * and does it redirect. The ref advertisement — `info/refs?service=…` — is
 * deliberately not requested, because interpreting it is the start of
 * fetching.
 *
 * The redirect question is the one that cannot wait for Phase 06. §8.3.4
 * requires redirects to be disabled, and an origin that 302s a credentialed
 * clone into private address space is a repository DocUp must refuse to
 * attach — not one it attaches and then fails to clone, with the refusal
 * buried in a build log a week later.
 *
 * An `ssh://` repository is inspected but not probed: there is no HTTP to
 * speak, and §8.3.9's client is an HTTP client. Reachability over SSH is
 * Phase 06's, along with the credential helper that would be needed to try.
 */
final readonly class RepositoryProbe
{
    public function __construct(
        private GitUrlPolicy $policy,
        private HardenedEgressClient $client,
    ) {}

    /**
     * @throws SourceRefused on any §8.3.4 refusal, including a redirect
     */
    public function probe(string $url, bool $enforceAddressPolicy = true): ProbeResult
    {
        $inspected = $this->policy->inspect($url, $enforceAddressPolicy);

        if ($inspected->url->scheme !== 'https') {
            return new ProbeResult($inspected, null);
        }

        try {
            $response = $this->client->get($inspected->url->canonical, [
                // Identifies DocUp in the origin's logs. Carries no credential:
                // authentication at probe time is Phase 06's credential helper.
                'User-Agent' => 'DocUp/probe',
                'Accept' => '*/*',
            ]);
        } catch (EgressRefused $refused) {
            /*
             * 🛑 Translated, not re-thrown. The person reading this is an
             * author who pasted a repository URL, and `egress.redirect_refused`
             * tells them about a subsystem they have never heard of.
             * `SourceRejection::fromEgress` is the single mapping point, so
             * the two vocabularies cannot drift.
             */
            throw new SourceRefused(
                SourceRejection::fromEgress($refused->rejection),
                $refused->host,
                $refused->context,
            );
        }

        return new ProbeResult($inspected, $response->status);
    }
}
