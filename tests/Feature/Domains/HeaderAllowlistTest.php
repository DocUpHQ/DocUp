<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Domains;

use App\Domains\DomainRefused;
use App\Domains\DomainRejection;
use App\Domains\HeaderAllowlist;
use App\Serving\ArtifactHandoff;
use Tests\TestCase;

/**
 * 🛑 §8.10.22's byte-identical assertion.
 *
 * > "Per-domain custom response headers MUST be restricted to a single
 * > shared allowlist constant, asserted **byte-identical** between the
 * > application and the proxy configuration by an automated test."
 *
 * The requirement names the test because both failure modes are silent. A
 * header the application accepts and the proxy strips looks to an operator
 * like their configuration did not save; a header the proxy passes and the
 * application never validated is an injection point on every response from
 * that hostname. Neither raises an error anywhere, so nothing but a
 * character-for-character comparison catches a list edited in one place.
 */
final class HeaderAllowlistTest extends TestCase
{
    /** 🛑 The two lists are the same list, in the same order. */
    public function test_the_application_and_the_proxy_agree_byte_for_byte(): void
    {
        $this->assertSame(
            HeaderAllowlist::NAMES,
            HeaderAllowlist::fromFile(base_path(HeaderAllowlist::FILE)),
            HeaderAllowlist::FILE.' and HeaderAllowlist::NAMES have diverged',
        );
    }

    /**
     * 🛑 Order is part of it.
     *
     * A set comparison would pass on two lists that agree on membership and
     * differ in order — which reads as noise in a diff and makes the next
     * divergence harder to see, not easier. Asserted separately so a future
     * reader does not "simplify" the comparison above into `sort()`.
     */
    public function test_the_allowlist_is_sorted(): void
    {
        $sorted = HeaderAllowlist::NAMES;
        sort($sorted, SORT_STRING);

        $this->assertSame($sorted, HeaderAllowlist::NAMES, 'keep the allowlist alphabetical');
    }

    /**
     * 🛑 Nothing an operator may set overrides a serving-path **decision**.
     *
     * `Cache-Control` and `Vary` are §9.3.2's privacy answer, `X-Robots-Tag`
     * is derived from §8.10.2's canonical mode, `Link` carries
     * `rel=canonical`. Overriding one of those is overriding a decision, and
     * the worst case makes a private project's pages publicly cacheable from
     * one hostname's configuration.
     */
    public function test_no_allowlisted_header_overrides_a_serving_decision(): void
    {
        $this->assertSame(
            [],
            HeaderAllowlist::assertDisjointFromHandoff(),
            'a per-domain header may not override a header the serving path decides',
        );
    }

    /**
     * 🛑 And every protected name is one the serving path actually sets.
     *
     * A protected list that drifted into names nobody emits would protect
     * nothing while looking like it did.
     */
    public function test_every_protected_header_is_one_the_serving_path_emits(): void
    {
        $this->assertSame(
            [],
            HeaderAllowlist::unmatchedServingDecisions(),
            'SERVING_DECISIONS names a header §8.9.8 does not preserve',
        );
    }

    /**
     * 🛑 `Content-Security-Policy` IS overridable, and that is the point of
     * the feature.
     *
     * DocUp sets a default; a per-domain policy replaces it. Asserted
     * explicitly because it is the one deliberate overlap with the serving
     * path, and a future tightening of the rule above would otherwise remove
     * it silently.
     */
    public function test_content_security_policy_is_deliberately_overridable(): void
    {
        $this->assertTrue(HeaderAllowlist::permits('content-security-policy'));
        $this->assertContains('Content-Security-Policy', ArtifactHandoff::PRESERVED_HEADERS);
    }

    /** Case-insensitive, because HTTP field names are. */
    public function test_the_check_ignores_case(): void
    {
        $this->assertTrue(HeaderAllowlist::permits('X-Frame-Options'));
        $this->assertTrue(HeaderAllowlist::permits('  referrer-policy  '));
        $this->assertFalse(HeaderAllowlist::permits('Set-Cookie'));
    }

    /** 🛑 And the refusal is a refusal, not a filter. */
    public function test_a_header_outside_the_allowlist_is_refused(): void
    {
        try {
            HeaderAllowlist::assertUsable(['Referrer-Policy' => 'no-referrer', 'Set-Cookie' => 'a=b']);
            $this->fail('Set-Cookie was accepted as a per-domain header');
        } catch (DomainRefused $refused) {
            $this->assertSame(DomainRejection::HeaderNotAllowed, $refused->rejection);
            $this->assertStringContainsString('Set-Cookie', $refused->getMessage());
        }
    }
}
