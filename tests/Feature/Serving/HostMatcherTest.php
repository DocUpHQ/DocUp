<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Serving;

use App\Serving\HostCandidate;
use App\Serving\HostKind;
use App\Serving\HostMatcher;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

/**
 * §8.9.3 — host resolution order, and the hard 404 at the end of it.
 *
 * The corpus's `host` category lands here. Three of its six cases are this
 * class's: `host-001` and `host-002` are look-alikes that must not resolve, and
 * `host-006` fixes the preview split on the **last** `--`. The other three are
 * noted against the tests that will own them.
 */
final class HostMatcherTest extends TestCase
{
    private const DOCS_APEX = 'docs.example.com';

    private const PREVIEW_APEX = 'preview.example.com';

    /**
     * @param  list<HostCandidate>  $candidates
     * @return list<string>
     */
    private static function kinds(array $candidates): array
    {
        return array_map(static fn (HostCandidate $c): string => $c->kind->value, $candidates);
    }

    // ------------------------------------------------------------ the ordering

    public function test_a_custom_domain_is_always_the_first_candidate(): void
    {
        $candidates = HostMatcher::candidates('docs.acme.test', self::DOCS_APEX, self::PREVIEW_APEX);

        $this->assertSame(['custom'], self::kinds($candidates));
        $this->assertSame('docs.acme.test', $candidates[0]->lookupHost);
        $this->assertNull($candidates[0]->projectSlug);
    }

    /**
     * 🛑 §8.9.3's order is a priority: proof of control outranks the shape of a
     * string. A host under the apex is offered as a custom domain **first**, so
     * an operator who verified it explicitly gets their configuration rather
     * than the pattern match.
     */
    public function test_a_host_under_the_apex_is_offered_as_a_custom_domain_first(): void
    {
        $candidates = HostMatcher::candidates('alpha.docs.example.com', self::DOCS_APEX, self::PREVIEW_APEX);

        $this->assertSame(['custom', 'default_subdomain'], self::kinds($candidates));
        $this->assertSame('alpha', $candidates[1]->projectSlug);

        // And the precedence the enum declares agrees with the order produced,
        // so neither can drift from the other unnoticed.
        $this->assertLessThan($candidates[1]->kind->precedence(), $candidates[0]->kind->precedence());
    }

    public function test_a_preview_host_splits_into_project_and_version(): void
    {
        $candidates = HostMatcher::candidates('alpha--pr-7.preview.example.com', self::DOCS_APEX, self::PREVIEW_APEX);

        $this->assertSame(['custom', 'preview'], self::kinds($candidates));
        $this->assertSame(HostKind::Preview, $candidates[1]->kind);
        $this->assertSame('alpha', $candidates[1]->projectSlug);
        $this->assertSame('pr-7', $candidates[1]->versionSlug);
    }

    /**
     * 🛑 Corpus `host-006`: "preview host parsing must split on the LAST `--`,
     * not the first".
     *
     * Splitting on the first would make this project `alpha` and version
     * `beta--pr-7`, so a repository whose name contains `--` would have its
     * previews served out of a different project's documentation.
     */
    public function test_a_preview_host_splits_on_the_last_double_hyphen(): void
    {
        $candidates = HostMatcher::candidates(
            'alpha--beta--pr-7.preview.example.com',
            self::DOCS_APEX,
            self::PREVIEW_APEX,
        );

        $preview = $candidates[1];

        $this->assertSame(HostKind::Preview, $preview->kind);
        $this->assertSame('alpha--beta', $preview->projectSlug);
        $this->assertSame('pr-7', $preview->versionSlug);
    }

    // ------------------------------------------------------- the look-alikes

    /**
     * Corpus `host-001`: "look-alike suffix; must not match the verified
     * domain".
     *
     * `docs.example.com.evil.net` ends with `.evil.net`, so the apex rule does
     * not fire. It is offered only as a custom domain — a question whose answer
     * is no row, and therefore the hard 404 of §8.9.3.
     */
    public function test_a_suffix_lookalike_produces_no_apex_candidate(): void
    {
        $candidates = HostMatcher::candidates(
            'docs.example.com.evil.net',
            self::DOCS_APEX,
            self::PREVIEW_APEX,
        );

        $this->assertSame(['custom'], self::kinds($candidates));
        $this->assertNull($candidates[0]->projectSlug);
    }

    /**
     * Corpus `host-002`: "prefix look-alike".
     *
     * `evildocs.docs.example.com` is a single label under the apex, so it IS a
     * legitimate question. The protection is not that the question is refused —
     * it is that there is no project called `evildocs` and §8.9.3 forbids
     * falling through to a default one.
     */
    public function test_a_prefix_lookalike_is_a_question_about_a_project_that_does_not_exist(): void
    {
        $candidates = HostMatcher::candidates('evildocs.docs.example.com', self::DOCS_APEX, self::PREVIEW_APEX);

        $this->assertSame(['custom', 'default_subdomain'], self::kinds($candidates));
        $this->assertSame('evildocs', $candidates[1]->projectSlug);
    }

    /**
     * 🛑 A nested name under the apex resolves to nothing.
     *
     * A wildcard certificate covers one label, so `a.b.docs.example.com` is
     * either a misconfiguration or somebody probing for one. Offering it as
     * project `a.b` would invent a project slug containing a dot, which §8.6.6's
     * slug function cannot produce.
     */
    public function test_a_nested_name_under_the_apex_is_not_a_subdomain_candidate(): void
    {
        $candidates = HostMatcher::candidates('a.b.docs.example.com', self::DOCS_APEX, self::PREVIEW_APEX);

        $this->assertSame(['custom'], self::kinds($candidates));
    }

    public function test_the_apex_itself_is_not_a_subdomain_candidate(): void
    {
        $candidates = HostMatcher::candidates(self::DOCS_APEX, self::DOCS_APEX, self::PREVIEW_APEX);

        $this->assertSame(['custom'], self::kinds($candidates));
    }

    /**
     * A preview label with no `--`, or nothing after it, is not a preview host.
     *
     * It still resolves as a custom domain if one is verified, which is the
     * honest outcome: the operator may well have pointed a real hostname there.
     */
    #[DataProvider('nonPreviewLabels')]
    public function test_a_label_without_a_usable_separator_is_not_a_preview(string $host): void
    {
        $this->assertSame(['custom'], self::kinds(
            HostMatcher::candidates($host, self::DOCS_APEX, self::PREVIEW_APEX),
        ));
    }

    /**
     * @return \Generator<string, array{0: string}>
     *
     * One case, not three. `alpha--.preview…` and `--pr-7.preview…` moved to
     * {@see self::malformedHosts()} for a better reason than this test was
     * written for: a DNS label may neither begin nor end with a hyphen, so
     * neither is a hostname at all. They are refused before the preview split
     * is reached, which is a stronger outcome than "not a preview".
     */
    public static function nonPreviewLabels(): \Generator
    {
        yield 'no separator' => ['alpha.preview.example.com'];
    }

    // ------------------------------------------------------- normalisation

    #[DataProvider('equivalentSpellings')]
    public function test_it_normalises_a_hostname_to_one_spelling(string $host): void
    {
        $this->assertSame('alpha.docs.example.com', HostMatcher::normalise($host));
    }

    /** @return \Generator<string, array{0: string}> */
    public static function equivalentSpellings(): \Generator
    {
        yield 'as sent' => ['alpha.docs.example.com'];
        yield 'mixed case' => ['Alpha.Docs.Example.COM'];
        yield 'with a port' => ['alpha.docs.example.com:8443'];
        yield 'fully qualified' => ['alpha.docs.example.com.'];
        yield 'all three' => ['ALPHA.docs.example.com.:443'];
    }

    #[DataProvider('malformedHosts')]
    public function test_a_malformed_host_produces_no_candidates(string $host): void
    {
        $this->assertNull(HostMatcher::normalise($host));

        // 🛑 And therefore nothing to fall through to. §8.9.3: "It MUST NEVER
        // fall through to a default project."
        $this->assertSame([], HostMatcher::candidates($host, self::DOCS_APEX, self::PREVIEW_APEX));
    }

    /** @return \Generator<string, array{0: string}> */
    public static function malformedHosts(): \Generator
    {
        yield 'empty' => [''];
        yield 'only a port' => [':443'];
        yield 'underscore' => ['al_pha.docs.example.com'];
        yield 'leading hyphen' => ['-alpha.docs.example.com'];
        yield 'trailing hyphen' => ['alpha-.docs.example.com'];
        yield 'empty label' => ['alpha..docs.example.com'];
        yield 'leading dot' => ['.docs.example.com'];
        yield 'raw non-ascii' => ["d\xD0\xBEcs.example.com"];
        yield 'label over 63 bytes' => [str_repeat('a', 64).'.docs.example.com'];
        yield 'name over 253 bytes' => [str_repeat('a.', 200).'docs.example.com'];
        yield 'a path, not a host' => ['alpha.docs.example.com/x'];
        yield 'a scheme' => ['https://alpha.docs.example.com'];
        yield 'a non-numeric port' => ['alpha.docs.example.com:https'];
        yield 'an empty port' => ['alpha.docs.example.com:'];
        // A label may neither begin nor end with a hyphen, so these are not
        // hostnames — refused earlier than the preview split would refuse them.
        yield 'label ending in a hyphen' => ['alpha--.preview.example.com'];
        yield 'label beginning with a hyphen' => ['--pr-7.preview.example.com'];
    }

    /**
     * With no apexes configured, only a verified custom domain can resolve.
     *
     * That is the correct degenerate behaviour rather than a gap: §8.1.4 makes
     * the documentation apex mandatory configuration, and a boot-time assertion
     * already refuses to start without it. If it were somehow absent at request
     * time, serving nothing is the safe answer.
     */
    public function test_without_apexes_only_a_custom_domain_is_a_candidate(): void
    {
        $this->assertSame(['custom'], self::kinds(
            HostMatcher::candidates('alpha.docs.example.com', null, null),
        ));
    }
}
