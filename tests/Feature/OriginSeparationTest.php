<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature;

use App\Support\Origins;
use Tests\TestCase;

/**
 * 🛑 SPEC 8.1.4: the application refuses to boot when the dashboard and
 * documentation origins share a registrable domain.
 *
 * This is the invariant the whole containment argument rests on. Built
 * documentation is attacker-controlled JavaScript by design (Sphinx evaluates
 * conf.py, build.commands is a shell), so on a shared registrable domain it can
 * toss cookies at the dashboard, Clear-Site-Data spans every tenant, and
 * Laravel's TrustHosts default trusts subdomains of APP_URL. There is no safe
 * configuration in that shape.
 *
 * The trap worth testing explicitly: app.example.com and docs.example.com LOOK
 * separate and are not. That is the mistake an operator actually makes.
 */
final class OriginSeparationTest extends TestCase
{
    public function test_distinct_registrable_domains_are_accepted(): void
    {
        Origins::assert('docup.example.com', 'example-docs.net', 'example-previews.net', false);

        $this->expectNotToPerformAssertions();
    }

    /** 🛑 The mistake an operator actually makes. */
    public function test_sibling_subdomains_of_one_domain_are_refused(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessageMatches('/share the registrable domain "example\.com"/');

        Origins::assert('app.example.com', 'docs.example.com', null, false);
    }

    public function test_identical_hosts_are_refused(): void
    {
        $this->expectException(\RuntimeException::class);

        Origins::assert('example.com', 'example.com', null, false);
    }

    public function test_a_colliding_preview_origin_is_refused(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessageMatches('/preview origin/');

        Origins::assert('docup.example.com', 'example-docs.net', 'previews.example-docs.net', false);
    }

    public function test_missing_origins_are_refused(): void
    {
        $this->expectException(\RuntimeException::class);

        Origins::assert(null, null, null, false);
    }

    /** SPEC 8.1.5: the sole exception, and it must be explicit. */
    public function test_the_unsafe_single_origin_flag_permits_the_collision(): void
    {
        Origins::assert('app.example.com', 'docs.example.com', null, true);

        $this->expectNotToPerformAssertions();
    }

    /**
     * Multi-label public suffixes are the case a naive "last two labels" rule
     * gets wrong, and getting it wrong here would silently permit the shape the
     * check exists to prevent.
     */
    public function test_multi_label_public_suffixes_are_handled(): void
    {
        $this->assertSame('acme.co.uk', Origins::registrable('docs.acme.co.uk'));
        $this->assertSame('acme.co.uk', Origins::registrable('app.acme.co.uk'));
        $this->assertTrue(Origins::shareRegistrableDomain('app.acme.co.uk', 'docs.acme.co.uk'));

        // ...and two genuinely different registrable domains under the same
        // public suffix must NOT be treated as shared.
        $this->assertFalse(Origins::shareRegistrableDomain('acme.co.uk', 'other.co.uk'));
    }

    public function test_hosts_are_normalised_before_comparison(): void
    {
        foreach ([
            'HTTPS://App.Example.COM:8443/path?q=1' => 'app.example.com',
            'app.example.com.' => 'app.example.com',
            'user@app.example.com' => 'app.example.com',
        ] as $input => $expected) {
            $this->assertSame($expected, Origins::normalise($input), "normalising [{$input}]");
        }
    }

    public function test_single_label_hosts_do_not_crash(): void
    {
        // `localhost` and bare container names appear in development.
        $this->assertSame('localhost', Origins::registrable('localhost'));
        $this->assertSame('db', Origins::registrable('db'));
    }
}
