<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Egress;

use App\Egress\EgressOptions;
use App\Egress\HardenedEgressClient;
use App\Source\GitUrlPolicy;
use App\Source\RepositoryConnector;
use Tests\TestCase;

/**
 * The shipped §8.3.9 configuration, and the wiring that uses it.
 *
 * 🛑 This is the counterweight to the integration tests that stand the
 * address policy down. Those construct their own {@see EgressOptions} so that
 * a loopback origin is reachable; the question this file answers is whether
 * **what the application actually resolves** does the same. If the shipped
 * configuration were ever permissive, the suite would be green and the
 * product wrong, which is the §18.18 failure in reverse.
 */
final class EgressConfigurationTest extends TestCase
{
    /** §8.3.9's numbers, as the file states them. */
    public function test_the_shipped_configuration_is_the_specified_budget(): void
    {
        $this->assertSame(['https'], config('egress.allowed_schemes'));
        $this->assertSame(5, config('egress.timeout_seconds'));
        $this->assertSame(262144, config('egress.max_response_bytes'));
        $this->assertTrue(config('egress.enforce_address_policy'));
    }

    /**
     * 🛑 The resolved client enforces the address policy.
     *
     * Asserted on the object the container builds, not on the config array:
     * a provider that read the wrong key, or defaulted the wrong way, would
     * satisfy the test above and ship an unguarded client.
     */
    public function test_the_resolved_options_enforce_the_address_policy(): void
    {
        $options = app(EgressOptions::class);

        $this->assertTrue($options->enforceAddressPolicy);
        $this->assertTrue($options->permitsScheme('https'));
        $this->assertFalse($options->permitsScheme('http'));
        $this->assertFalse($options->permitsScheme('file'));
        $this->assertFalse($options->permitsScheme('gopher'));
    }

    /**
     * 🛑 §20.4's invariant: "no security control sits behind a flag that
     * defaults open". The cheapest way to honour it for this file is to have
     * no flag at all, so `env()` must not appear in it.
     */
    public function test_the_egress_configuration_reads_nothing_from_the_environment(): void
    {
        /*
         * Tokenised rather than grepped, because the file's own comments
         * explain that it does not call `env()` — and a grep for `env(`
         * cannot tell the explanation from the thing it forbids. The first
         * version of this test failed on its own documentation.
         */
        $code = '';

        foreach (token_get_all((string) file_get_contents(config_path('egress.php'))) as $token) {
            if (is_array($token) && in_array($token[0], [T_COMMENT, T_DOC_COMMENT], true)) {
                continue;
            }

            $code .= is_array($token) ? $token[1] : $token;
        }

        $this->assertStringNotContainsString(
            'env(',
            $code,
            'an egress control reachable from .env is a control that gets widened at 2am and never narrowed',
        );
    }

    /**
     * 🛑 §8.3.9: "One class, sole call site". The binding is a singleton so
     * nothing can quietly construct a second client with different options —
     * which would be a second egress policy wearing the first one's name.
     */
    public function test_the_client_is_a_singleton(): void
    {
        $this->assertSame(app(HardenedEgressClient::class), app(HardenedEgressClient::class));
        $this->assertSame(app(EgressOptions::class), app(EgressOptions::class));
        $this->assertSame(app(GitUrlPolicy::class), app(GitUrlPolicy::class));
        $this->assertSame(app(RepositoryConnector::class), app(RepositoryConnector::class));
    }

    /**
     * The default `EgressOptions` constructor is safe on its own.
     *
     * A value object whose defaults are correct cannot be made dangerous by a
     * caller who omits arguments — which is the caller who will exist.
     */
    public function test_the_default_options_are_the_safe_ones(): void
    {
        $options = new EgressOptions;

        $this->assertSame(['https'], $options->allowedSchemes);
        $this->assertSame(5, $options->timeoutSeconds);
        $this->assertSame(262144, $options->maxResponseBytes);
        $this->assertTrue($options->enforceAddressPolicy);
    }

    /**
     * 🛑 The internal-destination list ships EMPTY (§8.10.14, Phase 19).
     *
     * It is the one way an installation can accept a private address, and
     * the default must be that it accepts none. A shipped entry would be a
     * hole every installation inherited from a file nobody read.
     */
    public function test_the_internal_destination_list_ships_empty(): void
    {
        $this->assertSame([], config('egress.internal_destinations'));
        $this->assertSame([], app(EgressOptions::class)->internalDestinations);
        $this->assertFalse((new EgressOptions)->permitsPrivateAddress('ca.internal'));
    }

    /**
     * 🛑 And a declared hostname waives private addresses for ITSELF only.
     *
     * Not for a subdomain of it — a suffix rule would let one declared name
     * widen into a zone somebody else controls — and never for loopback,
     * link-local or the metadata address, which `AddressGuard` refuses for
     * every host including a declared one.
     */
    public function test_a_declared_destination_matches_exactly(): void
    {
        $options = new EgressOptions(internalDestinations: ['ca.internal']);

        $this->assertTrue($options->permitsPrivateAddress('ca.internal'));
        $this->assertTrue($options->permitsPrivateAddress('CA.Internal.'), 'case and a trailing dot are one name');
        $this->assertFalse($options->permitsPrivateAddress('evil.ca.internal'));
        $this->assertFalse($options->permitsPrivateAddress('ca.internal.evil.test'));
    }

    /**
     * 🛑 The shipped file declares nothing, and explains itself at length.
     *
     * Asserted against the file rather than only against the parsed value,
     * because a file that had grown an uncommented example would ship a
     * hole the config array would faithfully report as intended.
     */
    public function test_the_shipped_destination_file_declares_nothing(): void
    {
        $path = base_path('deploy/internal-destinations.conf');

        $this->assertFileExists($path);

        foreach (explode("\n", (string) file_get_contents($path)) as $line) {
            $line = trim($line);

            $this->assertTrue(
                $line === '' || str_starts_with($line, '#'),
                'the shipped file must declare no destination, and declares: '.$line,
            );
        }
    }

    /**
     * 🛑 An IP literal on a line is ignored.
     *
     * A list of addresses would be a CIDR allowlist with extra steps, and a
     * literal has no name to have been declared under — which is also what
     * leaves the rebind check nothing to compare. Parsed through the real
     * `fromConfig()` so the rule lives in one place.
     */
    public function test_an_ip_literal_is_not_a_declarable_destination(): void
    {
        config(['egress.internal_destinations' => ['ca.internal', '10.0.0.5', '::1']]);

        $options = EgressOptions::fromConfig();

        $this->assertSame(['ca.internal'], $options->internalDestinations);
    }
}
