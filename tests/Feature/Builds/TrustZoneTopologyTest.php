<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Builds;

use Symfony\Component\Yaml\Yaml;
use Tests\TestCase;

/**
 * §11.2's five trust zones, "enforced by compose networks, not convention".
 *
 * 🛑 **Asserted against the file rather than against a running stack**, and
 * that is deliberate: the property is a statement about what an operator
 * gets from `docker compose up`, and a test that needed the stack up would
 * skip in CI — which is where a careless edit arrives. `SandboxIsolationTest`
 * measures the runtime behaviour this file describes.
 *
 * 🛑 **The absences carry the requirement.** §11.2's table is mostly a list
 * of things each zone may never reach, so most of what matters here is
 * `assertNotContains`: the runner not on `data`, the sandbox network
 * internal, the proxy the only bridge. An additive test would pass against
 * a compose file that put everything on everything.
 */
final class TrustZoneTopologyTest extends TestCase
{
    /** @var array<string, mixed> */
    private array $production;

    /** @var array<string, mixed> */
    private array $development;

    protected function setUp(): void
    {
        parent::setUp();

        /** @var array<string, mixed> $production */
        $production = Yaml::parseFile(base_path('compose.yaml'));
        $this->production = $production;

        /** @var array<string, mixed> $development */
        $development = Yaml::parseFile(base_path('compose.dev.yaml'));
        $this->development = $development;
    }

    /** All five zones exist, by the names §11.2 gives them. */
    public function test_the_five_zones_exist(): void
    {
        $networks = array_keys($this->networks());

        foreach (['app', 'runner', 'data', 'egress', 'sandboxes'] as $zone) {
            $this->assertContains($zone, $networks, '§11.2 names the '.$zone.' zone');
        }
    }

    /**
     * 🛑 `data` and `sandboxes` are internal, and that is the enforcement.
     *
     * Docker gives an internal network no gateway and no NAT, so nothing on
     * it has a route off the host. Without this the five networks would be
     * five names for one topology.
     */
    public function test_the_data_and_sandbox_zones_have_no_route_off_the_host(): void
    {
        foreach (['data', 'sandboxes'] as $zone) {
            $this->assertTrue(
                ($this->networks()[$zone]['internal'] ?? false) === true,
                '§11.2: the '.$zone.' zone must be internal',
            );
        }
    }

    /**
     * 🛑 "**runner** … MUST NEVER … reach the database."
     *
     * Expressed as the runner being on its own zone and on neither of the
     * two that would give it one.
     */
    public function test_the_runner_is_on_neither_the_app_zone_nor_the_data_zone(): void
    {
        $runner = $this->serviceNetworks('runner');

        $this->assertSame(['runner'], $runner);
        $this->assertNotContains('data', $runner);
        $this->assertNotContains('app', $runner);
    }

    /** "**app** … MUST NEVER hold a container-runtime socket" — nor its network. */
    public function test_the_credentialed_services_are_not_on_the_runner_or_sandbox_zones(): void
    {
        foreach (['app', 'worker'] as $service) {
            $networks = $this->serviceNetworks($service);

            $this->assertContains('data', $networks, $service.' needs the database');
            $this->assertNotContains('runner', $networks);
            $this->assertNotContains('sandboxes', $networks);
        }
    }

    /**
     * 🛑 The proxy is the **only** service bridging the sandbox zone to a
     * routed one.
     *
     * This is the sentence the whole egress design rests on: if anything
     * else sat on `sandboxes`, a build could reach it, and §8.5.9's
     * allowlist would be a suggestion.
     */
    public function test_the_proxy_is_the_only_bridge_out_of_the_sandbox_zone(): void
    {
        $onSandboxes = [];

        foreach (array_keys($this->services($this->production)) as $service) {
            if (in_array('sandboxes', $this->serviceNetworks((string) $service), true)) {
                $onSandboxes[] = (string) $service;
            }
        }

        $this->assertSame(['proxy'], $onSandboxes);
        $this->assertContains('egress', $this->serviceNetworks('proxy'));
    }

    /** The database and the cache are on the data zone and nothing else. */
    public function test_the_data_zone_holds_only_the_database_and_the_cache(): void
    {
        foreach (['db', 'cache'] as $service) {
            $this->assertSame(['data'], $this->serviceNetworks($service));
        }
    }

    /**
     * 🛑 Every production service declares a zone.
     *
     * A service with no `networks:` key silently joins `default`, which is
     * a sixth network §11.2 does not describe — and the failure is quiet:
     * the service starts, and simply cannot reach what it needs. That is
     * exactly what happened to the development overlay when these networks
     * were introduced, which is why the rule is asserted rather than
     * remembered.
     */
    public function test_every_service_declares_a_zone(): void
    {
        foreach (array_keys($this->services($this->production)) as $service) {
            $this->assertNotSame(
                [],
                $this->serviceNetworks((string) $service),
                $service.' declares no network, so it lands on `default` (§11.2)',
            );
        }

        foreach (['mailpit', 'phpmyadmin'] as $service) {
            $this->assertNotSame(
                [],
                $this->serviceNetworks($service, $this->development),
                $service.' declares no network, so it cannot reach what it is for',
            );
        }
    }

    /** @return array<string, array<string, mixed>> */
    private function networks(): array
    {
        /** @var array<string, array<string, mixed>> $networks */
        $networks = is_array($this->production['networks'] ?? null) ? $this->production['networks'] : [];

        return $networks;
    }

    /**
     * @param  array<string, mixed>  $file
     * @return array<array-key, mixed>
     */
    private function services(array $file): array
    {
        /** @var array<array-key, mixed> $services */
        $services = is_array($file['services'] ?? null) ? $file['services'] : [];

        return $services;
    }

    /**
     * @param  array<string, mixed>|null  $file
     * @return list<string>
     */
    private function serviceNetworks(string $service, ?array $file = null): array
    {
        $services = $this->services($file ?? $this->production);
        $definition = $services[$service] ?? null;

        if (! is_array($definition) || ! is_array($definition['networks'] ?? null)) {
            return [];
        }

        $networks = [];

        foreach ($definition['networks'] as $key => $value) {
            // Compose accepts both a list and a map of network names.
            $networks[] = is_string($key) ? $key : (string) $value;
        }

        return $networks;
    }
}
