<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Builds;

use App\Builds\Exceptions\SandboxMisconfigured;
use App\Builds\Sandbox\EgressMode;
use App\Builds\Sandbox\SandboxPolicy;
use App\Builds\Stage;
use App\Providers\BuildServiceProvider;
use Tests\TestCase;

/**
 * §8.5.11's isolation declaration and §8.1.7's hosting-only mode.
 *
 * > "🛑 The application MUST refuse to boot with `APP_ENV=production`,
 * > builds enabled and **no explicit isolation declaration**; `runc` plus
 * > open egress together MUST require `DOCUP_ACKNOWLEDGE_UNSANDBOXED=true`"
 *
 * 🛑 **Both directions, every time.** A test that only proved the refusal
 * would pass just as well against an application that refused to boot
 * always, which is a different and much worse defect — and one that would
 * be found by an operator rather than by CI. Phase 01's build log makes the
 * same point about the development seeder's production guard, and the
 * reasoning has not changed.
 */
final class SandboxPolicyTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        config()->set('builds.enabled', true);
        config()->set('builds.sandbox.egress', 'allowlist');
        config()->set('docup.unsafe.acknowledge_unsandboxed', false);
    }

    /** 🛑 The exit criterion, in one assertion. */
    public function test_production_boot_is_refused_with_builds_enabled_and_no_isolation_declaration(): void
    {
        config()->set('builds.sandbox.isolation', null);

        $this->expectException(SandboxMisconfigured::class);
        $this->expectExceptionMessageMatches('/no isolation declaration/');

        SandboxPolicy::fromConfig()->assertBootable('production');
    }

    /** ...and boots once the operator has said which one they chose. */
    public function test_production_boots_with_an_explicit_declaration(): void
    {
        foreach (['runc', 'gvisor'] as $declaration) {
            config()->set('builds.sandbox.isolation', $declaration);

            SandboxPolicy::fromConfig()->assertBootable('production');
        }

        $this->assertSame('runsc', SandboxPolicy::fromConfig()->runtime);
    }

    /**
     * 🛑 Development is not production, and this is why the default is null
     * rather than `runc`.
     *
     * A developer running `docker compose up` for the first time must not
     * meet a refusal about a runtime they have never heard of. The refusal
     * is scoped to the environment where the choice has consequences for
     * somebody other than the person making it.
     */
    public function test_development_boots_without_a_declaration(): void
    {
        config()->set('builds.sandbox.isolation', null);

        SandboxPolicy::fromConfig()->assertBootable('local');

        $this->assertNull(SandboxPolicy::fromConfig()->runtime);
    }

    /**
     * 🛑 §8.1.7: with builds disabled there is no sandbox to declare.
     *
     * Demanding a declaration here would push the security team this mode
     * exists for into describing a sandbox they have deliberately removed.
     */
    public function test_hosting_only_mode_boots_in_production_with_no_declaration(): void
    {
        config()->set('builds.enabled', false);
        config()->set('builds.sandbox.isolation', null);

        SandboxPolicy::fromConfig()->assertBootable('production');

        $this->assertFalse(SandboxPolicy::fromConfig()->buildsEnabled);
    }

    /** A declaration that is not in the §8.5.11 allowlist is a refusal, not a runtime. */
    public function test_an_unknown_isolation_name_is_refused_in_every_environment(): void
    {
        config()->set('builds.sandbox.isolation', 'kata; docker run --privileged');

        $this->expectException(SandboxMisconfigured::class);

        SandboxPolicy::fromConfig()->assertBootable('local');
    }

    /** 🛑 §8.5.11's second half: runc plus open egress needs the acknowledgement. */
    public function test_runc_with_open_egress_is_refused_without_the_acknowledgement(): void
    {
        config()->set('builds.sandbox.isolation', 'runc');
        config()->set('builds.sandbox.egress', 'open');

        $this->expectException(SandboxMisconfigured::class);
        $this->expectExceptionMessageMatches('/DOCUP_ACKNOWLEDGE_UNSANDBOXED/');

        SandboxPolicy::fromConfig()->assertBootable('production');
    }

    public function test_runc_with_open_egress_boots_once_acknowledged_and_shows_a_banner(): void
    {
        config()->set('builds.sandbox.isolation', 'runc');
        config()->set('builds.sandbox.egress', 'open');
        config()->set('docup.unsafe.acknowledge_unsandboxed', true);

        $policy = SandboxPolicy::fromConfig();
        $policy->assertBootable('production');

        $this->assertNotNull($policy->banner(), '§8.5.11 requires a dashboard banner');
        $this->assertTrue($policy->requiresUnsandboxedAudit());
        $this->assertStringContainsString('unrestricted', (string) $policy->banner());
    }

    /**
     * 🛑 The acknowledgement is narrow. gVisor with open egress is a
     * different posture and §8.5.11 does not gate it — the banner must not
     * appear for a configuration nobody acknowledged, or it becomes noise
     * that operators learn to ignore.
     */
    public function test_no_banner_for_a_configuration_that_did_not_need_acknowledging(): void
    {
        config()->set('builds.sandbox.isolation', 'gvisor');
        config()->set('builds.sandbox.egress', 'allowlist');
        config()->set('docup.unsafe.acknowledge_unsandboxed', true);

        $this->assertNull(SandboxPolicy::fromConfig()->banner());
    }

    /**
     * 🛑 An unreadable egress mode becomes the STRICTEST, never the most
     * convenient. A typo in `DOCUP_SANDBOX_EGRESS` must not open the
     * network.
     */
    public function test_an_unknown_egress_mode_falls_back_to_none(): void
    {
        config()->set('builds.sandbox.egress', 'allow-everything');

        $this->assertSame(EgressMode::None, SandboxPolicy::fromConfig()->egress);
    }

    /**
     * 🛑 `fetch` keeps the allowlist even when the build stage has none.
     *
     * Not a loophole: the fetcher runs a DocUp-authored image with no
     * repository code in it (§8.5.7), which is the property that makes
     * giving it a network acceptable when giving the generator one may not
     * be.
     */
    public function test_the_fetch_stage_keeps_egress_when_the_build_stage_has_none(): void
    {
        config()->set('builds.sandbox.egress', 'none');

        $policy = SandboxPolicy::fromConfig();

        $this->assertSame(EgressMode::Allowlist, $policy->egressFor(Stage::Fetch));
        $this->assertSame(EgressMode::None, $policy->egressFor(Stage::Build));
    }

    /** ...and `open` is never quietly narrowed for the fetcher either. */
    public function test_open_egress_is_not_downgraded_for_any_stage(): void
    {
        config()->set('builds.sandbox.egress', 'open');

        $policy = SandboxPolicy::fromConfig();

        $this->assertSame(EgressMode::Open, $policy->egressFor(Stage::Fetch));
        $this->assertSame(EgressMode::Open, $policy->egressFor(Stage::Build));
    }

    /**
     * 🛑 The assertion is wired into boot, not merely available.
     *
     * Everything above tests the policy object. This tests that something
     * calls it — the failure mode being a perfectly correct refusal that no
     * code path reaches, which is how §8.1.4's origin check would have
     * looked if `AppServiceProvider` had never invoked it.
     */
    public function test_the_service_provider_asserts_at_boot(): void
    {
        config()->set('builds.sandbox.assert_at_boot', true);
        config()->set('builds.sandbox.isolation', 'runc');
        config()->set('builds.sandbox.egress', 'open');
        config()->set('docup.unsafe.acknowledge_unsandboxed', false);

        $this->expectException(SandboxMisconfigured::class);

        (new BuildServiceProvider($this->app))->boot();
    }
}
