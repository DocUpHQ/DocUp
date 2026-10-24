<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds\Sandbox;

use App\Builds\BuildConfig;
use App\Builds\Exceptions\SandboxMisconfigured;
use App\Builds\Stage;

/**
 * The isolation declaration of §8.5.11, resolved once and asserted at boot.
 *
 * > "Isolation default MUST be hardened `runc`, with gVisor (`runsc`)
 * > documented as the recommended production runtime. 🛑 The application MUST
 * > refuse to boot with `APP_ENV=production`, builds enabled and **no explicit
 * > isolation declaration**; `runc` plus open egress together MUST require
 * > `DOCUP_ACKNOWLEDGE_UNSANDBOXED=true`, which writes an audit event and shows
 * > a dashboard banner."
 *
 * 🛑 **An absent declaration is not `runc`.** The configuration default is
 * `null`, and that is the whole mechanism: §19/23 rejects gVisor-by-default on
 * compatibility grounds and rejects silently-runc because an operator who has
 * not chosen has not understood that they are running other people's code on
 * their host. The refusal is what makes them choose.
 *
 * Resolved from configuration rather than read at each call site so that the
 * boot assertion and the runner cannot disagree about what is in force — the
 * failure mode being a production installation that booted because the
 * provider read one key and then ran builds against another.
 */
final readonly class SandboxPolicy
{
    private function __construct(
        /** The declared key (`runc`, `gvisor`), or null when nothing was declared. */
        public ?string $isolation,

        /** The runtime that key names, as `docker run --runtime` takes it. */
        public ?string $runtime,
        public EgressMode $egress,
        public bool $buildsEnabled,
        public bool $acknowledgedUnsandboxed,
    ) {}

    public static function fromConfig(): self
    {
        $declared = config('builds.sandbox.isolation');
        $declared = is_string($declared) && $declared !== '' ? strtolower($declared) : null;

        /** @var array<string, mixed> $runtimes */
        $runtimes = BuildConfig::map('sandbox.runtimes');
        $runtime = $declared === null ? null : ($runtimes[$declared] ?? null);

        return new self(
            isolation: $declared,
            runtime: is_string($runtime) ? $runtime : null,
            egress: EgressMode::fromConfig(config('builds.sandbox.egress')),
            buildsEnabled: config('builds.enabled') !== false,
            acknowledgedUnsandboxed: (bool) config('docup.unsafe.acknowledge_unsandboxed'),
        );
    }

    /**
     * 🛑 The §8.5.11 and §8.1.7 boot decision, in one place.
     *
     * @param  string  $environment  `app()->environment()`, passed in so the
     *                               assertion is testable without rebinding
     *                               the application environment
     *
     * @throws SandboxMisconfigured when the installation must not start
     */
    public function assertBootable(string $environment): void
    {
        /*
         * §8.1.7: hosting-only. With builds disabled no repository code runs
         * anywhere, so there is nothing for an isolation declaration to
         * declare and demanding one would be theatre — it would also push
         * exactly the security team this mode exists for into setting a
         * variable describing a sandbox they have deliberately removed.
         */
        if (! $this->buildsEnabled) {
            return;
        }

        if ($this->isolation !== null && $this->runtime === null) {
            throw new SandboxMisconfigured(sprintf(
                'DOCUP_BUILD_ISOLATION is "%s", which is not one of: %s. '
                .'§8.5.11 takes this value as a key into an allowlist, never as a runtime '
                .'name, so a typo here is a refusal rather than a container started with a '
                .'runtime nobody chose.',
                $this->isolation,
                implode(', ', array_keys(BuildConfig::map('sandbox.runtimes'))),
            ));
        }

        if ($environment === 'production' && $this->isolation === null) {
            throw new SandboxMisconfigured(
                '§8.5.11: this installation runs builds in production with no isolation '
                .'declaration. Set DOCUP_BUILD_ISOLATION=gvisor (recommended: runsc, and '
                .'the host needs Linux 5.6+ with runsc registered as a Docker runtime) or '
                .'DOCUP_BUILD_ISOLATION=runc (hardened runc, which shares the host kernel '
                .'with every repository it builds). There is no default, deliberately: '
                .'documentation builds execute arbitrary code from the repositories you '
                .'connect, and the choice of what separates that code from this host is '
                .'not one DocUp will make on your behalf. To run no builds at all, set '
                .'DOCUP_BUILDS_ENABLED=false (§8.1.7).'
            );
        }

        /*
         * 🛑 The second half of §8.5.11, and the narrower of the two. `runc`
         * on its own is a supported, documented posture. `runc` with egress
         * off the allowlist means a shared kernel AND an unrestricted
         * network from code the installation did not write, which is the
         * configuration §20.4 keeps behind an acknowledgement.
         */
        if ($this->isolation === 'runc' && $this->egress->isUnrestricted() && ! $this->acknowledgedUnsandboxed) {
            throw new SandboxMisconfigured(
                '§8.5.11: DOCUP_BUILD_ISOLATION=runc with DOCUP_SANDBOX_EGRESS=open is '
                .'hardened runc sharing this kernel with repository code that also has an '
                .'unrestricted network. Either restore the §8.5.9 allowlist '
                .'(DOCUP_SANDBOX_EGRESS=allowlist), move to gVisor, or set '
                .'DOCUP_ACKNOWLEDGE_UNSANDBOXED=true, which is audited on every build and '
                .'shows a permanent dashboard banner (§20.4).'
            );
        }

    }

    /**
     * What a given stage may reach (§8.5.9).
     *
     * 🛑 `fetch` is the exception and it is a narrow one: it is the only
     * stage that cannot do its job without egress, so an installation that
     * has narrowed the *build* stage to `none` still lets the fetcher reach
     * the allowlist. That is not a loophole in the sandbox — the fetcher
     * runs a DocUp-authored image with no repository code in it (§8.5.7),
     * which is exactly the property that makes giving it a network
     * acceptable when giving the generator one may not be.
     *
     * `open` is never upgraded or downgraded: an operator who declared it
     * gets it, having passed the boot assertion above to say so.
     */
    public function egressFor(Stage $stage): EgressMode
    {
        if ($this->egress === EgressMode::None && $stage === Stage::Fetch) {
            return EgressMode::Allowlist;
        }

        return $this->egress;
    }

    /**
     * §8.5.11's "shows a dashboard banner", as the text to show.
     *
     * Null when there is nothing to say. Returned as a sentence rather than a
     * flag because the component that renders it should not be the place
     * where the wording of a security posture is decided.
     */
    public function banner(): ?string
    {
        if (! $this->buildsEnabled) {
            return null;
        }

        if ($this->isolation === 'runc' && $this->egress->isUnrestricted() && $this->acknowledgedUnsandboxed) {
            return 'Builds run under hardened runc with unrestricted network egress, '
                .'acknowledged by DOCUP_ACKNOWLEDGE_UNSANDBOXED. Repository code shares this '
                .'host kernel and can reach any address this host can.';
        }

        return null;
    }

    /** True when a build running now must be audited as unsandboxed (§8.22.11). */
    public function requiresUnsandboxedAudit(): bool
    {
        return $this->banner() !== null;
    }
}
