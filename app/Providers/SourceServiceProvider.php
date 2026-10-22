<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Providers;

use App\Credentials\CredentialVault;
use App\Credentials\EnvelopeCipher;
use App\Egress\AddressGuard;
use App\Egress\DnsResolver;
use App\Egress\EgressOptions;
use App\Egress\HardenedEgressClient;
use App\Egress\IpAddressClassifier;
use App\Egress\PinnedCurlTransport;
use App\Egress\SystemDnsResolver;
use App\Egress\Transport;
use App\Source\GitUrlPolicy;
use App\Source\RepositoryConnector;
use Illuminate\Support\ServiceProvider;

/**
 * Binds the source-connection stack: hardened egress, the git URL policy and
 * the credential vault (§8.3).
 *
 * 🛑 This is the **only** place outside `App\Egress` permitted to construct
 * the transport or the options, and the architecture test that enforces
 * §8.3.9's sole-call-site rule allowlists `app/Providers/` by path for exactly
 * the reason `ArtifactServiceProvider` is allowlisted: binding a class is not
 * calling it. The exemption is a path rather than a comment marker so it
 * cannot be claimed by writing the right words in a file somewhere else.
 */
final class SourceServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        /*
         * One options object per process. §8.3.9's budget must not change
         * between the address check and the request it authorises: a config
         * reload mid-request would mean the scheme was validated against one
         * allowlist and the connection made under another.
         */
        $this->app->singleton(EgressOptions::class, static fn (): EgressOptions => EgressOptions::fromConfig());

        $this->app->singleton(IpAddressClassifier::class);
        $this->app->bind(DnsResolver::class, SystemDnsResolver::class);
        $this->app->bind(Transport::class, PinnedCurlTransport::class);

        $this->app->singleton(AddressGuard::class, static fn ($app): AddressGuard => new AddressGuard(
            $app->make(DnsResolver::class),
            $app->make(IpAddressClassifier::class),
        ));

        /*
         * 🛑 §8.3.9: "One class, sole call site, architecture-tested." The
         * binding is a singleton so that nothing is tempted to construct a
         * second one with different options — which would be a second egress
         * policy wearing the first one's name.
         */
        $this->app->singleton(HardenedEgressClient::class, static fn ($app): HardenedEgressClient => new HardenedEgressClient(
            $app->make(AddressGuard::class),
            $app->make(Transport::class),
            $app->make(EgressOptions::class),
        ));

        $this->app->singleton(GitUrlPolicy::class, static fn ($app): GitUrlPolicy => new GitUrlPolicy(
            $app->make(AddressGuard::class),
        ));

        $this->app->singleton(RepositoryConnector::class, static fn ($app): RepositoryConnector => new RepositoryConnector(
            $app->make(GitUrlPolicy::class),
        ));

        /*
         * 🛑 Resolved lazily. `EnvelopeCipher::fromConfig()` throws when
         * APP_KEY is absent (§9.1.7), and a provider that constructed it
         * eagerly would turn a missing key into a boot failure for every
         * command, including `key:generate` — the one command that fixes it.
         */
        $this->app->singleton(EnvelopeCipher::class, static fn (): EnvelopeCipher => EnvelopeCipher::fromConfig());

        $this->app->singleton(CredentialVault::class, static fn ($app): CredentialVault => new CredentialVault(
            $app->make(EnvelopeCipher::class),
        ));
    }
}
