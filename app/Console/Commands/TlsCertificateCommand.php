<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Console\Commands;

use App\Credentials\EnvelopeCipher;
use App\Egress\HardenedEgressClient;
use App\Models\AcmeAccount;
use App\Models\CertificateIssuanceAttempt;
use App\Models\Domain;
use App\Tls\Acme\AcmeAccountKey;
use App\Tls\Acme\AcmeChallenges;
use App\Tls\AcmeCertificateSource;
use App\Tls\CertificateRefused;
use App\Tls\CertificateRejection;
use App\Tls\CertificateSource;
use App\Tls\CertificateSourceKind;
use App\Tls\CertificateStore;
use App\Tls\DevelopmentCertificateSource;
use App\Tls\IssuanceBreaker;
use App\Tls\IssuanceBudgets;
use App\Tls\RegisteredDomain;
use App\Tls\UploadedCertificateSource;
use Illuminate\Console\Command;

/**
 * `docup:tls:certificate` — put a certificate in the database for a host.
 *
 * 🛑 One command for all of §8.10.14's sources that this application issues
 * from, because they sit behind one contract and the only thing that differs
 * is which implementation is constructed. A command per source would be
 * four copies of the budget check, the breaker and the store write — and the
 * one that got written in a hurry would be missing the budget check.
 *
 * There is no `--source=public_acme` shortcut that bypasses an account:
 * §18.20's consequence column requires "an operator-supplied ACME account",
 * and an installation that auto-registered against a public CA on an
 * operator's behalf would be spending that operator's rate limits under an
 * identity they never agreed to.
 */
final class TlsCertificateCommand extends Command
{
    protected $signature = 'docup:tls:certificate
        {host : The hostname, as it appears in the domains table}
        {--source=acme : acme, upload or development}
        {--account= : The acme_accounts label, for --source=acme}
        {--chain= : Path to a PEM chain, for --source=upload}
        {--key= : Path to the matching private key, for --source=upload}
        {--force : Issue even when the registrable domain is out of budget}';

    protected $description = 'Obtain or import a certificate and serve it from the database (§8.10.14)';

    public function handle(
        CertificateStore $store,
        IssuanceBudgets $budgets,
        IssuanceBreaker $breaker,
        EnvelopeCipher $cipher,
    ): int {
        $host = $this->hostArgument();
        $domain = Domain::query()->where('host', $host)->first();

        if ($domain === null) {
            $this->components->error('No domain row for '.$host.'. Add it first: a certificate for a hostname nobody has claimed is one §8.10.4 forbids.');

            return self::FAILURE;
        }

        if (! $breaker->closed($domain)) {
            $this->components->error(
                'The circuit breaker is open for '.$host.' until '.
                $domain->issuance_blocked_until?->toDateTimeString().'.',
            );

            return self::FAILURE;
        }

        try {
            $source = $this->source($cipher);
        } catch (CertificateRefused $refused) {
            $this->components->error($refused->getMessage());

            return self::FAILURE;
        }

        $registered = RegisteredDomain::fromConfig($host);

        /*
         * 🛑 The budget is consumed **before** the issuance, not after. A
         * token spent on an attempt that fails is a token the CA has also
         * spent — its bucket counts orders, not successes — so decrementing
         * only on success would let a failing host issue for ever against a
         * budget this installation believed was full.
         *
         * `--force` skips the local check and nothing else: the CA's own
         * limit is unaffected, and the operator is told so.
         */
        if (! $this->option('force')) {
            try {
                $remaining = $budgets->consume($registered);
            } catch (CertificateRefused $refused) {
                $this->components->error($refused->getMessage());

                return self::FAILURE;
            }

            if ($remaining < IssuanceBudgets::WARN_BELOW) {
                $this->components->warn(
                    $registered.' has '.number_format($remaining, 1).' of '.
                    IssuanceBudgets::CAPACITY.' issuances left before the CA refuses (§8.10.13).',
                );
            }
        } else {
            $this->components->warn('--force skips DocUp\'s budget, not the CA\'s. A refusal still costs authorization-failure budget.');
        }

        try {
            $certificate = $source->issue($host);
        } catch (CertificateRefused $refused) {
            $until = $breaker->fail($domain);

            $this->record($host, $registered, $source->kind(), 'failed', $refused->identifier(), $refused->getMessage());

            $this->components->error($refused->getMessage());
            $this->components->warn('Next attempt permitted at '.$until->toDateTimeString().' UTC.');

            return self::FAILURE;
        }

        $stored = $store->store(
            $host,
            $certificate,
            $source->kind(),
            $domain,
            $source instanceof AcmeCertificateSource ? $this->accountId() : null,
        );

        $breaker->succeed($domain);

        $this->record($host, $registered, $source->kind(), 'issued', null, 'expires '.$certificate->notAfter->toDateTimeString());

        $this->components->info(
            $host.' now serves a '.$source->kind()->value.' certificate from '.
            $certificate->issuer.', valid until '.$certificate->notAfter->toDateTimeString().'.',
        );
        $this->components->twoColumnDetail('Fingerprint', $stored->fingerprint);
        $this->components->twoColumnDetail('Served from', 'the database, at handshake time (§8.10.14)');

        return self::SUCCESS;
    }

    /** An option as a string, or the default when it is absent or not one. */
    private function text(string $option, string $default): string
    {
        $value = $this->option($option);

        return is_string($value) && $value !== '' ? $value : $default;
    }

    private function hostArgument(): string
    {
        $host = $this->argument('host');

        return is_string($host) ? $host : '';
    }

    /** @throws CertificateRefused */
    private function source(EnvelopeCipher $cipher): CertificateSource
    {
        return match ($this->text('source', 'acme')) {
            'upload' => new UploadedCertificateSource($this->read('chain'), $this->read('key')),
            'development' => new DevelopmentCertificateSource((string) app()->environment()),
            'acme' => $this->acme($cipher),
            default => throw CertificateRefused::of(
                CertificateRejection::AcmeRefused,
                'unknown source; use acme, upload or development',
            ),
        };
    }

    /** @throws CertificateRefused */
    private function acme(EnvelopeCipher $cipher): AcmeCertificateSource
    {
        $account = $this->account();

        return new AcmeCertificateSource(
            $account,
            new AcmeAccountKey($cipher),
            app(HardenedEgressClient::class),
            app(AcmeChallenges::class),
        );
    }

    /** @throws CertificateRefused */
    private function account(): AcmeAccount
    {
        $label = $this->option('account');

        $account = is_string($label) && $label !== ''
            ? AcmeAccount::query()->where('label', $label)->first()
            : AcmeAccount::query()->where('state', 'registered')->first();

        if ($account === null) {
            throw CertificateRefused::of(
                CertificateRejection::NoAcmeAccount,
                'no registered ACME account; run docup:tls:account first',
            );
        }

        return $account;
    }

    private function accountId(): ?string
    {
        try {
            return $this->account()->id;
        } catch (CertificateRefused) {
            return null;
        }
    }

    /** @throws CertificateRefused */
    private function read(string $option): string
    {
        $path = $this->option($option);

        if (! is_string($path) || $path === '' || ! is_file($path)) {
            throw CertificateRefused::of(
                CertificateRejection::ChainUnreadable,
                '--'.$option.' must name a readable file',
            );
        }

        return (string) file_get_contents($path);
    }

    private function record(
        string $host,
        string $registered,
        CertificateSourceKind $kind,
        string $outcome,
        ?string $reason,
        string $detail,
    ): void {
        CertificateIssuanceAttempt::query()->create([
            'host' => $host,
            'registered_domain' => $registered,
            'source' => $kind->value,
            'outcome' => $outcome,
            'reason' => $reason,
            'detail' => substr($detail, 0, 512),
            'attempted_at' => now(),
        ]);
    }
}
