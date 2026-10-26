<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Console\Commands;

use App\Credentials\EnvelopeCipher;
use App\Egress\HardenedEgressClient;
use App\Models\AcmeAccount;
use App\Support\Uuid;
use App\Tls\Acme\AcmeAccountKey;
use App\Tls\Acme\AcmeChallenges;
use App\Tls\AcmeCertificateSource;
use App\Tls\CertificateRefused;
use Illuminate\Console\Command;

/**
 * `docup:tls:account` — register this installation with a certificate
 * authority (§8.10.14, §18.20).
 *
 * 🛑 **An explicit operator action, by design.** §18.20's consequence column
 * says P19 "requires an operator-supplied ACME account", and the reason is
 * that an ACME account is an agreement: terms of service accepted, a contact
 * address the CA will mail about revocations and policy changes, and a rate
 * budget that is the operator's to spend. Auto-registering on first use
 * would accept all three on their behalf, silently, the first time somebody
 * added a domain.
 *
 * It is also how an air-gapped installation points at its own CA: the same
 * command with its own `--directory`, and nothing in the application needs
 * to know the difference (§8.10.14's one contract).
 */
final class TlsAccountCommand extends Command
{
    protected $signature = 'docup:tls:account
        {--label=default : How configuration refers to this account}
        {--directory= : The ACME directory URL; defaults to config(tls.acme.directory)}
        {--contact= : An address the CA may mail about expiry and policy}
        {--kind=public : public or internal (§8.10.14)}';

    protected $description = 'Register an ACME account and seal its key (§8.10.14, §8.10.15)';

    public function handle(EnvelopeCipher $cipher): int
    {
        $label = $this->text('label', 'default');
        $directory = $this->directory();

        if ($directory === '') {
            $this->components->error('No directory URL. Pass --directory or set DOCUP_ACME_DIRECTORY.');

            return self::FAILURE;
        }

        if (AcmeAccount::query()->where('label', $label)->exists()) {
            $this->components->error('An account labelled "'.$label.'" already exists.');

            return self::FAILURE;
        }

        $keys = new AcmeAccountKey($cipher);
        $id = Uuid::v7();

        try {
            [, $sealed] = $keys->create($id);
        } catch (CertificateRefused $refused) {
            $this->components->error($refused->getMessage());

            return self::FAILURE;
        }

        $contact = $this->option('contact');

        $account = new AcmeAccount;
        $account->forceFill([
            'id' => $id,
            'label' => $label,
            'kind' => $this->text('kind', 'public') === 'internal' ? 'internal' : 'public',
            'directory_url' => $directory,
            'contact' => is_string($contact) && $contact !== '' ? $contact : $this->configuredContact(),
            'envelope_version' => $sealed->version,
            'kek_fingerprint' => $sealed->kekFingerprint,
            'wrapped_key' => $sealed->wrappedKey,
            'ciphertext' => $sealed->ciphertext,
            'state' => 'pending',
        ])->save();

        $source = new AcmeCertificateSource(
            $account,
            $keys,
            app(HardenedEgressClient::class),
            app(AcmeChallenges::class),
        );

        try {
            $registered = $source->register();
        } catch (CertificateRefused $refused) {
            /*
             * 🛑 The row stays, in `pending`. Deleting it would throw away
             * the account key — and if the CA in fact created the account
             * before the response was lost, that key is the only thing that
             * can ever speak for it again. A pending row with a key is
             * recoverable by re-running; a deleted one is an orphaned
             * account at the CA that this installation can never reach.
             */
            $this->components->error($refused->getMessage());
            $this->components->warn('The account row is kept in "pending" so its key is not lost; re-run to retry.');

            return self::FAILURE;
        }

        $this->components->info('Registered "'.$label.'" with '.$directory.'.');
        $this->components->twoColumnDetail('Account', (string) $registered->account_url);
        $this->components->twoColumnDetail('Key', 'sealed; every read is audited (§8.10.15)');

        return self::SUCCESS;
    }

    /** An option as a string, or the default when it is absent or not one. */
    private function text(string $option, string $default): string
    {
        $value = $this->option($option);

        return is_string($value) && $value !== '' ? $value : $default;
    }

    private function directory(): string
    {
        $option = $this->option('directory');

        if (is_string($option) && $option !== '') {
            return $option;
        }

        $configured = config('tls.acme.directory');

        return is_string($configured) ? $configured : '';
    }

    private function configuredContact(): ?string
    {
        $contact = config('tls.acme.contact');

        return is_string($contact) && $contact !== '' ? $contact : null;
    }
}
