<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Tls;

use App\Auth\OrganisationContext;
use App\Egress\TlsHandshake;
use App\Models\CertificateIssuanceAttempt;
use App\Models\Domain;
use Illuminate\Support\Carbon;
use Illuminate\Support\Collection;

/**
 * 🛑 §8.10.17's scheduled prober — the only issuance-failure observability
 * this installation has.
 *
 * > "A scheduled outbound TLS handshake prober MUST run against every active
 * > domain at least every six hours, recording expiry, issuer and error,
 * > **because the proxy never calls the permission endpoint back on issuance
 * > failure**. Without it there is no issuance-failure observability at all."
 *
 * That last clause is the whole design, and it is worth stating plainly
 * because it looks like belt and braces and is not. The permission endpoint
 * is one-way: Caddy asks "may I issue for this name?", DocUp says yes, and
 * **nothing ever comes back**. If the CA then refuses — rate limited, DNS
 * moved, CAA record, an outage — the proxy records it in its own log and the
 * application never hears. Every dashboard in DocUp would show a verified,
 * active, permitted domain; every reader would get a TLS error. The only way
 * to close that loop from this side is to open a connection and look.
 *
 * 🛑 The prober writes a `failed` row to `certificate_issuance_attempts` for
 * exactly this case: an issuance failure the proxy never reported. That row
 * is the one §19's exit criterion asks for.
 */
final readonly class TlsProber
{
    public function __construct(
        private TlsHandshake $handshake,
        private ?Carbon $now = null,
    ) {}

    /**
     * Probe every host that should be serving, and record what it found.
     *
     * @return list<TlsProbe>
     */
    public function run(): array
    {
        $results = [];

        foreach ($this->due() as $domain) {
            $results[] = $this->probe($domain);
        }

        return $results;
    }

    /**
     * One host.
     *
     * 🛑 The error is recorded on the domain **and** in the attempts table,
     * and the duplication is deliberate: the column is the current state an
     * operator looks at, the row is the history an operator reconstructs a
     * fortnight later. Keeping only the column would mean a domain that
     * failed for three days and then recovered left no trace.
     */
    public function probe(Domain $domain): TlsProbe
    {
        $now = $this->now();
        $result = $this->handshake->probe($domain->host);

        $probe = $this->interpret($domain->host, $result);

        $domain->forceFill([
            'tls_last_probed_at' => $now,
            'tls_not_after' => $probe->notAfter,
            'tls_issuer' => $probe->issuer,
            'tls_probe_error' => $probe->error,
        ])->save();

        if (! $probe->ok()) {
            $this->record($domain, 'handshake_failed', (string) $probe->error);

            return $probe;
        }

        /*
         * A trusted certificate inside the renewal window is a renewal that
         * did not happen. The proxy renews silently and reports nothing, so
         * this is the only place an unrenewed certificate becomes visible
         * before a reader sees it expire.
         */
        if ($probe->expiringWithin($this->warningDays(), $now)) {
            $this->record(
                $domain,
                'expiring',
                'expires '.$probe->notAfter?->toDateTimeString().', inside the renewal window',
            );
        }

        return $probe;
    }

    /**
     * Every host that should currently be presenting a certificate.
     *
     * `passthrough` hosts are excluded: §8.10.21 has something else
     * terminating their TLS, so a handshake here would report on a device
     * this installation does not run and cannot fix.
     *
     * @return Collection<int, Domain>
     */
    private function due(): Collection
    {
        /*
         * 🛑 Across tenants. `Domain` is organisation-scoped and this runs
         * from the scheduler, where no organisation is current — the same
         * trap `PermittedHosts` hit on the handshake path. Scoped, the sweep
         * would quietly probe nothing, and §8.10.17's "no issuance-failure
         * observability at all" would be exactly what the installation had
         * while believing otherwise.
         */
        return app(OrganisationContext::class)->acrossAllOrganisations(
            static fn (): Collection => Domain::query()
                ->where('state', '!=', 'suspended')
                ->where('tls_mode', 'managed')
                ->get()
                ->filter(static fn (Domain $domain): bool => $domain->canServe())
                ->values(),
        );
    }

    /** @param  array{trusted: bool, error: string|null, certificate: array<array-key, mixed>|null}  $result */
    private function interpret(string $host, array $result): TlsProbe
    {
        $certificate = $result['certificate'];

        $notAfter = null;
        $issuer = null;
        $fingerprint = null;

        if (is_array($certificate)) {
            $validTo = $certificate['validTo_time_t'] ?? null;
            $notAfter = is_numeric($validTo) ? Carbon::createFromTimestampUTC((int) $validTo) : null;

            $issuerParts = is_array($certificate['issuer'] ?? null) ? $certificate['issuer'] : [];
            $name = $issuerParts['CN'] ?? $issuerParts['O'] ?? null;
            $issuer = is_string($name) ? substr($name, 0, 255) : null;

            $printed = $certificate['docup_fingerprint'] ?? null;
            $fingerprint = is_string($printed) ? $printed : null;
        }

        if ($result['trusted'] && $notAfter !== null && $issuer !== null && $fingerprint !== null) {
            return TlsProbe::succeeded($host, $notAfter, $issuer, $fingerprint);
        }

        /*
         * 🛑 A trusted handshake whose certificate could not be read is
         * still a failure here, and that is not pedantry. §8.10.17 asks for
         * "expiry, issuer and error"; a row with none of the three is a
         * probe that ran and learned nothing, and recording it as a success
         * would mean the one thing worse than no observability — the
         * appearance of it.
         */
        return TlsProbe::failed($host, $result['error'] ?? 'the peer presented no readable certificate');
    }

    private function record(Domain $domain, string $reason, string $detail): void
    {
        CertificateIssuanceAttempt::query()->create([
            'host' => $domain->host,
            'registered_domain' => RegisteredDomain::fromConfig($domain->host),
            'source' => 'edge',
            'outcome' => 'failed',
            'reason' => $reason,
            'detail' => substr($detail, 0, 512),
            'attempted_at' => $this->now(),
        ]);
    }

    private function warningDays(): int
    {
        $days = config('tls.probe.expiry_warning_days');

        return is_int($days) ? $days : 21;
    }

    private function now(): Carbon
    {
        return ($this->now ?? Carbon::now())->copy();
    }
}
