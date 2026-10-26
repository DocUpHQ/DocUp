<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Domains;

use App\Egress\HardenedEgressClient;
use App\Models\Domain;
use App\Models\DomainClaim;
use App\Models\DomainVerificationEvent;
use App\Support\Uuid;
use Illuminate\Support\Facades\DB;

/**
 * 🛑 §8.10.4's three proofs, run against two agreeing resolvers.
 *
 * > "Proof of domain control MUST precede any certificate issuance or **any
 * > byte served for a custom hostname**."
 *
 * The three mechanisms are tried in the order an operator would reach for
 * them, and the order is not arbitrary:
 *
 * 1. **parent claim** — already proven at the organisation level, so there
 *    is nothing to publish and nothing to check in DNS for this host. It is
 *    first because a host under a claimed apex should bind with no work.
 * 2. **CNAME** — one record that is simultaneously route and proof, so an
 *    operator who published it is finished.
 * 3. **per-host TXT** — the apex case, and the fallback for a provider that
 *    cannot CNAME where you need it.
 *
 * Every attempt is recorded (§8.10.6: "Every check MUST be recorded
 * append-only and retained 400 days"), including the ones that passed, and
 * including what each resolver said.
 */
final readonly class DomainVerifier
{
    public function __construct(
        private AgreeingResolvers $resolvers,
        private ?string $docsApex = null,
    ) {}

    /**
     * Check a domain's proof without changing its state.
     *
     * Separated from {@see Domains::verify()} on purpose: this is the part
     * that talks to the network and the part a daily re-verification run
     * repeats, while state transitions belong to the write service. Mixing
     * them would make the re-verification job the second place that decides
     * what `failing` means.
     */
    public function check(Domain $domain): VerificationResult
    {
        $apex = $this->docsApex ?? self::configuredApex();

        $parent = $this->parentClaim($domain);

        if ($parent instanceof DomainClaim) {
            /*
             * 🛑 No DNS lookup. The apex's own proof is what stands here, and
             * re-checking the host would defeat the mechanism: §8.10.4 says
             * "any host under it binds with **no further proof**".
             */
            return $this->record($domain, VerificationMethod::ParentClaim, Outcome::Answered, true, [
                'apex' => $parent->apex,
            ], 'bound under a proven parent claim');
        }

        $cname = $this->resolvers->cname($domain->host);
        $expected = Challenge::cnameTarget(Uuid::toBytes($domain->id), $apex);

        if ($cname->contains($expected)) {
            return $this->record($domain, VerificationMethod::Cname, $cname->outcome, true, $cname->observed);
        }

        $txt = $this->resolvers->txt(Challenge::txtName($domain->host));
        $token = (string) $domain->verification_token;

        if ($token !== '' && $txt->contains($token)) {
            return $this->record($domain, VerificationMethod::DnsTxt, $txt->outcome, true, $txt->observed);
        }

        /*
         * 🛑 Neither proof is present. Which failure is reported depends on
         * whether the resolvers could answer at all, because §8.10.6's state
         * machine treats the two completely differently — a withdrawn record
         * starts a seven-day grace, a resolver outage must not.
         */
        $outcome = match (true) {
            $cname->outcome === Outcome::Disagreed || $txt->outcome === Outcome::Disagreed => Outcome::Disagreed,
            $cname->outcome === Outcome::Unresolvable && $txt->outcome === Outcome::Unresolvable => Outcome::Unresolvable,
            default => Outcome::Answered,
        };

        return $this->record(
            $domain,
            VerificationMethod::Cname,
            $outcome,
            false,
            ['cname' => $cname->observed, 'txt' => $txt->observed],
            match ($outcome) {
                Outcome::Disagreed => 'the resolvers disagreed',
                Outcome::Unresolvable => 'no resolver answered',
                default => 'neither the CNAME nor the TXT record was found',
            },
        );
    }

    /** Check an organisation-level parent claim's own TXT record. */
    public function checkClaim(DomainClaim $claim): bool
    {
        $txt = $this->resolvers->txt(Challenge::txtName($claim->apex));

        return $txt->contains($claim->token);
    }

    /**
     * The proven parent claim covering this host, if any.
     *
     * 🛑 Restricted to the domain's **own** organisation. A claim held by
     * somebody else over the same apex does not bind this host — it excludes
     * it, which {@see Domains} refuses at write time. Reading the claim
     * without the organisation filter here would turn the exclusion into a
     * free pass.
     */
    private function parentClaim(Domain $domain): ?DomainClaim
    {
        $apexes = Hostname::parentApexes($domain->host);

        if ($apexes === []) {
            return null;
        }

        return DomainClaim::query()
            ->where('organisation_id', $domain->organisation_id)
            ->where('state', 'verified')
            ->whereNotNull('verified_at')
            ->whereIn('apex', $apexes)
            ->orderByRaw('LENGTH(apex) DESC')
            ->first();
    }

    /**
     * @param  array<string, mixed>  $observed
     */
    private function record(
        Domain $domain,
        VerificationMethod $method,
        Outcome $outcome,
        bool $passed,
        array $observed,
        string $detail = '',
    ): VerificationResult {
        $recorded = $passed ? 'passed' : match ($outcome) {
            Outcome::Disagreed => 'disagreed',
            Outcome::Unresolvable => 'unresolvable',
            Outcome::Answered => 'failed',
        };

        $event = new DomainVerificationEvent;

        $event->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $domain->organisation_id,
            'domain_id' => $domain->id,
            'method' => $method->value,
            'outcome' => $recorded,
            'observed' => $observed === [] ? null : $observed,
            'detail' => $detail === '' ? null : mb_strcut($detail, 0, 512),
            'checked_at' => now(),
        ])->save();

        return new VerificationResult($passed, $method, $outcome, $detail);
    }

    /** The resolvers a running installation uses, from configuration. */
    public static function fromConfig(): self
    {
        /** @var list<DnsRecords> $resolvers */
        $resolvers = [];

        foreach (self::configuredResolvers() as $label => $endpoint) {
            $resolvers[] = new DohRecords(app(HardenedEgressClient::class), $endpoint, $label);
        }

        return new self(new AgreeingResolvers($resolvers));
    }

    /** @return array<string, string> */
    private static function configuredResolvers(): array
    {
        $configured = config('domains.resolvers');
        $resolvers = [];

        foreach (is_array($configured) ? $configured : [] as $label => $endpoint) {
            if (is_string($label) && is_string($endpoint) && $endpoint !== '') {
                $resolvers[$label] = $endpoint;
            }
        }

        return $resolvers;
    }

    private static function configuredApex(): string
    {
        $apex = config('docup.origins.docs');

        return is_string($apex) && $apex !== '' ? $apex : 'localhost';
    }

    /**
     * Purge verification events past §8.10.6's 400-day retention.
     *
     * Deleted rather than partitioned, unlike `audit_events`: this is
     * operational telemetry with no evidentiary chain over it, so a plain
     * delete is honest and a partition would be machinery nobody needs.
     */
    public static function purge(): int
    {
        return DB::table('domain_verification_events')
            ->where('checked_at', '<', now()->subDays(DomainVerificationEvent::RETENTION_DAYS))
            ->delete();
    }
}
