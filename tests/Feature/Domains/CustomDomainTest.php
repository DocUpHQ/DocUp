<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Domains;

use App\Artifacts\Publisher;
use App\Auth\AccessLevel;
use App\Auth\OrganisationContext;
use App\Composition\Components;
use App\Composition\Mounts;
use App\Domains\AgreeingResolvers;
use App\Domains\Challenge;
use App\Domains\DnsInstructions;
use App\Domains\DomainLedger;
use App\Domains\DomainRefused;
use App\Domains\DomainRejection;
use App\Domains\Domains;
use App\Domains\DomainVerifier;
use App\Domains\HstsPolicy;
use App\Domains\Reverification;
use App\Models\Build;
use App\Models\Domain;
use App\Models\DomainEvent;
use App\Models\DomainTombstone;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Support\Uuid;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Storage;
use Illuminate\Testing\TestResponse;
use Symfony\Component\HttpFoundation\Response;
use Tests\Support\ArchiveWriter;
use Tests\Support\FakeDnsRecords;
use Tests\TestCase;

/**
 * 🛑 Phase 18's exit criteria.
 *
 * > "Add two domains, see the exact CNAME and TXT records, watch validation
 * > fail without the record and pass with it, then see **both serve 200**
 * > while the default subdomain also serves 200 and exactly one
 * > `rel=canonical` is emitted. Releasing a domain makes it unclaimable by
 * > another organisation until the tombstone expires, and reclaimable by the
 * > original owner only with a fresh token. A squatter's pending claim
 * > provably does **not** block the legitimate owner. 🛑 `includeSubDomains`
 * > on a shared apex is a validation error."
 *
 * The DNS is faked and nothing else is: the resolvers answer from a script
 * because §8.10.6 wants two of them to agree and no test can arrange real
 * disagreement, but the records checked are the ones
 * {@see DnsInstructions} printed, the verification is the real one, and the
 * three hostnames are served through the real route table.
 */
final class CustomDomainTest extends TestCase
{
    use DatabaseTransactions;

    private OrganisationContext $context;

    private Organisation $organisation;

    private Project $project;

    private ProjectVersion $version;

    private Domains $domains;

    private string $subdomain;

    private string $fixtures;

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('artifacts');
        Cache::flush();

        $this->fixtures = sys_get_temp_dir().'/docup-p18-'.getmypid();

        if (! is_dir($this->fixtures)) {
            mkdir($this->fixtures, 0o755, true);
        }

        $this->context = app(OrganisationContext::class);
        $this->context->spanAllOrganisations();

        $this->organisation = Organisation::query()->create([
            'name' => 'Hosted Co',
            'slug' => 'hosted-'.bin2hex(random_bytes(4)),
        ]);

        $this->context->for($this->organisation->id);

        $slug = 'manual-'.bin2hex(random_bytes(3));
        $this->subdomain = $slug.'.'.$this->docsApex();

        $this->project = Project::query()->create([
            'slug' => $slug,
            'name' => 'Manual',
            'visibility' => 'public',
        ]);

        $this->version = new ProjectVersion;
        $this->version->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'project_id' => $this->project->id,
            'slug' => 'v1',
            'kind' => 'channel',
            'language' => 'en',
            'visibility' => 'public',
        ])->save();

        $this->project->forceFill(['default_version_id' => $this->version->id])->save();

        $this->domains = new Domains;
    }

    protected function tearDown(): void
    {
        $this->context->forget();

        if (is_dir($this->fixtures)) {
            foreach ((array) glob($this->fixtures.'/*') as $file) {
                if (is_string($file)) {
                    @unlink($file);
                }
            }

            @rmdir($this->fixtures);
        }

        parent::tearDown();
    }

    // ------------------------------------------------------- exit criterion 1

    /**
     * 🛑 Two domains, the exact records, a failing check, a passing one, and
     * three hostnames serving 200 with exactly one `rel=canonical`.
     */
    public function test_two_verified_domains_and_the_default_subdomain_all_serve(): void
    {
        $this->publishTheDefaultSubdomain();

        $first = $this->domains->add($this->organisation->id, 'docs.acme.example');
        $second = $this->domains->add($this->organisation->id, 'manual.acme.example');

        /*
         * 🛑 "see the exact CNAME and TXT records". The test reads them from
         * the instructions rather than restating them, so a change to either
         * that did not change the other fails here — which is the only way
         * "the records we showed are the records we check" can be asserted
         * rather than hoped for.
         */
        $instructions = DnsInstructions::for($first, $this->docsApex());

        $this->assertFalse($instructions->isApex);
        $this->assertSame('CNAME', $instructions->records[0]['type']);
        $this->assertSame('docs.acme.example', $instructions->records[0]['name']);
        $this->assertSame(
            Challenge::cnameTarget(Uuid::toBytes($first->id), $this->docsApex()),
            $instructions->records[0]['value'],
        );
        $this->assertSame('TXT', $instructions->alternatives[0]['type']);
        $this->assertSame('_docup-challenge.docs.acme.example', $instructions->alternatives[0]['name']);
        $this->assertSame($first->verification_token, $instructions->alternatives[0]['value']);

        // 🛑 "watch validation fail without the record"
        try {
            $this->domains->verify($first, $this->verifierSeeing([]));
            $this->fail('verification passed with no record published');
        } catch (DomainRefused $refused) {
            $this->assertSame(DomainRejection::ProofMissing, $refused->rejection);
        }

        $this->assertSame('pending', $this->refreshed($first)->state);

        // 🛑 "and pass with it" — publishing exactly what was printed.
        $this->domains->verify($first, $this->verifierSeeingInstructions($first));
        $this->domains->verify($second, $this->verifierSeeingInstructions($second, useTxt: true));

        $this->assertSame('active', $this->refreshed($first)->state);
        $this->assertSame('cname', $this->refreshed($first)->verification_method);
        $this->assertSame('dns_txt', $this->refreshed($second)->verification_method);

        $this->domains->mount($first, $this->project);
        $this->domains->mount($second, $this->project);

        Cache::flush();

        // 🛑 "then see both serve 200 while the default subdomain also serves 200"
        foreach ([$this->subdomain, 'docs.acme.example', 'manual.acme.example'] as $host) {
            $this->getExactly("http://{$host}/en/v1/index.html")->assertOk();
        }

        /*
         * 🛑 "exactly one `rel=canonical` is emitted", and it points at the
         * canonical mount from every one of the three hosts. §8.10.2 makes
         * every verified domain answer 200 rather than redirect, so this
         * header is the only thing stopping three hostnames looking like
         * three copies of one site.
         */
        foreach ([$this->subdomain, 'docs.acme.example', 'manual.acme.example'] as $host) {
            $link = (string) $this->getExactly("http://{$host}/en/v1/index.html")->headers->get('Link');

            $this->assertSame(
                1,
                substr_count($link, 'rel="canonical"'),
                $host.' emitted '.substr_count($link, 'rel="canonical"').' canonical links',
            );

            $this->assertStringContainsString(
                '<https://'.$this->subdomain.'/en/v1/index.html>; rel="canonical"',
                $link,
                $host.' must point at the default subdomain, which is the canonical mount',
            );
        }

        // §8.10.2's derived indexability: the aliases are noindex, the
        // canonical mount is not.
        $this->assertNull($this->getExactly("http://{$this->subdomain}/en/v1/index.html")->headers->get('X-Robots-Tag'));
        $this->assertSame('noindex', $this->getExactly('http://docs.acme.example/en/v1/index.html')->headers->get('X-Robots-Tag'));
    }

    /** 🛑 §8.10.4: an unverified host serves nothing, mounted or not. */
    public function test_an_unverified_host_serves_nothing(): void
    {
        $this->publishTheDefaultSubdomain();

        $pending = $this->domains->add($this->organisation->id, 'docs.acme.example');
        $this->domains->mount($pending, $this->project);

        Cache::flush();

        $this->getExactly('http://docs.acme.example/en/v1/index.html')->assertNotFound();
    }

    /** And a suspended one stops, which is the other half of §8.10.6. */
    public function test_a_suspended_host_stops_serving(): void
    {
        $this->publishTheDefaultSubdomain();

        $domain = $this->verifiedDomain('docs.acme.example');
        $this->domains->mount($domain, $this->project);

        Cache::flush();
        $this->getExactly('http://docs.acme.example/en/v1/index.html')->assertOk();

        $domain->forceFill(['state' => 'suspended', 'suspended_at' => now()])->save();
        Cache::flush();

        $this->getExactly('http://docs.acme.example/en/v1/index.html')->assertNotFound();
    }

    // ------------------------------------------------------- exit criterion 2

    /**
     * 🛑 "Releasing a domain makes it unclaimable by another organisation
     * until the tombstone expires, and reclaimable by the original owner
     * only with a fresh token."
     */
    public function test_a_released_domain_is_tombstoned_and_reclaimable_only_by_its_owner(): void
    {
        $domain = $this->verifiedDomain('docs.acme.example');
        $originalToken = (string) $domain->verification_token;

        $tombstone = $this->domains->release($domain);

        $this->assertSame(
            DomainTombstone::DAYS,
            (int) round($tombstone->released_at?->diffInDays($tombstone->expires_at) ?? 0),
        );

        // 🛑 Another organisation cannot take it.
        $squatter = $this->otherOrganisation();

        try {
            $this->domains->add($squatter->id, 'docs.acme.example');
            $this->fail('a tombstoned hostname was claimed by another organisation');
        } catch (DomainRefused $refused) {
            $this->assertSame(DomainRejection::Tombstoned, $refused->rejection);
        }

        // 🛑 The original owner can, and gets a **fresh** token.
        $reclaimed = $this->domains->reclaim($this->organisation->id, 'docs.acme.example');

        $this->assertNotSame($originalToken, $reclaimed->verification_token);
        $this->assertSame('pending', $reclaimed->state, 'a reclaim proves control again');

        $this->assertSame(
            0,
            DomainTombstone::query()->where('host', 'docs.acme.example')->count(),
            'the tombstone is consumed by the reclaim',
        );
    }

    /** Once the tombstone lapses, anybody may claim the hostname. */
    public function test_a_lapsed_tombstone_releases_the_hostname(): void
    {
        $domain = $this->verifiedDomain('docs.acme.example');
        $tombstone = $this->domains->release($domain);

        $tombstone->forceFill(['expires_at' => now()->subDay()])->save();

        $squatter = $this->otherOrganisation();
        $taken = $this->domains->add($squatter->id, 'docs.acme.example');

        $this->assertSame($squatter->id, $taken->organisation_id);
    }

    // ------------------------------------------------------- exit criterion 3

    /**
     * 🛑 "A squatter's pending claim provably does **not** block the
     * legitimate owner."
     *
     * This is §8.10.5's whole reason for the generated column: "An
     * unconditional unique index lets a squatter's pending row block the
     * legitimate owner." The squatter here does everything an attacker can
     * do without controlling the DNS — adds the row, and waits.
     */
    public function test_a_squatters_pending_claim_does_not_block_the_owner(): void
    {
        $squatter = $this->otherOrganisation();

        $pending = $this->domains->add($squatter->id, 'docs.acme.example');

        $this->assertSame('pending', $pending->state);
        $this->assertNull(
            DB::table('domains')->where('id', $pending->id)->value('claimed_host'),
            'an unproven row contributes nothing to the uniqueness index',
        );

        // 🛑 The owner adds and proves the same hostname, unobstructed.
        $owned = $this->domains->add($this->organisation->id, 'docs.acme.example');
        $this->domains->verify($owned, $this->verifierSeeingInstructions($owned));

        $this->assertSame('active', $this->refreshed($owned)->state);

        // And now the squatter's own proof cannot land, because the index
        // holds exactly one proven claim.
        try {
            $this->domains->verify($pending->refresh(), $this->verifierSeeingInstructions($pending));
            $this->fail('two organisations proved one hostname');
        } catch (DomainRefused $refused) {
            $this->assertSame(DomainRejection::HostClaimed, $refused->rejection);
        }
    }

    /**
     * 🛑 §8.10.4's parent claim excludes other organisations from everything
     * under it.
     */
    public function test_a_proven_parent_claim_excludes_other_organisations(): void
    {
        $claim = $this->domains->claimParent($this->organisation->id, 'acme.example');

        $this->domains->verifyParent($claim, $this->verifierSeeing([
            '_docup-challenge.acme.example' => [$claim->token],
        ]));

        $squatter = $this->otherOrganisation();

        try {
            $this->domains->add($squatter->id, 'docs.acme.example');
            $this->fail('another organisation bound a host under a proven parent claim');
        } catch (DomainRefused $refused) {
            $this->assertSame(DomainRejection::ParentClaimed, $refused->rejection);
        }

        /*
         * 🛑 And the claimant's own hosts bind with **no further proof**,
         * which is the other half of §8.10.4 and the reason the mechanism
         * exists at all.
         */
        $bound = $this->domains->add($this->organisation->id, 'docs.acme.example');
        $this->domains->verify($bound, $this->verifierSeeing([]));

        $this->assertSame('active', $this->refreshed($bound)->state);
        $this->assertSame('parent_claim', $this->refreshed($bound)->verification_method);
    }

    // ------------------------------------------------------- exit criterion 4

    /**
     * 🛑 "`includeSubDomains` on a shared apex is a validation error."
     */
    public function test_include_subdomains_is_refused_on_a_shared_apex(): void
    {
        $apex = $this->verifiedDomain('acme.example');

        $second = Project::query()->create([
            'slug' => 'second-'.bin2hex(random_bytes(3)),
            'name' => 'Second',
            'visibility' => 'public',
        ]);

        $this->domains->mount($apex, $this->project, '');
        $this->domains->mount($apex, $second, 'second');

        $this->assertTrue($this->refreshed($apex)->shared_origin, '§8.10.20 derives the flag from the mount count');

        try {
            HstsPolicy::assertUsable($this->refreshed($apex), 31_536_000, true, false, []);
            $this->fail('includeSubDomains was accepted on a shared apex');
        } catch (DomainRefused $refused) {
            $this->assertSame(DomainRejection::HstsWouldSpanTenants, $refused->rejection);
        }
    }

    /**
     * 🛑 And on a hostname that is a DNS suffix of another claimed one, even
     * when it is not itself shared.
     *
     * This is the case the requirement spells out separately and it is the
     * more dangerous of the two: `acme.example` is one tenant's, nothing on
     * it is shared, and `includeSubDomains` there still decides HTTPS for
     * `legacy.acme.example`, which belongs to somebody else.
     */
    public function test_include_subdomains_is_refused_over_another_tenants_host(): void
    {
        $apex = $this->verifiedDomain('acme.example');

        try {
            HstsPolicy::assertUsable($apex, 31_536_000, true, false, ['legacy.acme.example']);
            $this->fail('includeSubDomains was accepted over another claimed host');
        } catch (DomainRefused $refused) {
            $this->assertSame(DomainRejection::HstsWouldSpanTenants, $refused->rejection);
            $this->assertStringContainsString('legacy.acme.example', $refused->getMessage());
        }
    }

    /** HSTS is off by default, and a plain policy on an unshared host is fine. */
    public function test_hsts_is_off_by_default_and_permitted_where_it_is_safe(): void
    {
        $domain = $this->verifiedDomain('docs.acme.example');

        $this->assertNull($domain->hsts_max_age);
        $this->assertNull(HstsPolicy::header($domain));

        HstsPolicy::assertUsable($domain, 31_536_000, true, false, ['other.example']);

        $domain->forceFill([
            'hsts_max_age' => 31_536_000,
            'hsts_include_subdomains' => true,
        ])->save();

        $this->assertSame('max-age=31536000; includeSubDomains', HstsPolicy::header($domain));
    }

    // ------------------------------------------------- §8.10.6's state machine

    /**
     * 🛑 "warning at the first failure, not the twenty-ninth", and suspension
     * seven days later.
     */
    public function test_a_withdrawn_record_warns_at_once_and_suspends_after_the_grace(): void
    {
        $domain = $this->verifiedDomain('docs.acme.example');

        $blind = new Reverification($this->verifierSeeing([]));

        $this->assertSame('failing', $blind->check($domain));
        $this->assertSame('failing', $this->refreshed($domain)->state);

        // 🛑 The warning is recorded on the FIRST failure.
        $this->assertSame(
            1,
            DomainEvent::query()->where('host', 'docs.acme.example')->where('event', 'failing')->count(),
        );

        // Still serving, which is what the grace period is for.
        $this->assertTrue($this->refreshed($domain)->canServe());

        // Seven days later, with the record still gone.
        $domain->forceFill([
            'failing_since' => now()->subDays(Reverification::GRACE_DAYS + 1),
            'next_check_at' => now()->subHour(),
        ])->save();

        $this->assertSame('suspended', $blind->check($domain->refresh()));
        $this->assertFalse($this->refreshed($domain)->canServe());
    }

    /**
     * 🛑 A resolver outage moves nothing.
     *
     * Without this, one bad hour at a DoH provider starts a seven-day
     * suspension clock on every custom domain in the installation at once.
     */
    public function test_a_resolver_outage_does_not_start_the_clock(): void
    {
        $domain = $this->verifiedDomain('docs.acme.example');

        $down = new Reverification(new DomainVerifier(
            new AgreeingResolvers([(new FakeDnsRecords('a'))->down()->withCname('docs.acme.example', null)]),
            $this->docsApex(),
        ));

        $this->assertSame('inconclusive', $down->check($domain));

        $after = $this->refreshed($domain);

        $this->assertSame('active', $after->state);
        $this->assertSame(0, $after->check_failures);
        $this->assertNull($after->failing_since);
    }

    /** A recovered domain comes back without anybody doing anything. */
    public function test_a_restored_record_clears_the_failing_state(): void
    {
        $domain = $this->verifiedDomain('docs.acme.example');

        (new Reverification($this->verifierSeeing([])))->check($domain);
        $this->assertSame('failing', $this->refreshed($domain)->state);

        $restored = new Reverification($this->verifierSeeingInstructions($domain->refresh()));

        $this->assertSame('passed', $restored->check($domain->refresh()));
        $this->assertSame('active', $this->refreshed($domain)->state);
        $this->assertNull($this->refreshed($domain)->failing_since);
    }

    /** 🛑 §8.10.6: the resolvers disagreeing is not a pass. */
    public function test_disagreeing_resolvers_never_verify(): void
    {
        $domain = $this->domains->add($this->organisation->id, 'docs.acme.example');
        $target = Challenge::cnameTarget(Uuid::toBytes($domain->id), $this->docsApex());

        $verifier = new DomainVerifier(new AgreeingResolvers([
            (new FakeDnsRecords('sees-it'))->withCname('docs.acme.example', $target),
            (new FakeDnsRecords('does-not'))->withCname('docs.acme.example', ''),
        ]), $this->docsApex());

        try {
            $this->domains->verify($domain, $verifier);
            $this->fail('a disagreement verified a hostname');
        } catch (DomainRefused $refused) {
            $this->assertSame(DomainRejection::ResolversDisagreed, $refused->rejection);
        }

        $this->assertSame('pending', $this->refreshed($domain)->state);
    }

    // ----------------------------------------------------------- the ledger

    /** §10.5's hash chain over a hostname's life. */
    public function test_the_domain_event_chain_verifies(): void
    {
        $domain = $this->verifiedDomain('docs.acme.example');
        $this->domains->release($domain);

        $ledger = new DomainLedger;

        $this->assertTrue($ledger->verify($this->organisation->id));

        // 🛑 And a rewritten row breaks it, which is the only property that
        // makes the chain worth having.
        $event = DomainEvent::query()->where('event', 'released')->firstOrFail();
        $event->forceFill(['host' => 'elsewhere.example'])->save();

        $this->assertFalse($ledger->verify($this->organisation->id));
    }

    /** §8.10.8's apex case: no CNAME, and the A-record advantage is stated. */
    public function test_an_apex_gets_its_own_instructions(): void
    {
        $apex = $this->domains->add($this->organisation->id, 'acme.example');

        $this->assertSame('apex', $apex->kind);

        $instructions = DnsInstructions::for($apex, $this->docsApex(), ['203.0.113.10', '2001:db8::1']);

        $this->assertTrue($instructions->isApex);
        $this->assertSame(['TXT'], array_column($instructions->records, 'type'));
        $this->assertSame(['ALIAS', 'A', 'AAAA'], array_column($instructions->alternatives, 'type'));

        $this->assertStringContainsString(
            'a hosted documentation service cannot offer you',
            $instructions->alternatives[1]['note'],
        );
    }

    // ---------------------------------------------------------------- helpers

    /**
     * The row as the database now holds it.
     *
     * `fresh()` is nullable because a row can be deleted underneath you, and
     * in these tests it never is - so the assertion documents that and keeps
     * every call site free of a null check that would only ever be noise.
     */
    private function refreshed(Domain $domain): Domain
    {
        $fresh = $domain->fresh();

        $this->assertInstanceOf(Domain::class, $fresh, $domain->host.' disappeared');

        return $fresh;
    }

    private function verifiedDomain(string $host): Domain
    {
        $domain = $this->domains->add($this->organisation->id, $host);

        return $this->domains->verify($domain, $this->verifierSeeingInstructions($domain));
    }

    /**
     * A verifier whose two resolvers both see exactly these TXT records.
     *
     * @param  array<string, list<string>>  $txt
     */
    private function verifierSeeing(array $txt): DomainVerifier
    {
        $resolvers = [];

        foreach (['alpha', 'beta'] as $label) {
            $resolver = new FakeDnsRecords($label);

            foreach ($txt as $name => $values) {
                $resolver->withTxt($name, $values);
            }

            $resolvers[] = $resolver;
        }

        return new DomainVerifier(new AgreeingResolvers($resolvers), $this->docsApex());
    }

    /**
     * 🛑 A verifier that sees exactly what {@see DnsInstructions} printed.
     *
     * The point of reading the instructions rather than rebuilding the
     * values: if the two ever disagree, an operator who copies what the
     * dashboard shows fails verification, and this is the test that would
     * have told us.
     */
    private function verifierSeeingInstructions(Domain $domain, bool $useTxt = false): DomainVerifier
    {
        $instructions = DnsInstructions::for($domain, $this->docsApex());

        $record = $useTxt || $instructions->isApex
            ? $instructions->records[0]
            : $instructions->records[0];

        if ($useTxt && ! $instructions->isApex) {
            $record = $instructions->alternatives[0];
        }

        if ($record['type'] === 'TXT') {
            return $this->verifierSeeing([$record['name'] => [$record['value']]]);
        }

        $resolvers = [];

        foreach (['alpha', 'beta'] as $label) {
            $resolvers[] = (new FakeDnsRecords($label))->withCname($record['name'], $record['value']);
        }

        return new DomainVerifier(new AgreeingResolvers($resolvers), $this->docsApex());
    }

    private function otherOrganisation(): Organisation
    {
        return $this->context->acrossAllOrganisations(fn (): Organisation => Organisation::query()->create([
            'name' => 'Squatter Co',
            'slug' => 'squatter-'.bin2hex(random_bytes(4)),
        ]));
    }

    /** The project on its default subdomain, with a real published build. */
    private function publishTheDefaultSubdomain(): void
    {
        $domainId = Uuid::v7();

        DB::table('domains')->insert([
            'id' => $domainId,
            'organisation_id' => $this->organisation->id,
            'host' => $this->subdomain,
            'kind' => 'default_subdomain',
            'state' => 'active',
            'verified_at' => now(),
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        DB::table('domain_mounts')->insert([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'domain_id' => $domainId,
            'project_id' => $this->project->id,
            'path_prefix' => '',
            'mode' => 'canonical',
            'mount_exposure' => 'inherit',
            'position' => 0,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $component = (new Components)->register(
            organisationId: $this->organisation->id,
            key: 'manual-'.bin2hex(random_bytes(4)),
            name: 'Manual',
            minAccess: AccessLevel::Public,
        );

        (new Mounts)->attach($this->version, $component, '', isPrimary: true);

        $archive = (new ArchiveWriter)
            ->add('html/index.html', "<!doctype html><html><head></head><body>manual</body></html>\n")
            ->toTarGz($this->fixtures.'/t-'.bin2hex(random_bytes(4)).'.tar.gz');

        $build = app(Publisher::class)->publishUpload($this->version, $archive)->build;

        $this->assertInstanceOf(Build::class, $build);

        Cache::flush();
    }

    private function docsApex(): string
    {
        $apex = config('docup.origins.docs');

        return is_string($apex) && $apex !== '' ? $apex : 'docup-docs.test';
    }

    /** @return TestResponse<Response> */
    private function getExactly(string $url): TestResponse
    {
        /** @var TestResponse<Response> */
        return TestResponse::fromBaseResponse($this->app->handle(Request::create($url, 'GET')));
    }
}
