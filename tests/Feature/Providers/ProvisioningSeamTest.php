<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Providers;

use App\Auth\OrganisationContext;
use App\Auth\Providers\BindingContext;
use App\Auth\Providers\BindingState;
use App\Auth\Providers\Federation\ProvisioningAction;
use App\Auth\Providers\Federation\ProvisioningDriver;
use App\Auth\Providers\Federation\ProvisioningIntent;
use App\Auth\Providers\Federation\ProvisioningLatency;
use App\Auth\Providers\Federation\ProvisioningRefused;
use App\Auth\Providers\Federation\ReaderProvisioning;
use App\Auth\Providers\Federation\ReaderSubject;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\ReaderIdentity;
use App\Readers\Grants\GrantMinter;
use App\Readers\ReaderSessions;
use App\Support\Uuid;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Tests\TestCase;

/**
 * 🛑 §8.12.26's `ProvisioningDriver` seam, and the write side of an identity
 * lifecycle whose read side has been complete for three phases.
 *
 * > "**[P2]** SCIM 2.0 inbound provisioning, at installation and organisation
 * > scope only. The `ProvisioningDriver` seam ships in v1 and the documentation
 * > states the deprovisioning latency honestly: epoch bump plus grant TTL plus
 * > the refresh-session ceiling."
 *
 * ## 🛑 The column nothing wrote
 *
 * `reader_identities.deprovisioned_at` has existed since Phase 24. The login
 * path refuses on it and §8.12.25's simulator refuses on it — and nothing in
 * the product ever set it, so both refusals were correct over a column that was
 * always null. The same shape as `reader_groups` and `cidr_allowlist` earlier in
 * this phase, and the third time this phase found it.
 */
final class ProvisioningSeamTest extends TestCase
{
    use DatabaseTransactions;

    /**
     * The one binding every intent in this file is pushed against.
     *
     * 🛑 A real UUIDv7 rather than sixteen repeated bytes: `Uuid::toText()`
     * refuses anything that is neither canonical text nor 16 bytes it
     * recognises, and the audit payload calls it. A fabricated id passed
     * every assertion in this file and threw inside the audit record, which
     * is the guard doing its job one layer further in than expected.
     */
    private string $bindingId;

    private OrganisationContext $context;

    private Organisation $organisation;

    private Project $project;

    private string $domainId;

    protected function setUp(): void
    {
        parent::setUp();

        $this->bindingId = Uuid::v7();

        $this->context = app(OrganisationContext::class);
        $this->context->spanAllOrganisations();

        $this->organisation = Organisation::query()->create([
            'name' => 'Provisioning Fixture',
            'slug' => 'prov-'.bin2hex(random_bytes(4)),
        ]);

        $this->context->for($this->organisation->id);

        $this->project = Project::query()->create([
            'organisation_id' => $this->organisation->id,
            'name' => 'Docs',
            'slug' => 'docs-'.bin2hex(random_bytes(4)),
            'visibility' => 'members',
        ]);

        $this->domainId = Uuid::v7();

        DB::table('domains')->insert([
            'id' => $this->domainId,
            'organisation_id' => $this->organisation->id,
            'host' => 'prov-'.bin2hex(random_bytes(4)).'.example.test',
            'kind' => 'custom',
            'state' => 'active',
            'tls_mode' => 'managed',
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        /*
         * 🛑 A real binding row, because `reader_identities.binding_id`
         * carries a foreign key with `ON DELETE RESTRICT` — §8.12.19's
         * "a referenced binding MUST NOT be deletable" as a database
         * constraint. A fabricated id passes every assertion in this file and
         * fails the insert, which is the constraint doing its job.
         *
         * Inserted rather than minted through `Bindings::create()`, because
         * `scim` is a PROVISIONING type and not an `AuthComponent`: the two
         * registries are deliberately separate, which is the point
         * {@see \App\Auth\Providers\Federation\ProvisioningDriver::type()}
         * makes.
         */
        DB::table('auth_provider_bindings')->insert([
            'id' => $this->bindingId,
            'organisation_id' => $this->organisation->id,
            'scope_type' => 'organisation',
            'scope_id' => $this->organisation->id,
            'type' => 'scim',
            'name' => 'Corporate directory',
            'config' => '{}',
            'state' => 'active',
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }

    protected function tearDown(): void
    {
        $this->context->forget();

        parent::tearDown();
    }

    // ------------------------------------------------------- the write side

    /** An inbound create makes an identity that did not exist. */
    public function test_an_inbound_create_provisions_an_identity(): void
    {
        $changed = app(ReaderProvisioning::class)->apply(
            $this->binding(),
            new ProvisioningIntent(ProvisioningAction::Create, 'dir-user-1', displayLabel: 'Alice'),
        );

        $this->assertTrue($changed);

        $identity = $this->identityFor('dir-user-1');

        $this->assertNotNull($identity);
        $this->assertNull($identity->deprovisioned_at);
    }

    /**
     * 🛑 A deactivation stamps `deprovisioned_at` — the write the product never
     * had — and revokes every session.
     */
    public function test_a_deactivation_stamps_the_column_and_revokes_the_sessions(): void
    {
        $provisioning = app(ReaderProvisioning::class);
        $binding = $this->binding();

        $provisioning->apply($binding, new ProvisioningIntent(ProvisioningAction::Create, 'dir-user-2'));

        $identity = $this->identityFor('dir-user-2');
        $this->assertNotNull($identity);

        $sessionId = $this->sessionFor($identity);

        $this->assertTrue($provisioning->apply(
            $binding,
            new ProvisioningIntent(ProvisioningAction::Deactivate, 'dir-user-2'),
        ));

        $deprovisioned = $this->identityFor('dir-user-2');

        $this->assertNotNull($deprovisioned);
        $this->assertNotNull($deprovisioned->deprovisioned_at);

        /*
         * 🛑 The revocation is not tidiness: it is what makes
         * {@see ProvisioningLatency::seconds()} the grant TTL rather than the
         * session's absolute ceiling. A session left alive could mint a fresh
         * grant on its next request.
         */
        $session = DB::table('docs_sessions')->where('id', $sessionId)->first();

        $this->assertNotNull($session?->revoked_at, '🛑 a deprovisioned reader kept a live session');
        $this->assertSame('deprovisioned', $session->revoked_reason);
    }

    /** 🛑 And a reactivation clears it, with the memberships still there. */
    public function test_a_reactivation_clears_the_column(): void
    {
        $provisioning = app(ReaderProvisioning::class);
        $binding = $this->binding();

        $provisioning->apply($binding, new ProvisioningIntent(ProvisioningAction::Create, 'dir-user-3'));
        $provisioning->apply($binding, new ProvisioningIntent(ProvisioningAction::Deactivate, 'dir-user-3'));

        $deactivated = $this->identityFor('dir-user-3');

        $this->assertNotNull($deactivated);
        $this->assertNotNull($deactivated->deprovisioned_at);

        $provisioning->apply($binding, new ProvisioningIntent(ProvisioningAction::Reactivate, 'dir-user-3'));

        /*
         * 🛑 The row is fetched and asserted present **before** its column is
         * read. `assertNull($this->identityFor(...)?->deprovisioned_at)` passes
         * when the identity itself is null — so it would also pass if
         * reactivation had deleted the row, which is the opposite of what this
         * test claims. Level 8 flagged the nullsafe as unnecessary; the
         * interesting part is what it was hiding.
         */
        $reactivated = $this->identityFor('dir-user-3');

        $this->assertNotNull($reactivated, 'a reactivation must not delete the row');
        $this->assertNull(
            $reactivated->deprovisioned_at,
            'a reactivation must be reversible, which is why Deactivate is not Delete',
        );
    }

    /**
     * 🛑 A deletion for somebody who never signed in here is **not** an error.
     *
     * A directory pushing an offboarding for a reader DocUp has never seen is a
     * directory doing its job, and refusing would make an offboarding sync fail
     * on exactly the readers it has least to say about.
     */
    public function test_withdrawing_an_unknown_identity_changes_nothing_and_does_not_throw(): void
    {
        $this->assertFalse(app(ReaderProvisioning::class)->apply(
            $this->binding(),
            new ProvisioningIntent(ProvisioningAction::Delete, 'never-seen-here'),
        ));
    }

    /**
     * 🛑 A dry run reports and changes nothing.
     *
     * The first sync against a real directory is exactly when a mapping mistake
     * deactivates everybody, so the seam is built to be rehearsed — which is
     * also why {@see ProvisioningDriver} returns
     * an intent rather than acting.
     */
    public function test_a_dry_run_changes_nothing(): void
    {
        $provisioning = app(ReaderProvisioning::class);
        $binding = $this->binding();

        $this->assertTrue(
            $provisioning->apply($binding, new ProvisioningIntent(ProvisioningAction::Create, 'dry-1'), dryRun: true),
            'a dry run must report that it would create',
        );

        $this->assertNull($this->identityFor('dry-1'), '🛑 a dry run wrote a row');

        /* And on a real identity, a dry-run withdrawal leaves it live. */
        $provisioning->apply($binding, new ProvisioningIntent(ProvisioningAction::Create, 'dry-2'));

        $this->assertTrue($provisioning->apply(
            $binding,
            new ProvisioningIntent(ProvisioningAction::Deactivate, 'dry-2'),
            dryRun: true,
        ));

        $rehearsed = $this->identityFor('dry-2');

        /* Present and still live, which is two claims rather than one. */
        $this->assertNotNull($rehearsed);
        $this->assertNull($rehearsed->deprovisioned_at);
    }

    /**
     * 🛑 §8.12.5: "SCIM endpoints and portal-role group mappings MUST exist at
     * installation and organisation scope only."
     *
     * Checked where the write happens as well as on the driver: a
     * project-scoped binding reaching this method would be creating and
     * deleting identities in an organisation's table.
     */
    public function test_inbound_provisioning_is_refused_at_project_scope(): void
    {
        $this->expectException(ProvisioningRefused::class);

        app(ReaderProvisioning::class)->apply(
            $this->binding(projectScoped: true),
            new ProvisioningIntent(ProvisioningAction::Create, 'tenant-pushed'),
        );
    }

    /** The audit chain records the act, with the bound beside it. */
    public function test_a_deprovisioning_is_audited_with_its_latency(): void
    {
        $provisioning = app(ReaderProvisioning::class);
        $binding = $this->binding();

        $provisioning->apply($binding, new ProvisioningIntent(ProvisioningAction::Create, 'dir-user-4'));
        $provisioning->apply($binding, new ProvisioningIntent(ProvisioningAction::Deactivate, 'dir-user-4'));

        $event = DB::table('audit_events')
            ->where('action', 'reader.identity.deprovisioned')
            ->orderByDesc('id')
            ->first();

        $this->assertNotNull($event);

        /*
         * 🛑 The bound is in the chain because an incident review asks "when
         * did they actually lose access", and the answer is this row's
         * timestamp plus this number — so both are recorded rather than one of
         * them left in a document that may since have changed.
         */
        $this->assertStringContainsString(
            (string) ProvisioningLatency::seconds(),
            (string) ($event->payload ?? ''),
        );
    }

    // --------------------------------------------- §8.12.26's honest latency

    /**
     * 🛑 The bound at Tier A and B is the **grant TTL alone**, and it is derived
     * rather than written down.
     *
     * §8.12.15: "Revocation bounds MUST be taken from the one invalidation
     * registry in §10.8 and MUST NOT be restated as a number anywhere else."
     * A latency in a document as "about ten minutes" stops being true the day
     * `MAX_TTL_SECONDS` changes, and prose does not fail.
     */
    public function test_the_latency_is_the_grant_ttl_and_is_derived(): void
    {
        $this->assertSame(GrantMinter::MAX_TTL_SECONDS, ProvisioningLatency::seconds());
    }

    /**
     * 🛑 §8.12.26 names three terms and the honest bound is **not their sum**.
     *
     * The session's absolute ceiling is excluded because deprovisioning revokes
     * sessions: a session that cannot mint a new grant cannot extend the window
     * past the grant it holds. Adding twenty-four hours would overstate the
     * latency by a factor of 144 — and the test says the factor out loud so
     * that a future edit adding the term has to explain itself.
     */
    public function test_the_session_ceiling_is_excluded_and_published_separately(): void
    {
        $this->assertSame(
            GrantMinter::MAX_TTL_SECONDS + ReaderSessions::ABSOLUTE_SECONDS,
            ProvisioningLatency::ifSessionsSurvived(),
        );

        $this->assertGreaterThan(
            ProvisioningLatency::seconds() * 100,
            ProvisioningLatency::ifSessionsSurvived(),
            'the two numbers differ by two orders of magnitude, which is why only one is the bound',
        );
    }

    /**
     * 🛑 At Tier C the bound needs the epoch-feed interval, and **unset means
     * unstated** rather than unbounded.
     *
     * §8.12.13 refuses Tier C without the feed, so there is no bound to report;
     * returning Tier B's number would claim a guarantee that tier does not
     * have.
     */
    public function test_tier_c_has_no_bound_without_an_epoch_feed(): void
    {
        Config::set('docup.edge.epoch_feed_seconds', null);
        $this->assertNull(ProvisioningLatency::secondsAtTierC());

        Config::set('docup.edge.epoch_feed_seconds', 30);
        $this->assertSame(GrantMinter::MAX_TTL_SECONDS + 30, ProvisioningLatency::secondsAtTierC());

        /* A string from the environment counts, because env values are strings. */
        Config::set('docup.edge.epoch_feed_seconds', '45');
        $this->assertSame(GrantMinter::MAX_TTL_SECONDS + 45, ProvisioningLatency::secondsAtTierC());
    }

    /** The sentence an operator reads is generated, so it cannot drift. */
    public function test_the_explanation_names_both_numbers(): void
    {
        Config::set('docup.edge.epoch_feed_seconds', null);

        $explained = ProvisioningLatency::explain();

        $this->assertStringContainsString('10 minutes', $explained);
        $this->assertStringContainsString('24 hours', $explained);
        $this->assertStringContainsString('refused without an epoch feed', $explained);
    }

    // ------------------------------------------------------------- fixtures

    private function binding(bool $projectScoped = false): BindingContext
    {
        return new BindingContext(
            id: $this->bindingId,
            type: 'scim',
            name: 'Corporate directory',
            state: BindingState::Active,
            projectId: $projectScoped ? str_repeat("\x44", 16) : null,
            organisationId: $this->organisation->id,
        );
    }

    private function identityFor(string $subject): ?ReaderIdentity
    {
        $candidates = ReaderSubject::candidates($this->bindingId, $subject);

        return $this->context->acrossAllOrganisations(
            static fn (): ?ReaderIdentity => ReaderIdentity::query()
                ->whereIn('subject_hash', $candidates)
                ->first(),
        );
    }

    /**
     * One live session for an identity, through the **real** creation path.
     *
     * 🛑 `ReaderSessions::establish()` rather than a hand-rolled insert, and
     * the first version of this fixture was the insert. It failed five times
     * in a row on columns and encodings the schema owns — a `binding_id`
     * that is not on this table, `char(64)` hashes written as raw bytes, a
     * `handle_hash_prefix` with no default — and each fix taught the test
     * something about the schema and nothing about the product.
     *
     * Driving the real seam is both less brittle and a stronger assertion:
     * the revocation is proven against a session DocUp actually makes,
     * including the two secrets and the epoch stamp a hand-written row would
     * have had to guess at.
     */
    private function sessionFor(ReaderIdentity $identity): string
    {
        $established = app(ReaderSessions::class)->establish(
            $this->project,
            $this->domainId,
            $identity,
            combinedEpoch: 0,
        );

        return $established['session']->id;
    }
}
