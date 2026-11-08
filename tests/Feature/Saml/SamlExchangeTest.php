<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Saml;

use App\Auth\OrganisationContext;
use App\Auth\Providers\Bindings;
use App\Auth\Providers\BindingState;
use App\Auth\Providers\Saml\SamlExchange;
use App\Auth\Providers\Saml\SamlRefused;
use App\Auth\Providers\Saml\SamlRejection;
use App\Models\Domain;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\User;
use App\Support\SecretToken;
use App\Support\Uuid;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\DB;
use Tests\Support\HostileSamlResponses;
use Tests\TestCase;

/**
 * 🛑 §8.12.18's stateful half for SAML: a single-use `RelayState` and a stored
 * request id.
 *
 * `ResponseValidatorTest` covers everything that is a property of a *document*.
 * These are properties of the stored exchange — single use needs a row to
 * latch, and `InResponseTo` needs DocUp to remember what it sent — so they are
 * asserted here against the real table.
 *
 * The sibling of `Tests\Feature\Oidc\OidcExchangeTest`, deliberately: the two
 * tables are built the same way and the assertions that matter are the same
 * ones.
 */
final class SamlExchangeTest extends TestCase
{
    use DatabaseTransactions;

    private OrganisationContext $context;

    private Organisation $organisation;

    private Project $project;

    private Domain $domain;

    private string $bindingId;

    private const string CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

    protected function setUp(): void
    {
        parent::setUp();

        $this->context = app(OrganisationContext::class);
        $this->context->spanAllOrganisations();

        $this->organisation = Organisation::query()->create([
            'name' => 'SAML Co',
            'slug' => 'saml-'.bin2hex(random_bytes(4)),
        ]);

        $this->context->for($this->organisation->id);

        $this->project = Project::query()->create([
            'slug' => 'saml-'.bin2hex(random_bytes(3)),
            'name' => 'Guarded',
            'visibility' => 'members',
        ]);

        $domainId = Uuid::toBytes(Uuid::v7());

        DB::table('domains')->insert([
            'id' => $domainId,
            'organisation_id' => $this->organisation->id,
            'host' => 'docs-'.bin2hex(random_bytes(3)).'.example.test',
            'kind' => 'default_subdomain',
            'state' => 'active',
            'verified_at' => now(),
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        DB::table('domain_mounts')->insert([
            'id' => Uuid::toBytes(Uuid::v7()),
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

        $domain = $this->context->acrossAllOrganisations(
            static fn (): ?Domain => Domain::query()->whereKey($domainId)->first(),
        );

        $this->assertInstanceOf(Domain::class, $domain);

        $this->domain = $domain;

        $operator = User::query()->create([
            'name' => 'Operator',
            'email' => 'saml-'.bin2hex(random_bytes(4)).'@example.test',
            'password' => 'x',
        ]);

        $bindings = app(Bindings::class);

        $this->bindingId = $bindings->create(
            scopeType: 'project',
            scopeId: $this->project->id,
            type: 'saml',
            name: 'the idp',
            config: [
                'idp_entity_id' => HostileSamlResponses::ISSUER,
                'sso_url' => 'https://idp.example.test/realms/acme/protocol/saml',
                'certificate' => (new HostileSamlResponses)->certificate(),
            ],
            organisationId: $this->organisation->id,
        );

        $bindings->transition($this->bindingId, BindingState::Verifying);
        $bindings->recordTestLogin($this->bindingId, $operator->id);

        /*
         * 🛑 §8.12.19: a binding authenticates nobody until it is `active`,
         * and reaching `active` needs **both** a recorded test login and a
         * passing probe. Omitting either produced a `saml.config_invalid`
         * refusal that reads like a bad certificate — the wrong diagnosis for
         * an inactive binding, and worth the comment.
         *
         * 🛑 The **real** probe runs here, not a stub, and it can: a SAML
         * probe makes no outbound request. Its trust anchor is the configured
         * certificate rather than a discovery document, so there is nothing to
         * fetch — which is why `OidcExchangeTest` needs a transport fake and
         * this does not.
         */
        $probe = $bindings->probe($this->bindingId);

        $this->assertTrue($probe->passed, 'the fixture certificate should probe clean: '.$probe->summary);

        $bindings->transition($this->bindingId, BindingState::Active);
    }

    protected function tearDown(): void
    {
        $this->context->forget();

        parent::tearDown();
    }

    /**
     * 🛑 A `RelayState` is consumable exactly once.
     *
     * The latch is one `UPDATE` whose `WHERE` holds every condition, so two
     * concurrent POSTs presenting the same `RelayState` cannot both proceed. A
     * `SELECT` then an `UPDATE` has the race whose outcome is whether one
     * captured assertion mints two sessions — which for SAML is the whole
     * attack, because an assertion is a bearer credential that travels through
     * the browser.
     */
    public function test_a_relay_state_is_consumable_exactly_once(): void
    {
        $exchange = app(SamlExchange::class);

        $relayState = $this->open($exchange, 'request-abc');

        $first = $exchange->consume($relayState);

        $this->assertSame($this->bindingId, $first['binding_id']);
        $this->assertSame($this->domain->id, $first['domain_id']);
        $this->assertSame('request-abc', $first['request_id']);

        try {
            $exchange->consume($relayState);
            $this->fail('a relay state was consumed twice');
        } catch (SamlRefused $refused) {
            $this->assertSame(
                SamlRejection::RelayStateExpired,
                $refused->rejection,
                '🛑 §8.12.18: the exchange is single-use, by its latch',
            );
        }
    }

    /** An unknown `RelayState` is refused as unknown, not as expired. */
    public function test_an_unknown_relay_state_is_refused(): void
    {
        $exchange = app(SamlExchange::class);

        try {
            $exchange->consume(SecretToken::generate('docup_saml_relay'));
            $this->fail('a forged relay state resolved');
        } catch (SamlRefused $refused) {
            $this->assertSame(SamlRejection::RelayStateUnknown, $refused->rejection);
        }
    }

    /**
     * 🛑 §9.1.4: the `RelayState` is stored **hashed**, so the plaintext appears
     * nowhere in the row.
     *
     * Asserted directly, because a column that held it would make the hash
     * decorative — and this is the value that, held by an attacker, turns a
     * captured assertion into a usable one.
     */
    public function test_the_relay_state_is_stored_hashed(): void
    {
        $exchange = app(SamlExchange::class);

        $relayState = $this->open($exchange, 'request-def');
        $consumed = $exchange->consume($relayState);

        $row = DB::table('saml_auth_requests')->where('id', $consumed['id'])->first();

        $this->assertNotNull($row);

        foreach ((array) $row as $column => $value) {
            if (is_string($value)) {
                $this->assertStringNotContainsString(
                    $relayState,
                    $value,
                    '🛑 §9.1.4: the plaintext relay state must not be stored, and `'
                        .$column.'` holds it',
                );
            }
        }

        $this->assertSame(SecretToken::hash($relayState), (string) $row->relay_state_hash);
    }

    /**
     * 🛑 The request id is stored in the **clear**, and that is deliberate.
     *
     * §9.1.4 governs security tokens, and this is not one: it travels through
     * the browser both ways and `InResponseTo` is checked only after both
     * signatures verify, so forging one needs the provider's private key. The
     * plaintext is also *needed* — `ResponseValidator` compares against the id
     * DocUp sent — so hashing it would buy nothing and cost the comparison.
     *
     * Asserted so that a future change which "hardens" the column has to
     * confront the reasoning rather than discover it.
     */
    public function test_the_request_id_is_stored_in_the_clear(): void
    {
        $exchange = app(SamlExchange::class);

        $relayState = $this->open($exchange, 'request-ghi');

        $this->assertSame(
            'request-ghi',
            (string) DB::table('saml_auth_requests')
                ->where('relay_state_hash_prefix', SecretToken::prefix($relayState))
                ->value('request_id'),
        );
    }

    /**
     * 🛑 An expired exchange is refused, and the expiry is checked in the latch.
     *
     * Not by a `SELECT` that could pass while the `UPDATE` races — the
     * condition is in the same statement that claims the row.
     */
    public function test_an_expired_exchange_is_refused(): void
    {
        $exchange = app(SamlExchange::class);

        $relayState = $this->open($exchange, 'request-jkl');

        DB::table('saml_auth_requests')
            ->where('relay_state_hash_prefix', SecretToken::prefix($relayState))
            ->update(['expires_at' => now()->subMinute()->format('Y-m-d H:i:s.v')]);

        try {
            $exchange->consume($relayState);
            $this->fail('an expired exchange was consumed');
        } catch (SamlRefused $refused) {
            $this->assertSame(SamlRejection::RelayStateExpired, $refused->rejection);
        }
    }

    /**
     * 🛑 One attempt, and no way to release the row for a second.
     *
     * The asymmetry with OIDC is the point: OIDC allows a retry because its
     * token-endpoint leg can fail before anything is spent, while a SAML
     * assertion arrives complete and its id reaches the replay cache before any
     * DocUp-side fault can occur. So a released row would offer a retry that
     * could only ever be refused as `AssertionReplayed`.
     *
     * Asserted as the **absence of a method**, because that is the design
     * decision: a `recordAttempt()` here would tell the next reader that a
     * working retry path existed.
     */
    public function test_a_saml_exchange_cannot_be_released_for_a_retry(): void
    {
        /*
         * 🛑 The whole public surface, not just the absence of one name.
         *
         * `method_exists()` would be the obvious assertion and Larastan folds
         * it to a constant — correctly, because the class is `final` and the
         * analyser can see every method. So the claim is made over reflection
         * and stated positively: these three and nothing else. Any fourth
         * public method fails this test, which puts whoever added it in front
         * of `MAX_ATTEMPTS`' reasoning before they add a releaser.
         */
        $surface = array_map(
            static fn (\ReflectionMethod $method): string => $method->getName(),
            (new \ReflectionClass(SamlExchange::class))->getMethods(\ReflectionMethod::IS_PUBLIC),
        );

        sort($surface);

        $this->assertSame(
            ['consume', 'open', 'sweep'],
            $surface,
            '🛑 a SAML exchange has no retry that could succeed; see MAX_ATTEMPTS',
        );

        $this->assertSame(1, SamlExchange::MAX_ATTEMPTS);
    }

    /**
     * The sweep removes spent rows and leaves live ones.
     *
     * 🛑 Asserted as "at least this row", never as a total. The table is shared
     * with whatever else has run — the Keycloak integration leaves rows of its
     * own — and a test that depends on an empty database is a test that fails
     * for the next person rather than for the change that broke it.
     */
    public function test_the_sweep_leaves_a_live_exchange_alone(): void
    {
        $exchange = app(SamlExchange::class);

        $relayState = $this->open($exchange, 'request-pqr');

        $mine = DB::table('saml_auth_requests')
            ->where('relay_state_hash_prefix', SecretToken::prefix($relayState));

        $exchange->sweep();

        $this->assertSame(1, $mine->count(), 'the sweep removed a live exchange');

        $mine->update(['expires_at' => now()->subDays(2)->format('Y-m-d H:i:s.v')]);

        $this->assertGreaterThanOrEqual(1, $exchange->sweep());
        $this->assertSame(0, $mine->count(), 'the sweep left an expired exchange behind');
    }

    private function open(SamlExchange $exchange, string $requestId): string
    {
        return $exchange->open(
            organisationId: (string) $this->organisation->id,
            bindingId: $this->bindingId,
            domainId: $this->domain->id,
            projectId: $this->project->id,
            requestId: $requestId,
            handoffChallenge: self::CHALLENGE,
            returnPath: '/',
        );
    }
}
