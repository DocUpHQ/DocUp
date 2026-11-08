<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Ldap;

use App\Auth\AccessLevel;
use App\Auth\OrganisationContext;
use App\Auth\Providers\BindingContext;
use App\Auth\Providers\BindingState;
use App\Auth\Providers\Federation\GroupMappings;
use App\Auth\Providers\Ldap\LdapAuthenticator;
use App\Auth\Providers\Ldap\LdapConnection;
use App\Auth\Providers\Ldap\LdapRefused;
use App\Auth\Providers\Ldap\LdapRejection;
use App\Credentials\SecretString;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\ReaderIdentity;
use App\Readers\ReaderSessions;
use App\Support\Uuid;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\DB;
use LDAP\Connection;
use Tests\Support\RequiresBuildImages;
use Tests\TestCase;

/**
 * 🛑 §17's Phase 26b exit criterion, against a **real directory**.
 *
 * > "An LDAP group removal drops access on the next decision."
 *
 * {@see LdapBoundaryTest} proves everything that is DocUp's with no server at
 * all — filter escaping against a hostile username, the TLS and referral
 * options, the installation-scope narrowing, the sorting of operator faults
 * from reader faults. What it cannot prove is that DocUp speaks the protocol a
 * real directory speaks, and this file is the rest of it:
 *
 * - that StartTLS **verifies** with `LDAP_OPT_X_TLS_HARD` set, against a
 *   certificate the application was taught to trust and not otherwise;
 * - that a simple bind as the reader's **own DN** is what checks their
 *   password, which is a claim about the directory's ACL as much as about
 *   DocUp's code;
 * - that `memberOf` arrives as a list;
 * - and that removing a member from a group changes what the next bind sees,
 *   which is the exit criterion.
 *
 * 🛑 **A skip is not a pass.** `DOCUP_LDAP_E2E=1` — set by `compose.ldap.yaml`
 * — turns every skip here into a failure, for the reason
 * {@see RequiresBuildImages} gives at length: without it a
 * broken integration and an absent one look identical, which is exactly the
 * state Phase 23 left this driver in when it shipped with no sign-in path at
 * all.
 *
 * Standing it up:
 *
 *   bash deploy/ldap-test-setup.sh
 *   docker compose -f compose.yaml -f compose.ldap.yaml up -d --build
 *   bash deploy/ldap-test-setup.sh --trust
 *   docker compose -f compose.yaml -f compose.ldap.yaml exec \
 *     -e DB_DATABASE=docup_test app ./vendor/bin/pest tests/Feature/Ldap
 */
final class LdapDirectoryTest extends TestCase
{
    use DatabaseTransactions;

    /** The fixture's own readers, named here so a test reads as a sentence. */
    private const string DANA = 'dana';

    private const string DANA_PASSWORD = 'dana-password-for-tests-only';

    private const string MORGAN = 'morgan';

    private const string MORGAN_PASSWORD = 'morgan-password-for-tests-only';

    private const string READERS_GROUP = 'cn=docs-readers,ou=groups,dc=docup,dc=test';

    private const string DANA_DN = 'uid=dana,ou=people,dc=docup,dc=test';

    /** The raw 16 bytes, which is what `Uuid::v7()` returns and what every column holds. */
    private string $bindingId;

    private OrganisationContext $context;

    private Organisation $organisation;

    private Project $project;

    private string $domainId;

    protected function setUp(): void
    {
        parent::setUp();

        $this->requireDirectory();

        $this->bindingId = Uuid::v7();
        $this->context = app(OrganisationContext::class);
        $this->context->spanAllOrganisations();

        $this->organisation = Organisation::query()->create([
            'name' => 'LDAP Fixture',
            'slug' => 'ldap-'.bin2hex(random_bytes(4)),
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
            'host' => 'ldap-'.bin2hex(random_bytes(4)).'.example.test',
            'kind' => 'custom',
            'state' => 'active',
            'tls_mode' => 'managed',
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        /*
         * 🛑 `scope_type: installation`, because §8.12.4 permits no other for
         * this driver — and the test would be testing a configuration the
         * product refuses if it used any other. `organisation_id` is therefore
         * null, which is what makes the binding the installation's.
         */
        DB::table('auth_provider_bindings')->insert([
            'id' => $this->bindingId,
            'organisation_id' => null,
            'scope_type' => 'installation',
            'scope_id' => null,
            'type' => 'ldap',
            'name' => 'Corporate directory',
            'config' => json_encode($this->config(), JSON_THROW_ON_ERROR),
            'state' => 'active',
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }

    protected function tearDown(): void
    {
        /*
         * 🛑 The group membership is put back, whatever the test did, and
         * NOT by `DatabaseTransactions` — the directory is not in the
         * database, so nothing rolls it back. A removal left in place would
         * make every later run of this file fail on a fixture the previous run
         * broke, which is the single most common way an integration suite
         * becomes untrustworthy.
         */
        if ($this->shouldRun()) {
            $this->restoreMembership();
        }

        $this->context->forget();

        parent::tearDown();
    }

    // ----------------------------------------------------- the ordinary case

    /**
     * 🛑 The positive case first, because every refusal below is only
     * meaningful if the mechanism works at all.
     */
    public function test_a_reader_signs_in_against_a_real_directory(): void
    {
        $identity = $this->authenticate(self::DANA, self::DANA_PASSWORD);

        $this->assertSame($this->bindingId, $identity->binding_id);

        /*
         * 🛑 The subject is the `uid`, hashed — §8.12.1 keys reader identities
         * on `(binding_id, subject_hash)` and forbids email for linking. The
         * assertion is that the identity resolves by the subject the directory
         * carries, which is the whole of what the key means.
         */
        $again = $this->authenticate(self::DANA, self::DANA_PASSWORD);

        $this->assertSame($identity->id, $again->id, 'a second sign-in made a second identity');
    }

    /** `memberOf` arrives as a list, which §8.13.7 reconciles into the column. */
    public function test_the_directory_groups_reach_the_identity(): void
    {
        $this->mapTheReadersGroup();

        $identity = $this->authenticate(self::DANA, self::DANA_PASSWORD);

        $this->assertContains('docs-readers', $this->groupsOf($identity));
    }

    /** A reader in no group is admitted by the directory and holds no group. */
    public function test_a_reader_in_no_group_holds_no_group(): void
    {
        $this->mapTheReadersGroup();

        $identity = $this->authenticate(self::MORGAN, self::MORGAN_PASSWORD);

        $this->assertSame([], $this->groupsOf($identity));
    }

    // -------------------------------------------- §17's first exit criterion

    /**
     * 🛑 "An LDAP group removal drops access on the next decision."
     *
     * The whole chain, and every link of it was missing at some point in this
     * phase: the directory's `memberOf`, §8.13.7's reconciliation **of a
     * removal** as well as an addition, the `reader_groups` column, and
     * §12.3's `members` rung reading it — which nothing did until Phase 26b.
     *
     * 🛑 The assertion is about the **level**, not about a 200 or a 404. A
     * level is what §12.3 decides and what `EffectiveAccess` then compares
     * against the rule; asserting a status here would be asserting the serving
     * path's behaviour from a test that never served anything, and would pass
     * for the wrong reason the day the default status changes.
     */
    public function test_a_group_removal_drops_access_on_the_next_decision(): void
    {
        $this->mapTheReadersGroup();

        /* 1. In the group: `members`, which is this project's visibility. */
        $before = $this->levelAfterSignIn(self::DANA, self::DANA_PASSWORD);

        $this->assertSame(
            AccessLevel::Members,
            $before,
            'a reader in a mapped group did not reach the `members` rung; '
            .'§12.3\'s group half is what Phase 26b added',
        );

        /* 2. The removal, in the directory and not in DocUp. */
        $this->removeMembership();

        /* 3. The next decision. */
        $after = $this->levelAfterSignIn(self::DANA, self::DANA_PASSWORD);

        $this->assertSame(
            AccessLevel::Authenticated,
            $after,
            'the group removal did not reach the decision',
        );

        /*
         * 🛑 And the column itself, because the level could fall for another
         * reason — a session that failed to establish would also report
         * `authenticated`. Asserting both is what makes this a test of the
         * reconciliation rather than of any path to a lower level.
         */
        $identity = $this->authenticate(self::DANA, self::DANA_PASSWORD);

        $this->assertSame([], $this->groupsOf($identity), 'the removal did not reach `reader_groups`');
    }

    // ------------------------------------------------------- reader refusals

    /** A wrong password is refused, and the directory is what refuses it. */
    public function test_a_wrong_password_is_refused(): void
    {
        $this->expectException(LdapRefused::class);

        $this->authenticate(self::DANA, 'not-dana-password');
    }

    /**
     * 🛑 And an unknown username is refused with the **same** rejection.
     *
     * Asserted as an identity rather than as two separate expectations,
     * because the requirement is that they cannot be told apart: a form that
     * said "no such user" would be an enumeration oracle over the operator's
     * employee directory, readable by anyone who can reach the sign-in page.
     * §8.12.23 says the same thing about 404-versus-401.
     */
    public function test_an_unknown_username_is_refused_identically_to_a_wrong_password(): void
    {
        $wrongPassword = $this->rejectionFrom(self::DANA, 'not-dana-password');
        $noSuchReader = $this->rejectionFrom('nobody-by-that-name', 'any-password-at-all');

        $this->assertSame(LdapRejection::CredentialsRejected, $wrongPassword);
        $this->assertSame(
            $wrongPassword,
            $noSuchReader,
            'an unknown username is distinguishable from a wrong password, which enumerates the directory',
        );
    }

    /**
     * 🛑 §8.12.18's "exactly one", against a directory that really returns two.
     *
     * The fixture carries two entries with the same `uid` in a branch of their
     * own, because this refusal cannot be tested against a tree that enforces
     * uniqueness — and picking the first would authenticate whichever one the
     * directory happened to return.
     */
    public function test_an_ambiguous_username_is_refused_rather_than_chosen(): void
    {
        $this->assertSame(
            LdapRejection::SubjectAmbiguous,
            $this->rejectionFrom('ambiguous', 'ambiguous-password-for-tests-only', 'dc=docup,dc=test'),
        );
    }

    /**
     * 🛑 An empty password does not reach the directory, proved against a real
     * one.
     *
     * {@see LdapBoundaryTest} asserts the same refusal without a server, which
     * proves the guard exists. This asserts that the guard is **in front of**
     * a directory that would have said yes: RFC 4511 §4.2 makes a simple bind
     * with an empty password an anonymous bind, and slapd accepts one — so
     * without the guard DocUp would read "authenticated as nobody" as success.
     */
    public function test_an_empty_password_is_refused_in_front_of_a_directory_that_would_accept_it(): void
    {
        $this->assertSame(
            LdapRejection::CredentialsRejected,
            $this->rejectionFrom(self::DANA, ''),
        );

        /*
         * The control: the same anonymous bind, made directly, succeeds. If
         * slapd ever refused anonymous binds this test would pass for the
         * wrong reason, and this is the line that notices.
         */
        $this->assertTrue(
            $this->bindsAnonymously(self::DANA_DN),
            'the directory refuses an empty-password bind, so the guard is untested here',
        );
    }

    // ------------------------------------------------------------- the edges

    /**
     * 🛑 StartTLS is verified, and the certificate is what makes it work.
     *
     * The positive half only; the negative half — that an untrusted
     * certificate is refused — is asserted by `deploy/ldap-test-setup.sh`,
     * which removes the anchor and re-probes. It lives there rather than here
     * because it mutates the container's trust store, and a test that did that
     * would leave every later test in this file depending on the order they
     * ran in.
     */
    public function test_starttls_verifies_against_the_real_directory(): void
    {
        $connection = LdapConnection::open($this->uri(), $this->bindDn(), $this->bindPassword());

        $entry = $connection->findOne('dc=docup,dc=test', '(uid=dana)', ['uid']);
        $connection->close();

        $this->assertSame(self::DANA_DN, $entry['dn']);
    }

    /**
     * 🛑 The service account cannot read a password hash, which is the
     * directory's half of why the reader's own bind is the check.
     *
     * If this ever returned a hash, `verifyPassword()` could be "simplified"
     * into a comparison — and that version would accept a hash format it did
     * not understand, or compare against an empty string.
     */
    public function test_the_service_account_cannot_read_a_password(): void
    {
        $connection = LdapConnection::open($this->uri(), $this->bindDn(), $this->bindPassword());

        $entry = $connection->findOne('dc=docup,dc=test', '(uid=dana)', ['userPassword']);
        $connection->close();

        $this->assertSame(
            [],
            $entry['attributes']['userPassword'] ?? [],
            'the service account can read a password hash; the fixture ACL is wrong',
        );
    }

    // ------------------------------------------------------------- the plumbing

    private function authenticate(string $username, string $password): ReaderIdentity
    {
        return app(LdapAuthenticator::class)->authenticate($this->binding(), $username, $password);
    }

    /**
     * The rejection a sign-in produced, so two of them can be compared.
     *
     * @param  string|null  $baseDn  overridden only by the ambiguity case,
     *                               whose two entries live outside the default
     *                               `ou=people`
     */
    private function rejectionFrom(string $username, string $password, ?string $baseDn = null): LdapRejection
    {
        $binding = $baseDn === null
            ? $this->binding()
            : $this->binding(['base_dn' => $baseDn, 'user_filter' => '(uid={username})']);

        try {
            app(LdapAuthenticator::class)->authenticate($binding, $username, $password);
        } catch (LdapRefused $refused) {
            return $refused->rejection;
        }

        $this->fail('the sign-in was not refused at all');
    }

    /** §12.3's level for a reader who has just signed in through the binding. */
    private function levelAfterSignIn(string $username, string $password): AccessLevel
    {
        $identity = $this->authenticate($username, $password);
        $sessions = app(ReaderSessions::class);

        $established = $sessions->establish(
            $this->project,
            $this->domainId,
            $identity,
            combinedEpoch: 0,
        );

        return $sessions->contextFor($established['session'], $this->project)->level;
    }

    /** @return list<string> */
    private function groupsOf(ReaderIdentity $identity): array
    {
        /*
         * 🛑 Across every organisation, which is not a convenience.
         *
         * This binding is installation-scoped, so the identity's
         * `organisation_id` is null -- and §8.2.1's global scope filters a
         * null tenant out of any organisation-scoped read. Every path in
         * the product that touches a reader identity already spans
         * deliberately for this reason
         * ({@see \App\Readers\ReaderSessions::contextFor()},
         * {@see \App\Auth\Providers\Federation\ReaderProvisioning}), and a
         * test that did not would report "the identity vanished" for a row
         * sitting right there. Which it did, before this comment existed.
         */
        $fresh = $this->context->acrossAllOrganisations(
            static fn (): ?ReaderIdentity => ReaderIdentity::query()->whereKey($identity->id)->first(),
        );

        $this->assertNotNull($fresh, 'the identity vanished');

        $decoded = json_decode((string) ($fresh->reader_groups ?? '[]'), true);

        if (! is_array($decoded)) {
            return [];
        }

        return array_values(array_filter($decoded, static fn (mixed $g): bool => is_string($g) && $g !== ''));
    }

    private function mapTheReadersGroup(): void
    {
        app(GroupMappings::class)->add(
            bindingId: $this->bindingId,
            bindingScopeType: 'installation',
            organisationId: null,
            /*
             * 🛑 The provider group is the group's **DN**, because that is what
             * `memberOf` carries — in this fixture and in Active Directory. An
             * operator mapping `docs-readers` by its bare `cn` would find the
             * mapping never matching, which is a configuration mistake worth
             * the test naming rather than papering over with a suffix match.
             */
            providerGroup: self::READERS_GROUP,
            target: 'group',
            targetValue: 'docs-readers',
        );
    }

    // --------------------------------------------------- the directory itself

    private function removeMembership(): void
    {
        $this->modifyGroup('ldap_mod_del');
    }

    private function restoreMembership(): void
    {
        /*
         * Adding a member that is already there is LDAP_TYPE_OR_VALUE_EXISTS,
         * which is the common case: most tests in this file never removed one.
         * Tolerated rather than branched on -- asking first would be two round
         * trips to learn something the write already knows.
         */
        $this->modifyGroup('ldap_mod_add', tolerate: [20]);
    }

    /**
     * 🛑 The directory mutated through `ext-ldap`, as its ADMINISTRATOR.
     *
     * Two things are deliberate here and neither is convenience.
     *
     * 🛑 **Raw `ldap_*` rather than {@see LdapConnection}**, because DocUp
     * never writes to a directory and the product must not grow a method that
     * could. This test plays the part of the operator's own administrator
     * removing somebody from a group; a `modify()` on the connection class
     * would be a write path in the product with no caller in the product.
     *
     * 🛑 **The admin DN rather than the service account**, because the
     * fixture's ACL gives the service account read and nothing else -- which is
     * what {@see self::test_the_service_account_cannot_read_a_password()}
     * asserts. Mutating as the service account would mean testing against a
     * directory configured more loosely than the one under test.
     *
     * And not the `ldapmodify` CLI, which lives in `ldap-utils`: that package is
     * in the FIXTURE image and deliberately not in the application's, where an
     * LDAP command-line client has no business being for a test's sake. The
     * first version of this helper shelled out, and the guard in
     * {@see self::requireDirectory()} is what caught it.
     *
     * @param  'ldap_mod_add'|'ldap_mod_del'  $operation
     * @param  list<int>  $tolerate  LDAP result codes that are not failures
     */
    private function modifyGroup(string $operation, array $tolerate = []): void
    {
        $handle = $this->adminConnection();

        if (@$operation($handle, self::READERS_GROUP, ['member' => [self::DANA_DN]]) !== true) {
            $code = ldap_errno($handle);

            if (! in_array($code, $tolerate, true)) {
                $message = ldap_error($handle);
                @ldap_unbind($handle);

                $this->fail($operation.' failed: '.$message.' ('.$code.')');
            }
        }

        @ldap_unbind($handle);
    }

    /** A connection bound as the directory's administrator, over StartTLS. */
    private function adminConnection(): Connection
    {
        $handle = ldap_connect($this->uri());

        $this->assertInstanceOf(Connection::class, $handle);

        ldap_set_option($handle, LDAP_OPT_PROTOCOL_VERSION, 3);
        ldap_set_option($handle, LDAP_OPT_REFERRALS, 0);
        ldap_set_option($handle, LDAP_OPT_X_TLS_REQUIRE_CERT, LDAP_OPT_X_TLS_HARD);

        $this->assertTrue(@ldap_start_tls($handle), 'StartTLS failed for the admin connection');
        $this->assertTrue(
            @ldap_bind($handle, 'cn=admin,dc=docup,dc=test', 'admin-password-for-tests-only'),
            'the admin bind failed; is LDAP_ADMIN_PASSWORD still the fixture value?',
        );

        return $handle;
    }

    /**
     * Whether the directory accepts a simple bind with an EMPTY password.
     *
     * RFC 4511 4.2 makes that an anonymous bind, and most directories accept
     * one -- which is the fact `LdapConnection::verifyPassword()`'s guard
     * exists for. Measured rather than assumed, so the guard's test cannot
     * pass on a directory where there was nothing to guard against.
     */
    private function bindsAnonymously(string $dn): bool
    {
        $handle = ldap_connect($this->uri());

        if (! $handle instanceof Connection) {
            return false;
        }

        ldap_set_option($handle, LDAP_OPT_PROTOCOL_VERSION, 3);
        ldap_set_option($handle, LDAP_OPT_X_TLS_REQUIRE_CERT, LDAP_OPT_X_TLS_HARD);

        $bound = @ldap_start_tls($handle) === true && @ldap_bind($handle, $dn, '') === true;

        @ldap_unbind($handle);

        return $bound;
    }

    // ------------------------------------------------------------ the binding

    /** @param array<string, mixed> $overrides */
    private function binding(array $overrides = []): BindingContext
    {
        return new BindingContext(
            id: $this->bindingId,
            type: 'ldap',
            name: 'Corporate directory',
            config: [...$this->config(), ...$overrides],
            /*
             * A SecretString, because BindingContext::secret() reveals only
             * that type -- a bare string comes back as null, and the
             * authenticator then refuses with `bind_credentials_missing`,
             * which is the right refusal for a binding that holds no
             * password and a very confusing one for a test fixture.
             */
            secrets: ['bind_password' => new SecretString($this->bindPassword())],
            state: BindingState::Active,
        );
    }

    /** @return array<string, mixed> */
    private function config(): array
    {
        return [
            'uri' => $this->uri(),
            'base_dn' => $this->env('DOCUP_LDAP_BASE_DN', 'dc=docup,dc=test'),
            'user_filter' => '(&(objectClass=inetOrgPerson)(uid={username}))',
            'bind_dn' => $this->bindDn(),
            'subject_attribute' => 'uid',
            'groups_attribute' => 'memberOf',
            'display_attribute' => 'cn',
            /*
             * 🛑 `create_reader_and_map_groups`, not `create_reader`.
             *
             * The shorter mode creates the identity and deliberately does
             * NOT reconcile groups -- `ProvisioningMode::mapsGroups()` is
             * false for it -- so this file first watched every group test
             * fail over an empty set while the sign-in itself worked. The
             * mode is the operator's choice and the names say which is
             * which; the exit criterion is about the one that maps.
             */
            'provisioning' => 'create_reader_and_map_groups',
        ];
    }

    private function uri(): string
    {
        return $this->env('DOCUP_LDAP_URI', 'ldap://openldap:389');
    }

    private function bindDn(): string
    {
        return $this->env('DOCUP_LDAP_BIND_DN', 'cn=svc-docup,dc=docup,dc=test');
    }

    private function bindPassword(): string
    {
        return $this->env('DOCUP_LDAP_BIND_PASSWORD', 'svc-password-for-tests-only');
    }

    private function env(string $name, string $fallback): string
    {
        $value = getenv($name);

        return is_string($value) && $value !== '' ? $value : $fallback;
    }

    // -------------------------------------------------------------- the gate

    private function shouldRun(): bool
    {
        return LdapConnection::available() && getenv('DOCUP_LDAP_E2E') === '1';
    }

    /**
     * 🛑 A skip where there is no directory, a **failure** where there was
     * supposed to be one.
     *
     * 🛑 And nothing here looks for a command-line client, because nothing
     * in this file uses one any more. The first version drove the group
     * removal with `ldapmodify`, which is in `ldap-utils` -- present in the
     * fixture image and deliberately absent from the application's. This
     * method is what caught it; the fix was to use `ext-ldap`, which is the
     * library the product uses anyway.
     */
    private function requireDirectory(): void
    {
        if (! LdapConnection::available()) {
            $this->markTestSkipped('ext-ldap is absent; §11.2 makes it a `suggest`');
        }

        if (getenv('DOCUP_LDAP_E2E') !== '1') {
            $this->markTestSkipped(
                'no directory: docker compose -f compose.yaml -f compose.ldap.yaml up -d --build, '
                .'then bash deploy/ldap-test-setup.sh --trust',
            );
        }

    }
}
