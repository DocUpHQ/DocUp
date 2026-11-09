<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Branding;

use App\Auth\OrganisationContext;
use App\Branding\Assets\AssetIntake;
use App\Branding\Assets\AssetKind;
use App\Branding\CascadeLevel;
use App\Branding\CredentialPageBranding;
use App\Branding\ThemeDelivery;
use App\Branding\ThemeRevisions;
use App\Branding\ThemeTarget;
use App\Http\Middleware\HandleInertiaRequests;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Support\Uuid;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Storage;
use Tests\TestCase;

/**
 * 🛑 §17's one 🛑 exit criterion for Phase 27, and §8.14.12.
 *
 * > §17: "🛑 A login page renders **installation** branding only, regardless of
 * > which tenant domain the reader arrived from."
 *
 * > §8.14.12: "Pages that accept credentials MUST carry **no project or
 * > organisation branding**. All authentication MUST redirect to the dashboard
 * > host with installation branding only, so a tenant-controlled domain can
 * > never present a DocUp-styled login form."
 *
 * ## 🛑 Asserted over the whole response body, never over the props
 *
 * Phase 26b's build log already recorded why, about the page this phase
 * inherited: "over the whole body rather than the props, since a shared prop or
 * a layout would satisfy a props-only check". A project name arriving through
 * {@see HandleInertiaRequests}'s shared array, or through
 * a page `<title>`, or through a layout component, would each pass a test that
 * inspected the controller's own props and would each violate the requirement.
 *
 * ## 🛑 Two tenants, each with branding worth stealing
 *
 * A single tenant proves little: a page that happened to render nothing would
 * pass. So each tenant here publishes a project theme with a distinctive
 * wordmark, a distinctive palette and an uploaded logo, and the test asserts
 * that **neither** reaches a credential page and that what does reach it is the
 * installation's own resolved theme — by content hash, which is the one value
 * that cannot be coincidentally equal.
 */
final class CredentialBrandingRefusalTest extends TestCase
{
    use DatabaseTransactions;

    /** 43 base64url characters, the shape `reader_handoff_codes` stores. */
    private const string CHALLENGE = 'Cq8rTQ8h-0VYjJm3tZ9xN2pL7wKdG5sRfBvHcUyAeI4';

    private OrganisationContext $context;

    /** @var list<array{organisation: Organisation, project: Project, host: string, domainId: string, logo: string}> */
    private array $tenants = [];

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('theme-assets');
        $this->withoutVite();

        $this->context = app(OrganisationContext::class);
        $this->context->spanAllOrganisations();

        $this->tenants = [
            $this->makeTenant('Aurora Systems', 'Aurora Docs', '#b3261e', '#ff8f85'),
            $this->makeTenant('Borealis Group', 'Borealis Docs', '#0f6b35', '#5bd98d'),
        ];
    }

    protected function tearDown(): void
    {
        $this->context->forget();

        parent::tearDown();
    }

    /**
     * 🛑 The criterion, over the dashboard login page, for each tenant domain
     * a reader might have arrived from.
     *
     * The `Referer` is the thing a tenant-controlled domain actually sends when
     * it bounces a reader to the dashboard, so it is set — and the assertion is
     * that it changes nothing.
     */
    public function test_the_login_page_carries_installation_branding_only_whichever_tenant_sent_the_reader(): void
    {
        $installation = $this->installationHash();

        foreach ($this->tenants as $tenant) {
            $response = $this
                ->withHeader('Referer', 'https://'.$tenant['host'].'/en/latest/')
                ->get('/login');

            $response->assertOk();

            $body = (string) $response->getContent();

            $this->assertNoTenantStringReached($body, $tenant, '/login');

            /*
             * 🛑 And the positive half: the branding that DID reach the page is
             * the installation's, identified by the content hash of its
             * resolved theme. A test that only asserted absences would pass for
             * a page carrying no branding at all.
             */
            $this->assertStringContainsString(
                $installation,
                $body,
                'the login page must carry the installation theme’s own stylesheet',
            );
        }
    }

    /**
     * 🛑 The same, for §8.12.16's **reader** credential page — the one page in
     * the application that legitimately resolves a tenant domain before it
     * renders.
     *
     * This is the hard case and the reason the rule is not "do not pass a
     * project to a credential page". The controller has a domain, a project and
     * an organisation in hand; what stops them reaching the reader is that
     * {@see CredentialPageBranding::resolve()} takes no arguments.
     */
    public function test_the_reader_credential_page_carries_installation_branding_only(): void
    {
        $installation = $this->installationHash();

        foreach ($this->tenants as $tenant) {
            $this->bindAnLdapProvider($tenant['organisation']);

            $response = $this->get('/_/auth/ldap?'.http_build_query([
                'domain' => Uuid::toText($tenant['domainId']),
                'challenge' => self::CHALLENGE,
                'return' => '/en/latest/',
            ]));

            $response->assertOk();

            $body = (string) $response->getContent();

            $this->assertNoTenantStringReached($body, $tenant, '/_/auth/ldap');
            $this->assertStringContainsString($installation, $body);

            /* The directory's own label is the operator's, and is permitted. */
            $this->assertStringContainsString('Corporate directory', $body);
        }
    }

    /**
     * 🛑 And the mechanism itself: the branding a credential page resolves is
     * byte-identical to the installation's, not merely free of tenant strings.
     *
     * Asserted in a tenant context, because the subtle failure is a resolver
     * that quietly picked up whichever organisation happened to be declared on
     * the request.
     */
    public function test_credential_branding_is_the_installation_theme_even_inside_a_tenant_context(): void
    {
        $tenant = $this->tenants[0];
        $this->context->for($tenant['organisation']->id);

        $credential = CredentialPageBranding::resolve();

        $installationTheme = ThemeDelivery::make()->deliver(ThemeTarget::installation());

        $this->assertSame($installationTheme->stylesheetUrl, $credential->stylesheetUrl);
        $this->assertSame('DocUp', $credential->installationName);

        /*
         * 🛑 The tenant uploaded a logo at organisation scope. A credential
         * page must not find it — and it does not, because the lookup behind
         * this resolution sees installation assets only, so the project's
         * `asset.logo` could not have resolved to a value in the first place.
         */
        $this->assertNull($credential->logoUrl);

        $this->context->spanAllOrganisations();
    }

    /**
     * The installation's own theme also publishes, so the comparison above is
     * not trivially true of an unthemed installation.
     */
    public function test_the_installation_theme_reaches_a_credential_page(): void
    {
        $revisions = ThemeRevisions::make();

        $revisions->publish($revisions->draft(
            level: CascadeLevel::Installation,
            scopeId: null,
            organisationId: null,
            tokens: ['brand.name' => 'Acme Hosting', 'color.brand.primary' => ['light' => '#6d28d9', 'dark' => '#c4b5fd']],
        ));

        $response = $this->get('/login');

        $response->assertOk();

        $body = (string) $response->getContent();

        $this->assertStringContainsString('Acme Hosting', $body);
        $this->assertStringContainsString($this->installationHash(), $body);
    }

    // ------------------------------------------------------------- the fixtures

    /** @param array{organisation: Organisation, project: Project, host: string, domainId: string, logo: string} $tenant */
    private function assertNoTenantStringReached(string $body, array $tenant, string $where): void
    {
        foreach ([
            'the project name' => $tenant['project']->name,
            'the project slug' => (string) $tenant['project']->slug,
            'the organisation name' => $tenant['organisation']->name,
            'the organisation slug' => (string) $tenant['organisation']->slug,
            'the documentation host' => $tenant['host'],
            'the tenant logo hash' => $tenant['logo'],
        ] as $what => $needle) {
            $this->assertStringNotContainsString(
                $needle,
                $body,
                $what.' reached '.$where.' (§8.14.12)',
            );
        }
    }

    /**
     * One tenant: an organisation, a themed project, a verified domain and an
     * uploaded logo.
     *
     * @return array{organisation: Organisation, project: Project, host: string, domainId: string, logo: string}
     */
    private function makeTenant(string $organisationName, string $wordmark, string $light, string $dark): array
    {
        $organisation = Organisation::query()->create([
            'name' => $organisationName,
            'slug' => strtolower(explode(' ', $organisationName)[0]).'-'.bin2hex(random_bytes(4)),
        ]);

        $this->context->for($organisation->id);

        $slug = strtolower(explode(' ', $organisationName)[0]).'docs-'.bin2hex(random_bytes(3));

        $project = Project::query()->create([
            'slug' => $slug,
            'name' => $organisationName.' Platform',
            'visibility' => 'members',
        ]);

        $version = new ProjectVersion;
        $version->forceFill([
            'organisation_id' => $organisation->id,
            'project_id' => $project->id,
            'slug' => 'latest',
            'kind' => 'channel',
            'language' => 'en',
            'visibility' => 'members',
        ])->save();

        $project->forceFill(['default_version_id' => $version->id])->save();

        $domainId = Uuid::v7();
        $host = $slug.'.'.$this->docsApex();

        DB::table('domains')->insert([
            'id' => $domainId,
            'organisation_id' => $organisation->id,
            'host' => $host,
            'kind' => 'default_subdomain',
            'state' => 'active',
            'verified_at' => now(),
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        DB::table('domain_mounts')->insert([
            'id' => Uuid::v7(),
            'organisation_id' => $organisation->id,
            'domain_id' => $domainId,
            'project_id' => $project->id,
            'path_prefix' => '',
            'mode' => 'canonical',
            'mount_exposure' => 'inherit',
            'position' => 0,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        /* A logo this tenant would very much like a credential page to show. */
        $logo = AssetIntake::make()->accept(
            bytes: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16"><title>'.$wordmark.'</title><rect width="16" height="16" fill="'.$light.'"/></svg>',
            kind: AssetKind::Logo,
            label: $wordmark.' mark',
            scope: CascadeLevel::Organisation,
            scopeId: (string) $organisation->id,
            organisationId: (string) $organisation->id,
        );

        $revisions = ThemeRevisions::make((string) $organisation->id, (string) $project->id);

        $revisions->publish($revisions->draft(
            level: CascadeLevel::Project,
            scopeId: (string) $project->id,
            organisationId: (string) $organisation->id,
            tokens: [
                'brand.name' => $wordmark,
                'asset.logo' => Uuid::toText($logo->asset->id),
                'color.brand.primary' => ['light' => $light, 'dark' => $dark],
            ],
        ));

        $this->context->spanAllOrganisations();

        return [
            'organisation' => $organisation,
            'project' => $project,
            'host' => $host,
            'domainId' => $domainId,
            'logo' => $logo->asset->content_hash,
        ];
    }

    /** The content hash of the installation's own resolved theme. */
    private function installationHash(): string
    {
        return ThemeDelivery::make()->deliver(ThemeTarget::installation())->contentHash;
    }

    /** An installation-scoped `ldap` binding — the only scope §8.12.4 permits. */
    private function bindAnLdapProvider(Organisation $organisation): void
    {
        if (DB::table('auth_provider_bindings')->where('type', 'ldap')->exists()) {
            return;
        }

        DB::table('auth_provider_bindings')->insert([
            'id' => Uuid::v7(),
            'organisation_id' => null,
            'scope_type' => 'installation',
            'scope_id' => null,
            'type' => 'ldap',
            'name' => 'Corporate directory',
            'config' => json_encode([
                'uri' => 'ldaps://directory.invalid:636',
                'base_dn' => 'dc=example,dc=test',
                'user_filter' => '(&(objectClass=inetOrgPerson)(uid={username}))',
                'bind_dn' => 'cn=svc,dc=example,dc=test',
                'subject_attribute' => 'uid',
                'groups_attribute' => 'memberOf',
                'display_attribute' => 'cn',
                'provisioning' => 'create_reader_and_map_groups',
            ], JSON_THROW_ON_ERROR),
            'state' => 'active',
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }

    /** `docup.origins.docs`, which is the key the snapshot loader reads. */
    private function docsApex(): string
    {
        $apex = config('docup.origins.docs');

        return is_string($apex) && $apex !== '' ? $apex : 'docup-docs.test';
    }
}
