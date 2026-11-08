<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

/*
|------------------------------------------------------------------------------
| Fixtures for §17's Phase 24 exit criterion, against a real Keycloak
|------------------------------------------------------------------------------
| Seeds two projects on one installation, each with a private version, each
| guarded by an `oidc` binding pointing at a different Keycloak realm — and
| prints the two documentation hosts deploy/verify-oidc.sh needs.
|
| 🛑 Two REALMS, not two clients on one realm. §17's criterion says "two
| different Keycloak realms", and the difference is the point: two realms have
| separate issuers, separate key sets and separate user directories, so a token
| from one is wrong in every dimension at the other. Two clients on one realm
| would share a key set and only differ by `aud`.
|
| Lives in deploy/ rather than _scratch/ for the reason seed-edge-fixture.php
| does: it is part of a CI matrix leg and must be committed. It writes rows and
| publishes artifacts, so it is for a disposable environment only.
*/

use App\Access\ReaderPolicies;
use App\Artifacts\Publisher;
use App\Auth\OrganisationContext;
use App\Auth\Providers\Bindings;
use App\Auth\Providers\BindingState;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Models\User;
use App\Support\Uuid;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Support\Facades\DB;
use Tests\Support\ArchiveWriter;

/*
| 🛑 Every `use` above the bootstrap, and the order is load-bearing — see the
| long note in seed-edge-fixture.php. Pint's `fully_qualified_strict_types`
| fixer shortens a reference and adds the import underneath it, and an import
| below a reference does not apply to it.
*/
require __DIR__.'/../vendor/autoload.php';

$app = require_once __DIR__.'/../bootstrap/app.php';
$app->make(Kernel::class)->bootstrap();

/** @var OrganisationContext $context */
$context = $app->make(OrganisationContext::class);
$context->spanAllOrganisations();

$suffix = bin2hex(random_bytes(3));

$organisation = Organisation::query()->create([
    'name' => 'Two Realm Co',
    'slug' => 'twor-'.$suffix,
]);

$context->for($organisation->id);

$operator = User::query()->create([
    'name' => 'Operator',
    'email' => 'oidc-'.$suffix.'@example.test',
    'password' => bin2hex(random_bytes(16)),
]);

$apex = config('docup.origins.docs');
$apex = is_string($apex) && $apex !== '' ? $apex : 'docup-docs.localhost';

$fixtures = sys_get_temp_dir().'/docup-oidc-fixture';

if (! is_dir($fixtures)) {
    mkdir($fixtures, 0o755, true);
}

$hosts = [];

foreach (['acme', 'globex'] as $realm) {
    $issuer = env(
        'DOCUP_OIDC_ISSUER_'.strtoupper($realm),
        'https://keycloak:8443/realms/'.$realm,
    );

    $slug = $realm.'-'.$suffix;
    $host = $slug.'.'.$apex;

    /*
     * 🛑 A **public** project with a **private** version, which is the shape a
     * credential is actually for — a mostly-public site with a guarded version
     * — and it makes a refusal a refusal of the version rather than of the
     * project, so §8.12.23's case (b) stays available.
     */
    $project = Project::query()->create([
        'slug' => $slug,
        'name' => ucfirst($realm),
        'visibility' => 'public',
    ]);

    $version = new ProjectVersion;
    $version->forceFill([
        'organisation_id' => $organisation->id,
        'project_id' => $project->id,
        'slug' => 'v1',
        'kind' => 'channel',
        'language' => 'en',
        'visibility' => 'members',
    ])->save();

    /*
     * 🛑 The project's own `ArchiveWriter`, not a hand-rolled tar.
     *
     * The first version of this script wrote the header bytes itself and got
     * the checksum field wrong — `contract.unreadable_archive: Entry: header
     * checksum mismatch`, from the ingestor, which is the ingestor doing its
     * job. `Tests\Support\ArchiveWriter` exists because §9.4's corpus needs
     * archives no library will emit, and it writes correct ones too.
     *
     * Reaching into `tests/` from `deploy/` is unusual and deliberate: this
     * script is a CI fixture, autoload-dev maps `Tests\`, and the alternative
     * is a second tar writer that disagrees with the first.
     */
    $archive = (new ArchiveWriter)
        ->add('html/index.html', '<!doctype html><html><head><title>'.$realm.'</title></head>'
            .'<body><h1>'.$realm.' private</h1></body></html>
')
        ->toTarGz($fixtures.'/'.$slug.'.tar.gz');

    /** @var Publisher $publisher */
    $publisher = $app->make(Publisher::class);
    $publisher->publishUpload($version, $archive);

    $project->forceFill(['default_version_id' => $version->id])->save();

    $domainId = Uuid::v7();

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

    /** @var Bindings $bindings */
    $bindings = $app->make(Bindings::class);

    $bindingId = $bindings->create(
        scopeType: 'project',
        scopeId: $project->id,
        type: 'oidc',
        name: $realm.' realm',
        config: [
            'issuer' => $issuer,
            'client_id' => 'docup-'.$realm,
            'provisioning' => 'create_reader_and_map_groups',
            'groups_claim' => 'groups',
        ],
        /*
         * 🛑 The client secret, which only exists in the realm JSON beside this
         * script and in a disposable Keycloak. Sealed by §9.1.7's envelope on
         * the way in, so it is not readable back out even here.
         */
        secrets: ['client_secret' => $realm.'-client-secret-for-tests-only'],
        organisationId: $organisation->id,
    );

    /*
     * 🛑 §8.12.19's whole progression, including the probe — which **reaches
     * Keycloak**. That is the first real assertion this fixture makes: a probe
     * that cannot fetch the discovery document or the key set fails here,
     * before any reader is involved, with a reason.
     */
    $bindings->transition($bindingId, BindingState::Verifying);

    $probe = $bindings->probe($bindingId);

    if (! $probe->passed) {
        fwrite(STDERR, 'seed-oidc: FAIL the '.$realm." binding's probe failed: ".$probe->summary."\n");
        exit(1);
    }

    $bindings->recordTestLogin($bindingId, $operator->id);
    $bindings->transition($bindingId, BindingState::Active);

    /** @var ReaderPolicies $policies */
    $policies = $app->make(ReaderPolicies::class);

    $policies->createFor($project, actorId: $operator->id);

    /*
     * 🛑 A rule naming **this** binding, which is what makes "two realms"
     * testable: a rule written as a bare `{binding}` would be satisfied by
     * either realm's reader and would prove nothing about isolation.
     */
    $policies->addRule(
        project: $project,
        label: 'admit the '.$realm.' realm',
        allow: true,
        requirement: ['leaf' => 'binding', 'binding_id' => Uuid::toText($bindingId)],
        versionSlugs: ['v1'],
        actorId: $operator->id,
    );

    $hosts[$realm] = $host;

    fwrite(STDERR, 'seed-oidc: '.$realm.' → '.$host.' (probe: '.$probe->summary.")\n");
}

/*
 * What the driver needs, on stdout and nothing else on stdout — so it can be
 * eval'd or read with `grep`.
 */
printf("DOCUP_OIDC_HOST_ACME=%s\n", $hosts['acme']);
printf("DOCUP_OIDC_HOST_GLOBEX=%s\n", $hosts['globex']);
