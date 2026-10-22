<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

/*
|------------------------------------------------------------------------------
| Fixtures for the SPEC 18.18 edge verification
|------------------------------------------------------------------------------
| Seeds two projects — one public, one not — publishes a tree to each through
| the REAL HTTP API, and prints what deploy/verify-edge.sh needs to drive its
| requests.
|
| 🛑 It publishes over HTTP rather than by calling the Publisher, deliberately.
| Laravel's `UploadedFile(..., test: true)` bypasses PHP's upload machinery, so
| the entire Phase 03 suite exercised the ingestor without ever sending a real
| multipart body — which is how `upload_max_filesize=2M` survived in the image
| while SPEC 8.21.6 documented a 1 GB ceiling. Going through curl is what found
| it, and is what keeps it found.
|
| Lives in deploy/ rather than _scratch/ because it is part of the CI matrix leg
| and must be committed. It writes rows and publishes artifacts, so it is for a
| disposable environment only; `doctor` has no reason to run it.
*/

/*
| 🛑 Every `use` comes BEFORE the bootstrap, and the order is load-bearing.
|
| PHP builds a file's import table as it compiles top to bottom, so a `use`
| below a reference does not apply to it. With the `require` lines first --
| the obvious layout for a standalone script -- Pint's
| `fully_qualified_strict_types` fixer shortened
| `Illuminate\Contracts\Console\Kernel::class` to `Kernel::class` and added
| the import underneath it. `Kernel::class` then resolved to the GLOBAL
| `\Kernel`, and the script died with "Target class [Kernel] does not exist".
| Pint was satisfied; the file was broken.
|
| `use` declares a name and loads nothing, so it is safe above `require`.
| Keep it that way: moving the require back to the top reintroduces the bug
| the next time Pint runs.
*/

use App\Auth\ApiTokens;
use App\Auth\Capability;
use App\Auth\OrganisationContext;
use App\Auth\Role;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Models\User;
use App\Support\Uuid;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Support\Facades\DB;

require __DIR__.'/../vendor/autoload.php';

$app = require __DIR__.'/../bootstrap/app.php';
$app->make(Kernel::class)->bootstrap();

$context = app(OrganisationContext::class);
$context->spanAllOrganisations();

$apex = (string) config('docup.origins.docs');
$suffix = bin2hex(random_bytes(4));

$organisation = Organisation::query()->create([
    'name' => 'Edge Verification',
    'slug' => 'edge-'.$suffix,
]);

$context->spanAllOrganisations();

$user = User::query()->create([
    'name' => 'Edge Publisher',
    'email' => 'edge-'.$suffix.'@example.test',
    'password' => bin2hex(random_bytes(16)),
]);

DB::table('role_assignments')->insert([
    'id' => Uuid::v7(),
    'organisation_id' => $organisation->id,
    'subject_type' => 'user',
    'subject_id' => $user->id,
    'scope_type' => 'organisation',
    'scope_id' => $organisation->id,
    'role' => Role::OrgAdmin->value,
    'source' => 'manual',
    'created_at' => now(),
    'updated_at' => now(),
]);

$context->for($organisation->id);

[, $token] = app(ApiTokens::class)->mint(
    user: $user,
    organisation: $organisation,
    name: 'edge-verification-'.$suffix,
    capabilities: [Capability::ProjectVersionPublish],
);

/**
 * A minimal tar, written by hand.
 *
 * `PharData` refuses to build some of what the ingestor must accept, and the
 * project's own writer lives in tests/ where production code cannot reach it.
 * Two members: SPEC 8.4.5 makes `html/index.html` mandatory, and the stylesheet
 * is what the exit criterion means by "with working assets".
 *
 * @param  array<string, string>  $files
 */
function docup_tar(string $path, array $files): string
{
    $out = '';

    foreach ($files as $name => $contents) {
        $header = str_pad(substr($name, 0, 100), 100, "\0")
            .sprintf("%07o\0", 0o644)
            .sprintf("%07o\0", 0)
            .sprintf("%07o\0", 0)
            .sprintf("%011o\0", strlen($contents))
            .sprintf("%011o\0", 0)
            .str_repeat(' ', 8)
            .'0'
            .str_repeat("\0", 100)
            ."ustar\0"
            .'00'
            .str_pad('docup', 32, "\0")
            .str_pad('docup', 32, "\0")
            .sprintf("%07o\0", 0)
            .sprintf("%07o\0", 0)
            .str_repeat("\0", 155)
            .str_repeat("\0", 12);

        $sum = 0;

        for ($i = 0; $i < 512; $i++) {
            $sum += ord($header[$i]);
        }

        $out .= substr_replace($header, sprintf("%06o\0 ", $sum), 148, 8);
        $out .= str_pad($contents, (int) (ceil(strlen($contents) / 512) * 512), "\0");
    }

    file_put_contents($path, $out.str_repeat("\0", 1024));

    return $path;
}

$archive = docup_tar(sys_get_temp_dir().'/docup-edge-'.$suffix.'.tar', [
    'html/index.html' => "<!doctype html><html><head><title>Edge</title></head>\n"
        .'<body><h1 id="anchor">Edge verification</h1>'
        .'<link rel="stylesheet" href="assets/site.css">'
        ."</body></html>\n",
    'html/assets/site.css' => "body{color:#222}\n",
]);

/**
 * Create a project with a canonical default-subdomain mount, and publish to it.
 *
 * SPEC 8.10.2: "The **first** domain mount created for a project … MUST be
 * created with `mode='canonical'`." Written directly because Phase 04 has no
 * domain-management surface — SPEC 17 puts claims and verification in Phase 18
 * and gives this phase the tables "rows only".
 */
function docup_seed_project(
    Organisation $organisation,
    string $slug,
    string $visibility,
    string $apex,
): ProjectVersion {
    $project = Project::query()->create([
        'slug' => $slug,
        'name' => 'Edge '.$visibility,
        'visibility' => $visibility,
    ]);

    $version = new ProjectVersion;
    $version->forceFill([
        'organisation_id' => $organisation->id,
        'project_id' => $project->id,
        'slug' => 'latest',
        'kind' => 'channel',
        'language' => 'en',
        // SPEC 12.3 evaluates project visibility first and this second; both are
        // stored and both authoritative, so the version matches the project.
        'visibility' => $visibility,
    ])->save();

    // SPEC 8.6.14: an explicit stored pointer, never derived.
    $project->forceFill(['default_version_id' => $version->id])->save();

    $domainId = Uuid::v7();

    DB::table('domains')->insert([
        'id' => $domainId,
        'organisation_id' => $organisation->id,
        'host' => $slug.'.'.$apex,
        // An installation-owned apex needs no proof of control (SPEC 8.10.4),
        // which is why a default subdomain serves immediately.
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
        // canonical_for_project_id and is_indexable are GENERATED from this.
        'mode' => 'canonical',
        'mount_exposure' => 'inherit',
        'position' => 0,
        'created_at' => now(),
        'updated_at' => now(),
    ]);

    return $version;
}

$public = docup_seed_project($organisation, 'edgepub-'.$suffix, 'public', $apex);
$private = docup_seed_project($organisation, 'edgepriv-'.$suffix, 'members', $apex);

printf("host=%s\n", 'edgepub-'.$suffix.'.'.$apex);
printf("private_host=%s\n", 'edgepriv-'.$suffix.'.'.$apex);
printf("public_path=%s\n", '/en/latest/');
printf("token=%s\n", $token);
printf("archive=%s\n", $archive);
printf("upload_public=%s\n", '/api/v3/projects/edgepub-'.$suffix.'/versions/latest/uploads');
printf("upload_private=%s\n", '/api/v3/projects/edgepriv-'.$suffix.'/versions/latest/uploads');
printf("artifact_root=%s\n", (string) config('artifacts.root'));
printf("edge_driver=%s\n", (string) config('docup.edge.driver'));
