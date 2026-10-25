<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Console\Commands;

use App\Auth\OrganisationContext;
use App\Composition\CompositionRefused;
use App\Docs\DogfoodPlan;
use App\Docs\DogfoodProvisioner;
use App\Models\Organisation;
use App\Support\Uuid;
use Illuminate\Console\Command;

/**
 * `docup:dogfood` — stand DocUp's own manual up on this installation.
 *
 * §17 Phase 17: "DocUp's own documentation split across three repositories,
 * composed into one project, served by the installation itself." This is the
 * "served by the installation itself" half — the part a test cannot be, because
 * the point of dogfooding is that a real operator runs the real write path and
 * finds out what is awkward.
 *
 * It provisions the composition and stops. Builds are a webhook's or
 * `docup:poll-repositories`' job (§8.5), and a provisioning command that also
 * built would be the one place in DocUp where changing configuration
 * implicitly spends a build sandbox.
 */
final class DogfoodCommand extends Command
{
    protected $signature = 'docup:dogfood
        {--organisation= : Organisation slug; the only one, if there is only one}
        {--operator-repo= : Clone URL for the operator guide}
        {--author-repo= : Clone URL for the author guide}
        {--reference-repo= : Clone URL for the .docup.yaml reference}';

    protected $description = "Compose DocUp's own manual from its three documentation repositories";

    public function __construct(private readonly OrganisationContext $context)
    {
        parent::__construct();
    }

    public function handle(DogfoodProvisioner $provisioner): int
    {
        $organisation = $this->organisation();

        if (! $organisation instanceof Organisation) {
            return self::FAILURE;
        }

        $overrides = array_filter([
            'docup-operator' => $this->stringOption('operator-repo'),
            'docup-author' => $this->stringOption('author-repo'),
            'docup-reference' => $this->stringOption('reference-repo'),
        ], is_string(...));

        $this->context->for($organisation->id);

        try {
            $version = $provisioner->provision($organisation->id, $overrides);
        } catch (CompositionRefused $refused) {
            /*
             * Reported as the identifier rather than as a stack trace: these
             * are §8.1.11 public contract and an operator searching for
             * `composition.min_access_ceiling_exceeded` should find the same
             * string the audit log holds.
             */
            $this->components->error($refused->identifier().' — '.$refused->getMessage());

            return self::FAILURE;
        }

        $this->components->info('Composed '.DogfoodPlan::PROJECT.' from '.count(DogfoodPlan::guides()).' repositories.');

        foreach (DogfoodPlan::guides() as $guide) {
            $this->components->twoColumnDetail(
                $guide['name'],
                '<fg=gray>'.($guide['mount'] === '' ? '/' : '/'.$guide['mount'].'/').'</>',
            );
        }

        $this->newLine();
        $this->components->bulletList([
            'Version '.Uuid::toText($version->id).' is composed and not yet published.',
            'Push to a guide, or run `php artisan docup:poll-repositories`, to build it.',
            'The same pages build without DocUp: `mkdocs build --strict`.',
        ]);

        return self::SUCCESS;
    }

    /**
     * The organisation to provision into.
     *
     * Named explicitly, or inferred only when there is exactly one — an
     * installation with several tenants must not have its manual land in
     * whichever one sorted first.
     */
    private function organisation(): ?Organisation
    {
        return $this->context->acrossAllOrganisations(function (): ?Organisation {
            $slug = $this->stringOption('organisation');

            if (is_string($slug)) {
                $named = Organisation::query()->where('slug', $slug)->first();

                if (! $named instanceof Organisation) {
                    $this->components->error('No organisation with slug "'.$slug.'".');
                }

                return $named;
            }

            /** @var list<Organisation> $all */
            $all = array_values(Organisation::query()->limit(2)->get()->all());

            if ($all === []) {
                $this->components->error('No organisation exists yet; run `php artisan docup:install` first.');

                return null;
            }

            if (count($all) > 1) {
                $this->components->error('Several organisations exist; name one with --organisation=<slug>.');

                return null;
            }

            return $all[0];
        });
    }

    private function stringOption(string $name): ?string
    {
        $value = $this->option($name);

        return is_string($value) && $value !== '' ? $value : null;
    }
}
