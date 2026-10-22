<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Arch;

use App\Auth\Tenancy;
use App\Auth\TenancyPosture;
use App\Concerns\BelongsToOrganisation;
use Illuminate\Database\Eloquent\Model;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Finder\Finder;

/**
 * 🛑 §8.2.1: "an architecture test MUST fail CI for any model that does not
 * declare a tenancy posture."
 *
 * Reflection only — no database, no container — so this belongs to the set
 * CLAUDE.md rule 5 runs on every change however narrow. Cross-tenant leakage is
 * §14's top finding, and it is cheap to guard and expensive to discover late.
 *
 * Declaration rather than inference is the point. A model without
 * `organisation_id` might be correctly installation-wide or might be a leak
 * nobody noticed, and the two are indistinguishable to a tool that guesses.
 */
final class TenancyTest extends TestCase
{
    /**
     * Every concrete Eloquent model in `app/Models`.
     *
     * @return list<\ReflectionClass<Model>>
     */
    private function models(): array
    {
        $directory = dirname(__DIR__, 2).'/app/Models';

        $finder = (new Finder)->files()->in($directory)->name('*.php');

        $models = [];

        // No @var here: Finder yields its own Symfony\Component\Finder\SplFileInfo,
        // and annotating it as the global \SplFileInfo narrows it wrongly.
        foreach ($finder as $file) {
            /** @var class-string $class */
            $class = 'App\\Models\\'.$file->getBasename('.php');

            if (! class_exists($class)) {
                continue;
            }

            $reflection = new \ReflectionClass($class);

            if ($reflection->isAbstract() || ! $reflection->isSubclassOf(Model::class)) {
                continue;
            }

            /** @var \ReflectionClass<Model> $reflection */
            $models[] = $reflection;
        }

        return $models;
    }

    /** A guard on the guard: a finder that matched nothing would pass everything. */
    public function test_models_were_actually_found(): void
    {
        $this->assertNotEmpty($this->models(), 'no models found; the finder path is wrong');
    }

    /**
     * 🛑 The requirement §8.2.1 names directly.
     */
    public function test_every_model_declares_a_tenancy_posture(): void
    {
        $undeclared = [];

        foreach ($this->models() as $model) {
            if ($model->getAttributes(Tenancy::class) === []) {
                $undeclared[] = $model->getShortName();
            }
        }

        $this->assertSame(
            [],
            $undeclared,
            'these models declare no #[Tenancy] posture (§8.2.1): '.implode(', ', $undeclared)
            ."\n\nAdd one. If the model carries organisation_id use "
            .'TenancyPosture::OrganisationScoped; if it is genuinely installation-wide say so '
            .'and give a `because` explaining why it is not a cross-tenant leak.'
        );
    }

    /**
     * An org-scoped model that forgets the trait is the exact shape of a
     * cross-tenant leak: it has the column, so it looks tenant-aware, and
     * nothing filters it.
     */
    public function test_organisation_scoped_models_apply_the_global_scope(): void
    {
        $missing = [];

        foreach ($this->models() as $model) {
            $attributes = $model->getAttributes(Tenancy::class);

            if ($attributes === []) {
                continue;
            }

            if ($attributes[0]->newInstance()->posture !== TenancyPosture::OrganisationScoped) {
                continue;
            }

            if (! in_array(BelongsToOrganisation::class, $this->traitsOf($model), true)) {
                $missing[] = $model->getShortName();
            }
        }

        $this->assertSame(
            [],
            $missing,
            'these models are declared OrganisationScoped but do not use BelongsToOrganisation, '
            .'so nothing filters them (§8.2.1): '.implode(', ', $missing)
        );
    }

    /**
     * 🛑 Opting out of tenancy filtering requires a stated reason.
     *
     * §4.3 puts the reason beside the rule: a constraint whose reason is
     * missing gets removed by someone who cannot see what it was protecting.
     * Here the inverse applies — an *exemption* whose reason is missing gets
     * copied onto the next model by someone who assumes it was considered.
     */
    public function test_every_tenancy_exemption_states_its_reason(): void
    {
        $unexplained = [];

        foreach ($this->models() as $model) {
            $attributes = $model->getAttributes(Tenancy::class);

            if ($attributes === []) {
                continue;
            }

            $tenancy = $attributes[0]->newInstance();

            if ($tenancy->posture === TenancyPosture::OrganisationScoped) {
                continue;
            }

            if ($tenancy->because === null || trim($tenancy->because) === '') {
                $unexplained[] = $model->getShortName().' ('.$tenancy->posture->value.')';
            }
        }

        $this->assertSame(
            [],
            $unexplained,
            'these models opt out of tenancy filtering without saying why: '
            .implode(', ', $unexplained)
        );
    }

    /**
     * The trait must not be used without the matching declaration either.
     *
     * The mismatch is less dangerous than the reverse but still wrong: the
     * posture is what the architecture test reads, so a model filtered in
     * practice but declared installation-wide tells a reviewer the opposite of
     * the truth.
     */
    public function test_models_using_the_trait_are_declared_scoped(): void
    {
        $mismatched = [];

        foreach ($this->models() as $model) {
            if (! in_array(BelongsToOrganisation::class, $this->traitsOf($model), true)) {
                continue;
            }

            $attributes = $model->getAttributes(Tenancy::class);

            if ($attributes === [] || $attributes[0]->newInstance()->posture !== TenancyPosture::OrganisationScoped) {
                $mismatched[] = $model->getShortName();
            }
        }

        $this->assertSame(
            [],
            $mismatched,
            'these models use BelongsToOrganisation but are not declared OrganisationScoped: '
            .implode(', ', $mismatched)
        );
    }

    /**
     * Traits used by a class and all its parents.
     *
     * `getTraitNames()` is shallow, and a posture test that missed an inherited
     * trait would report a false violation.
     *
     * @param  \ReflectionClass<Model>  $class
     * @return list<string>
     */
    private function traitsOf(\ReflectionClass $class): array
    {
        $traits = [];

        for ($current = $class; $current !== false; $current = $current->getParentClass()) {
            foreach ($current->getTraitNames() as $trait) {
                $traits[] = $trait;
            }
        }

        return $traits;
    }
}
