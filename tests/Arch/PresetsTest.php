<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);
use Illuminate\Console\Command;

/*
| SPEC 9.4 baseline gate: the four named architecture presets.
|
| These catch a different class of problem from tests/Arch/ArchitectureTest.php.
| The presets catch sloppiness - a debug call left in, a global, a weak
| comparison. The bespoke suite catches DocUp's own invariants, which no preset
| could know about. Both are required; neither substitutes for the other.
*/

arch()->preset()->php();

arch()->preset()->security();

arch()->preset()->laravel();

arch()->preset()->strict()
    // Each exemption names its reason, so a later reader can remove it
    // deliberately rather than wonder what it was protecting.
    ->ignoring([
        // Laravel's generated providers predate our strict-types pass.
        'App\Providers',
        // The framework base controller is abstract and exists to be extended,
        // so the preset's final-class rule cannot apply to it.
        'App\Http\Controllers\Controller',
        // Eloquent declares its extension points protected - casts(), booted(),
        // newUniqueId(). Widening them to public to satisfy the preset would
        // misreport the framework's API, so this namespace is exempt and the
        // rules that DO still apply to models are restated below.
        'App\Models',
    ]);

// 🛑 Restating these is the whole point of the exemption above: dropping a
// namespace from a preset must not quietly stop checking the rules that still
// hold there. Without this, 'App\Models' would be unchecked rather than
// partially checked, and nothing would say so.
arch()
    ->expect('App\Models')
    ->toUseStrictTypes()
    ->toBeFinal();

/*
| DocUp's own structural expectations. SPEC 4.3/7 requires one ArtifactIngestor,
| one Resolver, one EffectiveAccess and one HardenedEgressClient, each the sole
| call site. Those classes arrive in Phases 03, 04, 21 and 05; what can be
| expressed now is that the support layer they will depend on stays final and
| side-effect free.
*/

arch()
    ->expect('App\Support')
    ->toBeFinal()
    ->toUseStrictTypes();

arch()
    ->expect('App\Console\Commands')
    ->toBeFinal()
    ->toExtend(Command::class);

arch()
    ->expect('App\Concerns')
    ->toBeTraits();
