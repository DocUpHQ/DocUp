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

arch()->preset()->laravel()
    // The preset expects enums under App\Enums. DocUp's enums for the §12.2
    // capability matrix live in App\Auth instead, deliberately: §9.4 raises
    // PHPStan to level 9 for app/Auth specifically, because a type error in
    // authorisation code is a security bug rather than a crash. Moving Role,
    // Capability and Scope to App\Enums to satisfy a file-location convention
    // would move the authorisation model OUT of the namespace the higher bar
    // applies to, and scatter it across two namespaces for no reader benefit.
    //
    // Cohesion by concern beats cohesion by technical type here, and the
    // specification scopes level 9 by namespace, so the namespace is load-bearing.
    ->ignoring([
        'App\Auth',
        // Same reasoning for App\Audit: ActorType is part of the audit
        // concern, and §8.22's chain code is the only thing that means anything
        // by it. Collecting both namespaces' enums under App\Enums would group
        // them by the fact that they are enums, which is the least interesting
        // thing about them.
        //
        // Both exemptions also cover the preset's rule that exceptions live
        // under App\Exceptions. Said out loud because an exemption whose real
        // scope is wider than its comment is the thing the tenancy arch test
        // refuses to allow for models: TenancyContextMissing, AuditKeyMissing
        // and ChainLockUnavailable are each meaningless outside the concern
        // that throws them, and a shared exception namespace would put them
        // next to unrelated ones with nothing in common but their base class.
        'App\Audit',
        // And App\Artifacts, for the same reason twice over. §9.4 raises
        // PHPStan to level 9 for app/Artifacts specifically, so moving
        // EntryType and RejectionCode to App\Enums would move them OUT of the
        // namespace the higher bar covers — and RejectionCode's values are
        // §8.1.11 public contract, which is exactly the kind of thing the
        // stricter analysis is there for.
        //
        // IngestRejected and ArtifactWriteRefused stay in
        // App\Artifacts\Exceptions for the reason above: each is meaningless
        // outside the concern that throws it. IngestRejected carries a
        // RejectionCode, so a shared App\Exceptions would import the artifact
        // namespace into a namespace everything else depends on.
        'App\Artifacts',
        // And App\Serving, third time for the same reason. §9.4 names
        // app/Serving as a level-9 namespace because "a type error in request
        // resolution is a security bug rather than a crash" — so HostKind and
        // RejectionReason belong inside it, not collected under App\Enums by
        // the fact that they are enums. RejectionReason's values also reach
        // `X-DocUp-Resolver` and operator alerting, which is exactly the kind
        // of contract the stricter analysis exists for.
        'App\Serving',
    ]);

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
        // §17 asks for a local driver and an S3 driver "behind the same
        // interface", and the two genuinely differ in how write-once is
        // enforced - a POSIX chmod against a bucket-level Object Lock. The
        // shared key construction has to live somewhere, and duplicating it is
        // how the two drivers come to disagree about where a build's bytes are.
        // So this one class is abstract and exists to be extended; its two
        // subclasses are final and are checked below.
        'App\Artifacts\FilesystemArtifactStore',
        // And its two subclasses, for one method each. enforceImmutability() is
        // the hook that base class declares abstract, and the two drivers do
        // genuinely different things in it - a POSIX chmod against a
        // bucket-level Object Lock. Widening it to public to satisfy the
        // preset's no-protected-methods rule would advertise as API the one
        // thing no caller should reach for: write-once is enforced by put(),
        // and calling the hook directly would skip the check it follows.
        'App\Artifacts\LocalArtifactStore',
        'App\Artifacts\S3ArtifactStore',
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

/*
| 🛑 Restating what the two exemptions above still leave in force for
| App\Artifacts. Dropping a namespace from a preset must not quietly stop
| checking the rules that do hold there, and nothing else would say so.
|
| FilesystemArtifactStore is excluded from the final-class rule and from nothing
| else: it is abstract because §17 asks for two drivers behind one interface, and
| that is the only concession it gets.
*/
arch()
    ->expect('App\Artifacts')
    ->toUseStrictTypes();

/*
| 🛑 And the same restatement for App\Serving. §8.9.1 requires the resolver to
| have "no framework dependencies", which is a stronger claim than any preset
| checks, so these are the parts a preset can still hold it to.
*/
arch()
    ->expect('App\Serving')
    ->toUseStrictTypes();

arch()
    ->expect('App\Serving')
    ->toBeFinal()
    ->ignoring([
        // PHP enums are implicitly final and the keyword is a syntax error on
        // one, so the rule is inapplicable rather than relaxed.
        'App\Serving\HostKind',
        'App\Serving\RejectionReason',
    ]);

arch()
    ->expect('App\Artifacts')
    ->toBeFinal()
    ->ignoring([
        'App\Artifacts\ArtifactStore',            // an interface
        'App\Artifacts\ArchiveReader',            // an interface
        'App\Artifacts\FilesystemArtifactStore',  // abstract by design, see above
        // PHP enums are implicitly final and the keyword is a syntax error on
        // one, so the rule is not relaxed here - it is inapplicable.
        'App\Artifacts\EntryType',
        'App\Artifacts\RejectionCode',
    ]);

arch()
    ->expect('App\Console\Commands')
    ->toBeFinal()
    ->toExtend(Command::class);

arch()
    ->expect('App\Concerns')
    ->toBeTraits();
