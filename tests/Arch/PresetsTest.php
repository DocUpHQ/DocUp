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
        // And App\Support, for §10.8's Epoch. The registry is deliberately
        // cross-cutting — one epoch per concern, exactly one registry — so it
        // cannot live inside any one of the concerns it coordinates, and
        // App\Enums would file it by the fact that it is an enum.
        'App\Support',
        // Phase 05, and the same reason a fourth, fifth and sixth time.
        // phpstan-strict.neon raises app/Egress, app/Source and
        // app/Credentials to level 9, on §9.4's own argument: a type error in
        // an SSRF deny list or a credential envelope is a security bug rather
        // than a crash. Collecting AddressClass, EgressRejection, Provider,
        // IdentifierShape, SourceRejection and CredentialKind under App\Enums
        // would move them OUT of the namespaces the higher bar covers, and
        // would file them by the least interesting thing about them.
        //
        // EgressRefused and SourceRefused stay beside the policies that throw
        // them for the reason the App\Audit note gives: each is meaningless
        // outside its concern, and EgressRefused carries an EgressRejection,
        // so a shared App\Exceptions would import the egress namespace into a
        // namespace everything else depends on.
        'App\Egress',
        'App\Source',
        'App\Credentials',
        // Phase 06, same argument again. Stage, FailureClass and
        // EnvironmentScope are the build pipeline's vocabulary and mean
        // nothing outside it; BuildFailure carries a FailureClass, so a
        // shared App\Exceptions would import the build namespace into a
        // namespace everything else depends on. SPEC 8.5.15's failure classes
        // are also public contract — operators alert on the identifiers — so
        // they belong beside the code that produces them.
        'App\Builds',
        // Phase 09, and the argument has not changed. phpstan-strict.neon
        // raises app/Config to level 9 on §9.4's grounds — a type error in
        // configuration parsing is a security bug rather than a crash, which
        // is why `app/Config/README.md` has said so since Phase 01. Moving
        // ConfigRejection to App\Enums would move it OUT of the namespace the
        // higher bar covers, and its values are §8.1.11 public contract:
        // `config.unknown_key` reaches an operator's alert rule, so it
        // belongs beside the parser that produces it.
        //
        // ConfigRefused stays beside it for the reason the App\Egress note
        // gives: it carries a ConfigRejection, so a shared App\Exceptions
        // would import the configuration namespace into a namespace
        // everything else depends on.
        'App\Config',
        // Phase 10, same argument once more. `RefKind`, `VersionComparator`
        // and `VersionRejection` are the version model's vocabulary and mean
        // nothing outside §8.6 — `RefKind::versionKind()` exists precisely to
        // keep "a git ref's kind" and "a version's kind" as two ideas, which
        // a shared App\Enums would file as one. `VersionRefused` carries a
        // `VersionRejection`, so a shared App\Exceptions would import the
        // version namespace into a namespace everything else depends on.
        //
        // The rejection identifiers are also §8.1.11 public contract:
        // `version.slug_reserved` reaches an operator's tooling, which is
        // the kind of thing that belongs beside the code producing it.
        'App\Versions',
    ]);

arch()->preset()->strict()
    // Each exemption names its reason, so a later reader can remove it
    // deliberately rather than wonder what it was protecting.
    ->ignoring([
        // Laravel's generated providers predate our strict-types pass.
        'App\Providers',
        /*
         * 🛑 Phase 06: the strict preset forbids `sleep`/`usleep`, and these
         * two genuinely wait.
         *
         * The runner is a separate process holding the container-runtime
         * socket with NO database access (SPEC 8.5.13, and Phase 06's exit
         * criterion that its environment carries no credentials), so the
         * worker and the runner exchange work through a spool directory. A
         * directory has no readiness signal, so waiting on one is a poll, and
         * a poll without a sleep is a busy loop that burns a core.
         *
         * The exemption is two named classes, not the namespace: everything
         * else in App\Builds is still held to the rule. It can be removed
         * when the exchange gains something to block on — inotify, or the
         * unix socket Phase 07's trust-zone work may bring with it.
         */
        'App\Builds\BuildPipeline',
        'App\Console\Commands\RunnerCommand',
        /*
         * 🛑 Phase 07, same rule and a different wait: the warden has to be
         * observed to have installed its nftables ruleset before a build
         * container joins its namespace (ADR 0011 records why assuming it
         * is not good enough — the first warden enforced nothing and looked
         * healthy). A container's start-up has no readiness signal either,
         * so the observation is a poll with a deadline.
         *
         * Note the direction: this sleep exists so that a security control
         * is verified rather than assumed. Removing it would mean trusting
         * the control, which is the thing the phase found wrong.
         */
        'App\Builds\Runner\Warden',
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
    ->toUseStrictTypes();

arch()
    ->expect('App\Support')
    ->toBeFinal()
    // PHP enums are implicitly final and the keyword is a syntax error on one,
    // so the rule is inapplicable rather than relaxed. §10.8's registry lives
    // in App\Support because it is cross-cutting: every epoch belongs to a
    // different concern, which is the whole reason the specification insists
    // there be only one of it.
    ->ignoring(['App\Support\Epoch']);

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
        // one, so the rule is inapplicable rather than relaxed. Listed by name
        // rather than by namespace so that adding an enum here is a deliberate
        // act: the suite fails loudly until the new name is added, which is
        // cheaper than a blanket exemption that would also excuse a class.
        // An interface; the final rule does not apply.
        'App\Serving\ArtifactHandoff',
        'App\Serving\FileKind',
        'App\Serving\HostKind',
        'App\Serving\RejectionReason',
        'App\Serving\RouteKind',
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
        'App\Artifacts\InjectionOutcome',
        'App\Artifacts\RejectionCode',
    ]);

arch()
    ->expect('App\Console\Commands')
    ->toBeFinal()
    ->toExtend(Command::class);

arch()
    ->expect('App\Concerns')
    ->toBeTraits();
