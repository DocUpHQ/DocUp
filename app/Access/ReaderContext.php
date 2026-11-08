<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Access;

use App\Auth\AccessLevel;

/**
 * What a request established about its reader, before any decision is made.
 *
 * 🛑 **This holds no request, no headers and no cookies**, and that is §8.12.23
 * being enforced by the type system rather than by discipline:
 *
 * > "The denial outcome is decided by the request's **authorisation state**,
 * > never by its `Accept` or `Sec-Fetch-*` headers; those choose only the
 * > *representation* of an already-decided outcome (§8.12.24)."
 *
 * The transport builds one of these, {@see EffectiveAccess} consumes it, and
 * because the decision function can only see what is on this object there is no
 * path by which a client-supplied header could change an outcome. Phase 22
 * fills it from `docs_sessions` and a verified grant; Phase 21 constructs it
 * directly, which is also what makes the generated decision table possible.
 *
 * 🛑 `level` is §12.3's "reader's established context", and it is **not** a
 * function of the resource. `restricted` is: §12.3 defines it as "only a reader
 * satisfying an explicit allow rule naming this component or version", so it is
 * established per resource by {@see EffectiveAccess} and never stored here.
 */
final class ReaderContext
{
    /**
     * @param  AccessLevel  $level  the reader's identity level: `public` for
     *                              anonymous, `authenticated` for a satisfied
     *                              identity leaf, `members` for an identity
     *                              mapping to a role assignment or group on
     *                              this organisation (§12.3)
     * @param  list<AccessLeaf>  $satisfiedLeaves  the leaf kinds this request
     *                                             actually satisfied
     * @param  list<string>  $satisfiedBindings  binding ids satisfied, for a
     *                                           `{binding}` leaf naming one
     * @param  bool  $credentialPresented  🛑 §8.12.23's case (a): "a credential
     *                                     was presented and rejected". The
     *                                     distinction between "no credential"
     *                                     and "a bad credential" is what decides
     *                                     whether a 401 is permitted, so it
     *                                     cannot be inferred from the leaves.
     * @param  bool  $credentialRejected  the presented credential was expired,
     *                                    revoked or out of scope
     * @param  CredentialScope|null  $scope  §12.3's last conjunct, when the
     *                                       satisfying leaf carries one. 🛑 Use
     *                                       {@see self::scopeFor()} to read it:
     *                                       a reader may hold a share **and** a
     *                                       bearer token, and this single field
     *                                       cannot say which scope belongs to
     *                                       which.
     * @param  array<string, CredentialScope>  $scopes  per-leaf scopes, keyed by
     *                                                  {@see AccessLeaf} value.
     *                                                  🛑 Phase 23 added this
     *                                                  because one field is
     *                                                  wrong for a reader who
     *                                                  presents two scoped
     *                                                  credentials: §12.3
     *                                                  applies the scope of the
     *                                                  **satisfying** leaf, and
     *                                                  with one field a reader
     *                                                  holding a wide share
     *                                                  link and a narrow token
     *                                                  would be judged on the
     *                                                  share while the rule
     *                                                  named the token.
     * @param  string|null  $subject  an opaque reader subject, for the decision
     *                                log's keyed digest. 🛑 Never an email:
     *                                §8.12.1 forbids email for linking or
     *                                lookup anywhere in this population.
     */
    public function __construct(
        public readonly AccessLevel $level = AccessLevel::Public,
        public readonly array $satisfiedLeaves = [AccessLeaf::Public],
        public readonly array $satisfiedBindings = [],
        public readonly bool $credentialPresented = false,
        public readonly bool $credentialRejected = false,
        public readonly ?CredentialScope $scope = null,
        public readonly ?string $subject = null,
        public readonly array $scopes = [],
        /*
         * 🛑 §8.12.20's open break-glass window, as the grant's id (raw 16
         * bytes) or null.
         *
         * Part of the reader's **established context** rather than a parameter
         * of the request, because that is what it is: a fact about who this
         * reader is right now, resolved once where the session is known and
         * carried into the one decision function unchanged. The alternative —
         * a flag on {@see AccessRequest} — would have put it beside the
         * resource's properties, where it would read as a property of the
         * resource.
         *
         * 🛑 It is an **id**, not a boolean, so §20.3's log can record
         * which window admitted a read. A boolean would answer "was an override
         * used" and not "which one", and with three activations an hour
         * permitted those are different questions.
         */
        public readonly ?string $breakGlassId = null,
    ) {}

    /**
     * 🛑 The scope that belongs to one leaf — §12.3's last conjunct, read
     * correctly.
     *
     * > "share/bearer scope covers (project, version, path) **if that was the
     * > satisfying leaf**"
     *
     * The conditional is on the *satisfying* leaf, so the scope has to be
     * looked up by it. A reader presenting a share link for `/guide/` and a
     * bearer token for `/api/` satisfies two scoped leaves with two different
     * scopes, and which one applies depends on which leaf the matched rule
     * named — not on which the transport happened to store.
     *
     * Falls back to {@see self::$scope} so Phase 21 and Phase 22's
     * single-credential contexts keep working unchanged.
     */
    public function scopeFor(AccessLeaf $leaf): ?CredentialScope
    {
        return $this->scopes[$leaf->value] ?? $this->scope;
    }

    /** An anonymous reader: the public leaf and nothing else. */
    public static function anonymous(): self
    {
        return new self;
    }

    /**
     * A reader who satisfied an identity leaf but maps to no role or group.
     *
     * @param  list<string>  $bindings
     */
    public static function authenticated(string $subject, array $bindings = []): self
    {
        return new self(
            level: AccessLevel::Authenticated,
            satisfiedLeaves: [AccessLeaf::Public, AccessLeaf::Binding],
            satisfiedBindings: $bindings,
            credentialPresented: true,
            subject: $subject,
        );
    }

    /**
     * A reader whose identity maps to a role assignment or group on this
     * organisation (§12.3's `members`).
     *
     * @param  list<string>  $bindings
     */
    public static function member(string $subject, array $bindings = []): self
    {
        return new self(
            level: AccessLevel::Members,
            satisfiedLeaves: [AccessLeaf::Public, AccessLeaf::Binding],
            satisfiedBindings: $bindings,
            credentialPresented: true,
            subject: $subject,
        );
    }

    /**
     * Whether this reader satisfies a leaf.
     *
     * 🛑 `{public}` is satisfied by everybody, including an anonymous reader,
     * and that is not a loophole: §8.12.7 keeps a requirement from resting on
     * it, and §12.3's lattice keeps a public leaf from reaching a resource that
     * demands more. A public terminal that an anonymous reader could not
     * satisfy would make public documentation unservable.
     *
     * @param  string|null  $bindingId  when the leaf names a specific binding
     */
    public function satisfies(AccessLeaf $leaf, ?string $bindingId = null): bool
    {
        if ($leaf === AccessLeaf::Public) {
            return true;
        }

        if (! in_array($leaf, $this->satisfiedLeaves, true)) {
            return false;
        }

        if ($bindingId === null) {
            return true;
        }

        /*
         * 🛑 A leaf naming a binding is satisfied only by **that** binding. A
         * project with two bindings — an employee IdP and a customer portal —
         * writes one rule per audience, and matching any binding would let a
         * customer read the employee section.
         */
        return in_array($bindingId, $this->satisfiedBindings, true);
    }

    /**
     * 🛑 The strongest leaf this reader actually holds, for a decision reached
     * **without** a rule.
     *
     * §12.3's lattice can admit a reader on its own: a member reading a
     * `members` version with no policy at all is allowed because their
     * established level reaches the required one, and no rule — so no
     * {@see Requirement} — was involved. The decision still has to say *what*
     * admitted them, because §20.3's log and §8.12.25's simulator both key off
     * it.
     *
     * 🛑 **Phase 22 found Phase 21 getting this wrong, and the error was
     * invisible while it was correct.** `EffectiveAccess` defaulted the
     * satisfying leaf to `public` whenever no policy existed, which was true of
     * every reader Phase 21 could construct — they were all anonymous, because
     * §17 put reader identities in Phase 22. The moment a member could read, a
     * `members`-only 200 started reporting `by=public`: an operator reading the
     * decision header or the audit log would see the public terminal named on a
     * response no anonymous reader could ever have obtained.
     *
     * Nothing was over-permitted — the lattice had already decided — but the
     * evidence was wrong, and §8.12.22's nightly policy linter and §8.12.25's
     * simulator are both built on that evidence.
     */
    public function strongestLeaf(): ?AccessLeaf
    {
        foreach (AccessLeaf::strongestFirst() as $leaf) {
            if (in_array($leaf, $this->satisfiedLeaves, true)) {
                return $leaf;
            }
        }

        return null;
    }

    /**
     * Whether this is an authenticated principal, for §8.12.23's `deny_status`.
     *
     * > "A per-project `deny_status='403'` MUST be available for
     * > **authenticated** principals only, never anonymous."
     *
     * 🛑 Read from the established **level**, not from `credentialPresented`. A
     * request carrying an expired share cookie has presented a credential and
     * is anonymous; telling it 403 would confirm the resource exists to anybody
     * who sends a malformed cookie.
     */
    public function isAuthenticated(): bool
    {
        return $this->level->order() >= AccessLevel::Authenticated->order();
    }
}
