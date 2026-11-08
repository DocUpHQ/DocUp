<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth;

use App\Http\Middleware\RequireMfaEnrolment;
use App\Models\Organisation;
use App\Models\User;

/**
 * 🛑 §8.13.4, as one function.
 *
 * > "MFA MUST be enforceable per installation and per organisation, **required
 * > above `project_writer`**, via TOTP, with passkeys where the library proves
 * > production-ready (§18)."
 *
 * Four separate facts have to agree before a person is held out of their own
 * dashboard, and every one of them is a way to get this wrong:
 *
 * 1. **Is enforcement on**, at the installation or at an organisation this
 *    person holds a role in?
 * 2. **Does any role they hold require it** ({@see Role::requiresMfa()} —
 *    §8.13.4's "above `project_writer`")?
 * 3. **Are they enrolled** — and enrolled means a *confirmed* secret, not a
 *    secret?
 * 4. If all three, are they asking for something they must be allowed to reach
 *    anyway, so they can fix it?
 *
 * This class owns 1–3. {@see RequireMfaEnrolment} owns 4,
 * because only the transport knows what was asked for.
 *
 * ## 🛑 The installation switch dominates
 *
 * An organisation cannot turn off a requirement the installation imposes. That
 * ordering is the only one that makes the installation switch worth having: the
 * reverse would mean a tenant administrator could opt their own organisation
 * out of the operator's security posture, which is not a setting, it is a
 * vulnerability with a checkbox.
 *
 * ## 🛑 Why the role test spans every organisation the person belongs to
 *
 * §8.13.4 attaches the requirement to the **role**, not to the request. A
 * person who administers organisation A and reads organisation B is an
 * administrator; they do not stop being one while they are looking at B. So
 * enrolment is a property of the account, checked once per request, and not a
 * per-page question — which also means they cannot be walked through a
 * half-blocked dashboard discovering which pages work.
 *
 * ## 🛑 Passkeys are deliberately absent
 *
 * §8.13.4 says "with passkeys where the library proves production-ready (§18)"
 * and §18 carries **no passkey row** — not an unverified one, none at all. Phase
 * 02's `config/fortify.php` already recorded the consequence by leaving
 * `Features::passkeys()` commented out. Phase 26a proposes the amendment that
 * adds the §18 assumption rather than inventing a verdict for an assumption
 * nobody wrote. TOTP is the mandatory path and is what this enforces.
 */
final readonly class MfaEnforcement
{
    public function __construct(
        private RoleResolver $roles,
        private OrganisationContext $context,
    ) {}

    /**
     * 🛑 Whether this person must enrol before they may use the dashboard.
     *
     * The three conjuncts in order, cheapest first — and the order matters for
     * more than speed: an installation with enforcement off and no organisation
     * requiring it pays one `config()` read and one query per request, which is
     * what makes it affordable to ask on every request rather than caching an
     * answer that a role change would invalidate.
     */
    public function blocks(User $user): bool
    {
        if (! $this->isRequiredFor($user)) {
            return false;
        }

        return ! self::isEnrolled($user);
    }

    /**
     * Whether any scope this person belongs to requires MFA of a role they
     * hold.
     */
    public function isRequiredFor(User $user): bool
    {
        if (self::installationRequires()) {
            /*
             * 🛑 Installation-wide: every role this person holds counts, in
             * every scope — including an installation-scope one that belongs to
             * no organisation at all, which is exactly the person the
             * installation switch exists for.
             */
            return $this->holdsARoleRequiringMfa($user, null);
        }

        foreach ($this->organisationsRequiring($user) as $organisationId) {
            if ($this->holdsARoleRequiringMfa($user, $organisationId)) {
                return true;
            }
        }

        return false;
    }

    /**
     * The roles this person holds in scopes where enforcement is on.
     *
     * 🛑 For the enrolment page to say **why**, in §12.1's own role names. A
     * page that said only "two-factor authentication is required" sends a
     * person to ask an administrator a question the installation can already
     * answer, once per person on it.
     *
     * Returns every role in the enforcing scopes, not only the obliging ones:
     * the caller filters on {@see Role::requiresMfa()}, because "which of my
     * roles did this" and "what am I" are different questions and this one is
     * the second.
     *
     * @return list<Role>
     */
    public function rolesObliging(User $user): array
    {
        if (self::installationRequires()) {
            return $this->roles->rolesAnywhere($user);
        }

        $roles = [];

        foreach ($this->organisationsRequiring($user) as $organisationId) {
            foreach ($this->roles->rolesAnywhere($user, $organisationId) as $role) {
                $roles[$role->value] = $role;
            }
        }

        return array_values($roles);
    }

    /**
     * 🛑 §8.13.4's enrolment test: a **confirmed** secret.
     *
     * `two_factor_secret` alone is somebody who opened the QR-code screen and
     * closed the tab. Treating that as enrolment would lock them out with a
     * secret no authenticator holds, and the only remedy would be an operator
     * clearing the column — which is why `config/fortify.php` sets
     * `'confirm' => true` and why this reads the confirmation rather than the
     * secret.
     */
    public static function isEnrolled(User $user): bool
    {
        return $user->two_factor_confirmed_at !== null;
    }

    /** §8.13.4's installation switch, from configuration (§11's deployment profile). */
    public static function installationRequires(): bool
    {
        return config('docup.mfa.required') === true;
    }

    /**
     * Turn enforcement on or off for one organisation.
     *
     * 🛑 Here rather than on the model, so that the ordering rule above has
     * exactly one place that can be read and one place that can be changed. A
     * `$organisation->mfa_required = false` somewhere else would look like it
     * had turned enforcement off and would not have.
     */
    public static function setForOrganisation(Organisation $organisation, bool $required): void
    {
        $organisation->forceFill(['mfa_required' => $required])->save();
    }

    /**
     * Whether this organisation's own switch is on, ignoring the installation.
     *
     * For an operator page that has to show what the tenant chose, distinctly
     * from what they are getting.
     */
    public static function organisationRequires(Organisation $organisation): bool
    {
        return (bool) $organisation->mfa_required;
    }

    /**
     * The organisations with enforcement on in which this person holds any
     * role.
     *
     * 🛑 Two reads rather than one join, and not for tidiness: §8.2.1's global
     * scope would filter the `organisations` read to the *current* tenant,
     * while the question is deliberately about every organisation this person
     * belongs to — they do not stop being an administrator of A while they are
     * looking at B. So the ids come from {@see RoleResolver}, the sole reader of
     * `role_assignments` (an architecture test enforces it), and the switch is
     * read across the span the question needs.
     *
     * @return list<string> raw 16 bytes
     */
    private function organisationsRequiring(User $user): array
    {
        $ids = $this->roles->organisationIdsFor($user);

        if ($ids === []) {
            return [];
        }

        /** @var list<string> $requiring */
        $requiring = $this->context->acrossAllOrganisations(
            static fn (): array => Organisation::query()
                ->whereIn('id', $ids)
                ->where('mfa_required', true)
                ->pluck('id')
                ->all(),
        );

        return $requiring;
    }

    /**
     * Whether any role this person holds in a scope obliges enrolment.
     *
     * 🛑 {@see RoleResolver::rolesAnywhere()} rather than `rolesFor()`, because
     * §8.13.4 attaches the requirement to the role and `rolesFor()` includes a
     * project-scope assignment only when it is handed a project. A person whose
     * only role is `project_admin` on one project is an administrator, and
     * asking the narrower question would have let exactly that person past —
     * silently, since nothing about the check would look wrong.
     *
     * @param  string|null  $organisationId  raw 16 bytes, or null for the
     *                                       installation scope
     */
    private function holdsARoleRequiringMfa(User $user, ?string $organisationId): bool
    {
        foreach ($this->roles->rolesAnywhere($user, $organisationId) as $role) {
            if ($role->requiresMfa()) {
                return true;
            }
        }

        return false;
    }
}
