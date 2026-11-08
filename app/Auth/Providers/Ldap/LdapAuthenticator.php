<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers\Ldap;

use App\Auth\Providers\BindingContext;
use App\Auth\Providers\Federation\ProvisioningMode;
use App\Auth\Providers\Federation\ProvisioningRefused;
use App\Auth\Providers\Federation\ReaderProvisioning;
use App\Models\ReaderIdentity;

/**
 * §8.12.18's LDAP sign-in, orchestrated once.
 *
 * 🛑 **The only place in DocUp where a reader's directory password is
 * handled.** {@see LdapDriver} deliberately holds none of this: its
 * `attempt()` is satisfied by a *session*, because binding on every reader
 * request would put the password on every request and a directory round-trip
 * in front of every page. The bind happens here, once, and §8.12.10's handoff
 * carries it afterwards.
 *
 * The protocol requirements are not restated here either — they live in
 * {@see LdapConnection} and {@see LdapFilter}, with no options to weaken. What
 * this class owns is the **order** of the three steps and what each failure is
 * allowed to tell the reader.
 *
 * ## 🛑 Search, then bind — and never the other way round
 *
 * A reader types a username, not a DN. The service account searches for the
 * entry, and the reader's password is then verified by binding **as the DN the
 * directory returned**. Building a DN by interpolating the username into a
 * template is the alternative, and it is wrong twice over: it assumes a flat
 * directory, and `ldap_bind()` with a crafted value is how an injected DN
 * authenticates as somebody else.
 *
 * ## 🛑 Not found and wrong password are the same answer
 *
 * {@see self::authenticate()} throws {@see LdapRefused} for both, and the
 * caller is given no way to tell them apart. The reason is not politeness:
 * a form that said "no such user" would be a **username oracle against the
 * operator's own directory**, readable by anyone who can reach the sign-in
 * page, and the thing it enumerates is the employee list. §8.12.23's
 * disclosure rule says the same thing about 404-versus-401, and the reasoning
 * transfers intact.
 *
 * 🛑 And the search result is **not** short-circuited: when no entry matches,
 * the password is still checked against a DN that cannot bind, so the two
 * paths both pay for one directory round-trip. This is a narrowing of the
 * timing signal, not a constant-time guarantee — a remote directory's own
 * latency is not ours to flatten — and saying so is the point of this
 * paragraph, because a comment claiming constant time would be read as one.
 */
final readonly class LdapAuthenticator
{
    /**
     * 🛑 A DN that exists in no directory, used to spend the same bind a real
     * reader's password would.
     *
     * `cn=` with an empty value is syntactically a DN and semantically
     * nothing: RFC 4514 permits the empty attribute value, every directory
     * parses it, and none of them has an entry at it. A random DN would also
     * work and would be worse — it would occasionally name something.
     */
    private const string NO_SUCH_DN = 'cn=,dc=invalid';

    public function __construct(private ReaderProvisioning $provisioning) {}

    /**
     * Authenticate a reader against the directory this binding names.
     *
     * @param  string  $username  as the reader typed it; escaped by
     *                            {@see LdapFilter::build()} before it reaches
     *                            the directory and never used to build a DN
     *
     * @throws LdapRefused when the extension is absent, the directory is
     *                     unreachable, its TLS cannot be verified, the service
     *                     account cannot bind, the search fails or is
     *                     ambiguous, or the reader's credentials do not verify
     *                     — the last of which deliberately covers both "no
     *                     such entry" and "wrong password"
     * @throws ProvisioningRefused when the
     *                             binding's provisioning mode refuses this reader
     */
    public function authenticate(BindingContext $binding, string $username, string $password): ReaderIdentity
    {
        $uri = $this->required($binding, 'uri');
        $subjectAttribute = $binding->string('subject_attribute') ?? 'uid';
        $groupsAttribute = $binding->string('groups_attribute') ?? 'memberOf';
        $displayAttribute = $binding->string('display_attribute') ?? 'cn';

        $connection = LdapConnection::open(
            $uri,
            $this->required($binding, 'bind_dn'),
            $binding->secret('bind_password') ?? '',
        );

        try {
            $entry = $this->lookUp(
                connection: $connection,
                baseDn: $this->required($binding, 'base_dn'),
                filter: LdapFilter::build($this->required($binding, 'user_filter'), ['username' => $username]),
                attributes: array_values(array_unique([$subjectAttribute, $groupsAttribute, $displayAttribute])),
            );
        } finally {
            /*
             * Closed before the reader's own bind, not after. The service
             * account's handle has nothing left to do, and a connection held
             * open across a second bind is the shape that invites somebody to
             * re-use it — which {@see LdapConnection::verifyPassword()}
             * explains is how the service account's privileges get left behind.
             */
            $connection->close();
        }

        if (! LdapConnection::verifyPassword($uri, $entry['dn'], $password)) {
            throw LdapRefused::of(LdapRejection::CredentialsRejected);
        }

        /*
         * 🛑 A reader whose entry was not found reaches this line having spent
         * a real bind, and is refused here rather than earlier. See the class
         * note: the refusal must not say which of the two it was.
         */
        if ($entry['found'] === false) {
            throw LdapRefused::of(LdapRejection::CredentialsRejected);
        }

        $subject = $this->firstValue($entry['attributes'], $subjectAttribute);

        if ($subject === null) {
            /*
             * 🛑 The configured subject attribute is empty on this entry, and
             * that is a refusal rather than a fallback to the DN or to an
             * email. §8.12.1 keys reader identities on `(binding_id,
             * subject_hash)` and forbids email for linking; a silent fallback
             * would key two readers on whatever the fallback happened to
             * share.
             */
            throw LdapRefused::of(
                LdapRejection::SubjectNotFound,
                'the entry carries no `'.$subjectAttribute.'`',
            );
        }

        $claims = ['sub' => $subject];

        /*
         * 🛑 Keyed by the OPERATOR's spelling, and read by the DIRECTORY's.
         *
         * {@see LdapConnection::findOne()} returns attributes keyed in lower
         * case, because `ldap_get_entries()` lowercases them -- LDAP attribute
         * names are case-insensitive by RFC 4512 and the extension picks one
         * spelling. The operator, meanwhile, configured `memberOf`, and
         * `GroupMappings::assertedGroups()` looks the claim up by the name this
         * driver reports. So the two spellings are reconciled exactly here, and
         * {@see self::firstValue()} and {@see self::valuesOf()} are that seam.
         *
         * 🛑 Measured against a real directory: `uid` and `cn` are already
         * lower case and worked by luck, and `memberOf` did not -- so every
         * group arrived empty while the subject and the display name arrived
         * fine. Eight tests passed and the two about groups failed, which is a
         * much better outcome than the reverse and is the reason this comment
         * names the mechanism rather than the symptom.
         *
         * The groups arrive as a list because §8.13.7 reads them as one, and
         * the display name as a string for the same reason SAML's does.
         */
        $groups = $this->valuesOf($entry['attributes'], $groupsAttribute);

        if ($groups !== []) {
            $claims[$groupsAttribute] = $groups;
        }

        $display = $this->firstValue($entry['attributes'], $displayAttribute);

        if ($displayAttribute !== $subjectAttribute && $display !== null) {
            $claims[$displayAttribute] = $display;
        }

        return $this->provisioning->provision(
            binding: $binding,
            mode: ProvisioningMode::fromConfig($binding->string('provisioning')),
            claims: $claims,
            groupsClaim: $groupsAttribute,
        );
    }

    /**
     * The entry, or a stand-in that spends the same bind as a real one.
     *
     * @param  list<string>  $attributes
     * @return array{dn: string, attributes: array<string, list<string>>, found: bool}
     *
     * @throws LdapRefused on any failure that is not "no such entry"
     */
    private function lookUp(
        LdapConnection $connection,
        string $baseDn,
        string $filter,
        array $attributes,
    ): array {
        try {
            $entry = $connection->findOne($baseDn, $filter, $attributes);

            return [...$entry, 'found' => true];
        } catch (LdapRefused $refused) {
            /*
             * 🛑 Only this one case is absorbed. `SubjectAmbiguous`,
             * `SearchFailed` and everything else propagate, because they are
             * the operator's faults and the audit chain is owed the reason —
             * and absorbing them would hide a misconfigured filter behind
             * "wrong password" for every reader at once.
             */
            if ($refused->rejection !== LdapRejection::SubjectNotFound) {
                throw $refused;
            }

            return ['dn' => self::NO_SUCH_DN, 'attributes' => [], 'found' => false];
        }
    }

    /**
     * Every value of one attribute, looked up by the directory's spelling.
     *
     * @param  array<string, list<string>>  $attributes
     * @return list<string>
     */
    private function valuesOf(array $attributes, string $name): array
    {
        return $attributes[mb_strtolower($name)] ?? [];
    }

    /**
     * The first value of one attribute, or null where it is absent or empty.
     *
     * @param  array<string, list<string>>  $attributes
     */
    private function firstValue(array $attributes, string $name): ?string
    {
        $value = $this->valuesOf($attributes, $name)[0] ?? null;

        return $value === '' ? null : $value;
    }

    /**
     * @throws LdapRefused when the binding lacks a value its own validation
     *                     required, which means the row was written by
     *                     something other than {@see LdapDriver::validate()}
     */
    private function required(BindingContext $binding, string $key): string
    {
        $value = $binding->string($key);

        if ($value === null || $value === '') {
            throw LdapRefused::of(LdapRejection::BindCredentialsMissing, 'the binding has no `'.$key.'`');
        }

        return $value;
    }
}
