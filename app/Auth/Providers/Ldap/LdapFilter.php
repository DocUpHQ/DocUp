<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers\Ldap;

use App\Auth\Providers\BindingRefused;
use App\Auth\Providers\BindingRejection;

/**
 * 🛑 §8.12.18's first LDAP requirement: "DN and filter escaping".
 *
 * This is the whole of it, and it is a class rather than two calls because the
 * vulnerability it prevents is one of the oldest in directory services and the
 * safe form is not the obvious one.
 *
 * ## 🛑 The attack, concretely
 *
 * An operator configures `user_filter` as `(uid={username})`. A reader submits
 * the username:
 *
 * ```
 * *)(uid=*))(|(uid=*
 * ```
 *
 * Interpolated raw, the filter becomes
 * `(uid=*)(uid=*))(|(uid=*)` — a syntactically valid filter matching **every**
 * entry in the directory. The search returns the first user in the tree, DocUp
 * binds as them if the attacker also knows *any* valid password, and the
 * reader is somebody else. Variants turn a filter into a blind oracle for
 * enumerating attributes one character at a time.
 *
 * The remedy is RFC 4515 §3's escaping of `\`, `*`, `(`, `)` and NUL, which
 * PHP's `ldap_escape()` implements — and the reason this class exists is that
 * the dangerous thing is not getting the escape wrong, it is **forgetting to
 * call it** on one of several values in a template somebody edits later.
 *
 * ## 🛑 So the template never meets an unescaped value
 *
 * {@see self::build()} takes a template and a map, escapes every value, and
 * refuses a template with a placeholder the map does not supply. There is no
 * way to pass a pre-interpolated filter, no way to opt out of escaping, and no
 * `raw` parameter — the shape §8.12.18 means by "framework-enforced, not
 * driver-optional". {@see LdapDriver} never builds a filter itself.
 *
 * 🛑 **And a DN is escaped differently from a filter.** RFC 4514's DN rules
 * escape `,`, `+`, `"`, `\`, `<`, `>`, `;`, leading and trailing spaces and a
 * leading `#` — a different set from RFC 4515's, with a different meaning for
 * the same byte. `ldap_escape()` takes a flag for each and using the wrong one
 * produces a value that looks escaped and is not.
 */
final class LdapFilter
{
    /**
     * The placeholder grammar: `{name}`, where `name` is a short identifier.
     *
     * 🛑 Deliberately narrow. A grammar that admitted arbitrary text between
     * the braces would make "is this a placeholder" a question with a clever
     * answer, and the thing being decided is which bytes get escaped.
     */
    private const string PLACEHOLDER = '/\{([a-z][a-z0-9_]{0,31})\}/';

    /**
     * Build a search filter from a template, escaping every value.
     *
     * @param  string  $template  an RFC 4515 filter with `{name}` placeholders,
     *                            as an operator configured it
     * @param  array<string, string>  $values  the untrusted values, escaped here
     * @return string a filter safe to send
     *
     * @throws BindingRefused when the template names a value the caller did not
     *                        supply, which is a configuration error rather than
     *                        an attack — but one whose silent handling would be
     *                        a filter containing a literal `{username}`
     */
    public static function build(string $template, array $values): string
    {
        $missing = [];

        $filter = (string) preg_replace_callback(
            self::PLACEHOLDER,
            static function (array $match) use ($values, &$missing): string {
                $name = $match[1];

                if (! array_key_exists($name, $values)) {
                    $missing[] = $name;

                    return '';
                }

                /*
                 * 🛑 `LDAP_ESCAPE_FILTER`, never `LDAP_ESCAPE_DN`, and never
                 * both. The two escape different bytes to different forms;
                 * a DN-escaped value inside a filter leaves `*` and `(`
                 * untouched, which is the whole attack.
                 */
                return ldap_escape($values[$name], '', LDAP_ESCAPE_FILTER);
            },
            $template,
        );

        if ($missing !== []) {
            throw BindingRefused::of(
                BindingRejection::ConfigInvalid,
                'the LDAP filter names a value nothing supplied: '.implode(', ', array_unique($missing)),
            );
        }

        return $filter;
    }

    /**
     * Escape one component of a distinguished name (RFC 4514).
     *
     * 🛑 A **component**, not a whole DN. Escaping a complete DN would escape
     * its own commas and produce a single malformed RDN — so this is for
     * building `uid=<value>,ou=people,dc=example,dc=test` from an untrusted
     * `<value>`, and the structure around it comes from configuration.
     */
    public static function escapeDnComponent(string $value): string
    {
        return ldap_escape($value, '', LDAP_ESCAPE_DN);
    }

    /**
     * 🛑 Refuse a template at **write** time if it is not a filter at all.
     *
     * Three shapes, each of which an operator writes and each of which fails
     * differently at read time:
     *
     * - **Unbalanced parentheses.** The directory answers with a protocol
     *   error, which surfaces as "the provider is unreachable" and sends the
     *   operator to check their network.
     * - **No placeholder.** A filter that ignores the username matches the same
     *   entry for every reader — so the first person in the tree becomes
     *   everybody. This is the one worth refusing loudest: it *works*, for one
     *   reader, which is how it reaches production.
     * - **A bare `*` as the whole value**, as in `(uid=*)`. Matches every
     *   entry, with the same consequence.
     *
     * @throws BindingRefused
     */
    public static function assertUsable(string $template): void
    {
        if ($template === '' || mb_strlen($template) > 512) {
            throw BindingRefused::of(
                BindingRejection::ConfigInvalid,
                'an LDAP `user_filter` is between 1 and 512 characters',
            );
        }

        if (substr_count($template, '(') !== substr_count($template, ')')) {
            throw BindingRefused::of(
                BindingRejection::ConfigInvalid,
                'the LDAP `user_filter` has unbalanced parentheses',
            );
        }

        if (preg_match(self::PLACEHOLDER, $template) !== 1) {
            throw BindingRefused::of(
                BindingRejection::ConfigInvalid,
                '🛑 the LDAP `user_filter` names no `{username}` placeholder, so it would match '
                .'the same entry for every reader',
            );
        }

        /*
         * 🛑 A wildcard **beside** a placeholder is the operator writing
         * `(uid={username}*)` and getting prefix matching they did not mean:
         * `al` would match `alice`. Refused rather than normalised, because
         * guessing which of the two they wanted is how a narrowing becomes a
         * widening.
         */
        if (preg_match('/\*\s*\}|\{\s*\*|\}\*|\*\{/', $template) === 1) {
            throw BindingRefused::of(
                BindingRejection::ConfigInvalid,
                '🛑 a wildcard beside the placeholder makes the LDAP filter match by prefix',
            );
        }
    }
}
