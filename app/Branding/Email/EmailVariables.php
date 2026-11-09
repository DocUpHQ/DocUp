<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding\Email;

/**
 * 🛑 §8.14.13's "pre-escaped variable map".
 *
 * > "Email customisation MUST be structured slot overrides plus Markdown with
 * > HTML disabled, substituted over a **pre-escaped variable map**."
 *
 * Two properties, and both are in the name.
 *
 * **Pre-escaped**: a value is escaped once, here, when the map is built — by
 * the code that knows what the value is. {@see SlotMarkdown::substitute()} then
 * replaces placeholders in finished HTML without escaping anything, which is
 * why it cannot double-escape. A project called `Smith & Sons` arrives as
 * `Smith &amp; Sons` exactly once.
 *
 * **A map**: the placeholder set is fixed and per slot. A tenant's slot text
 * cannot reach a value they were not given, because
 * {@see SlotMarkdown::render()} refuses a placeholder outside the slot's list
 * rather than leaving it unsubstituted. That is the difference between a map
 * and a template context: a context is everything the renderer happens to
 * have, and the classic template-engine disclosure is a tenant discovering
 * which variable names exist.
 *
 * 🛑 **No placeholder is a reader's identity.** There is no `{reader_email}`
 * and no `{reader_name}`, at any slot. The slots are authored by the tenant and
 * the email goes to a person whose address the tenant may not hold — so a
 * placeholder that echoed the recipient would let a tenant confirm, from the
 * rendered email, an address DocUp holds and they do not. §8.12.23's
 * disclosure boundary applied to a mail template.
 */
final class EmailVariables
{
    /**
     * Which placeholders each slot may name.
     *
     * 🛑 Per slot rather than global. `{action_url}` belongs in the paragraph
     * before the button and nowhere else: a sign-off that could carry the
     * action URL would be a sign-off a tenant could turn into a second,
     * differently-worded call to action beneath DocUp's own.
     *
     * @return list<string>
     */
    public static function availableTo(EmailSlot $slot): array
    {
        return match ($slot) {
            EmailSlot::Greeting => ['installation', 'organisation'],
            EmailSlot::Intro => ['installation', 'organisation', 'project', 'action_url'],
            EmailSlot::Outro => ['installation', 'organisation', 'project'],
            EmailSlot::Signoff => ['installation', 'organisation'],
            EmailSlot::FooterNote => ['installation', 'organisation'],
        };
    }

    /**
     * Build the escaped map for one send.
     *
     * Only the keys a value was supplied for are present, so a slot naming
     * `{project}` on an email that has no project refuses at render rather
     * than emitting an empty space where a name should be.
     *
     * 🛑 **Every value here is DocUp's own**, and that is a precondition
     * rather than an observation. {@see SlotMarkdown} admits a placeholder as
     * a whole link target precisely because of it: the tenant chooses which
     * name to use and DocUp chooses what it holds. A caller that passed a
     * tenant-supplied string in as `action_url` would be handing a tenant the
     * link target of an email DocUp sends — so the values come from the
     * sending code's own context, never from a request.
     *
     * The escaping is HTML escaping, because every value lands either in HTML
     * text or in an `href` attribute, and `&` → `&amp;` is correct in both.
     *
     * @param  array<string, string|null>  $values
     * @return array<string, string>
     */
    public static function escape(array $values): array
    {
        $escaped = [];

        foreach ($values as $name => $value) {
            if ($value === null || $value === '') {
                continue;
            }

            $escaped[$name] = htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        }

        return $escaped;
    }
}
