<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding\Email;

/**
 * 🛑 §8.14.13's closed set of email slots.
 *
 * > "Email customisation MUST be structured slot overrides plus Markdown with
 * > HTML disabled, substituted over a pre-escaped variable map. 🛑 No template
 * > engine MUST be exposed to tenants at any scope — Blade compiles to PHP, and
 * > Twig's own documentation declines to be a security boundary alone."
 *
 * A **slot** rather than a template is the whole of that requirement. A tenant
 * supplies the paragraph above the button and the sign-off below it; DocUp
 * supplies the layout, the button, the footer and the unsubscribe line. There
 * is no expression language, no loop, no include and no file path — so there is
 * nothing for §19/37's rejected template engines to be a boundary for.
 *
 * Five slots, and the set is closed for the reason {@see HomepageBlock}'s is:
 * the sixth is a change to this enum with a test behind it.
 */
enum EmailSlot: string
{
    /** Replaces DocUp's own opening line. */
    case Greeting = 'greeting';

    /**
     * A paragraph before the primary action.
     *
     * 🛑 The one slot that is genuinely useful and genuinely risky: it is where
     * an operator explains their own policy, and it is where a phishing
     * paragraph would go. It is Markdown with HTML disabled and no link
     * rewriting, so a link in it renders as a link to wherever it points — and
     * that is why {@see SlotMarkdown} refuses any scheme but `http`, `https`
     * and `mailto`.
     */
    case Intro = 'intro';

    /** A paragraph after the primary action. */
    case Outro = 'outro';

    /** Replaces DocUp's sign-off. */
    case Signoff = 'signoff';

    /**
     * A line in the footer, beside DocUp's own.
     *
     * 🛑 **Beside**, not instead of. §15's operator-contact and the
     * unsubscribe affordance are DocUp's and a tenant cannot remove them: an
     * email with no way back to the operator is an email a recipient reports as
     * spam.
     */
    case FooterNote = 'footer_note';

    /** The character cap for this slot. */
    public function maxCharacters(): int
    {
        return match ($this) {
            self::Greeting, self::Signoff => 200,
            self::Intro, self::Outro => 1200,
            self::FooterNote => 400,
        };
    }
}
