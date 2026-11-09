<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding\Chrome;

use App\Branding\CascadeLevel;
use App\Branding\TokenRefused;
use App\Branding\TokenRejection;
use App\Branding\Values\ShortTextValue;

/**
 * 🛑 §8.14.3: "Chrome content MUST be structured data — navigation links,
 * footer links, an announcement with a tiny inline-tag allowlist, and homepage
 * blocks from a registry — **never free HTML**."
 *
 * ## 🛑 §8.14.8's raw-HTML surface lives here, and the scope check is the point
 *
 * > "Tenant JavaScript and raw HTML MUST NOT enter portal or documentation
 * > chrome at **any scope below installation**. Installation-scope raw head
 * > HTML MUST sit behind an unsafe flag documented as code execution. The
 * > argument 'they already run JavaScript in their build' is exactly why they
 * > need nothing extra: build JavaScript is contained in its own origin; a
 * > chrome slot puts it in the same DOM as the version switcher and
 * > authentication state."
 *
 * `head_html` is **not** a branding token, and keeping it out of the registry
 * is deliberate: every one of the forty-five tokens is safe by construction,
 * and admitting one whose grammar is "anything" would make the registry's
 * guarantee a guarantee with an exception. It is a field here, refused outright
 * below installation scope, and refused at installation scope unless
 * `DOCUP_ALLOW_RAW_HTML_BRANDING` is set — which is already in §20.4's unsafe
 * registry and is documented as code execution.
 *
 * 🛑 **Tenant JavaScript at any scope below installation is permanently out of
 * scope** (§17, §8.14.8). There is no field for it here and no flag that
 * enables one. A future phase adding one would be reversing a decision §19/36
 * records the reasoning for.
 *
 * ## What "structured" buys
 *
 * A navigation link is `{label, href}`. The label goes through
 * {@see ShortTextValue}'s rules, so it cannot contain an angle bracket; the
 * href goes through {@see SafeHref}, so it cannot contain a scheme that
 * executes. There is no field in which markup is meaningful, which means there
 * is no renderer that has to remember to escape — and no renderer that can
 * forget.
 */
final readonly class ChromeContent
{
    /**
     * @param  list<array{label: string, href: string}>  $navigation
     * @param  list<array{label: string, links: list<array{label: string, href: string}>}>  $footer
     * @param  array<string, mixed>  $homepage  blocks, each `{type, …}`
     * @param  list<string>  $removed  what sanitisation did not admit
     */
    private function __construct(
        public array $navigation,
        public array $footer,
        public ?Announcement $announcement,
        public string $announcementTone,
        public array $homepage,
        public ?string $headHtml,
        public array $removed,
    ) {}

    public static function empty(): self
    {
        return new self([], [], null, 'notice', [], null, []);
    }

    /**
     * Parse one authored chrome payload for one cascade level.
     *
     * @param  array<array-key, mixed>  $authored
     *
     * @throws TokenRefused
     */
    public static function parse(array $authored, CascadeLevel $level): self
    {
        foreach (array_keys($authored) as $key) {
            if (! in_array($key, ['navigation', 'footer', 'announcement', 'homepage', 'head_html'], true)) {
                throw TokenRefused::of(
                    TokenRejection::UnknownToken,
                    'chrome.'.(string) $key,
                    'chrome content is a closed set of keys',
                );
            }
        }

        $removed = [];

        $navigation = self::links(
            $authored['navigation'] ?? [],
            'chrome.navigation',
            self::limit('max_navigation_links', 12),
        );

        $footer = self::footerGroups($authored['footer'] ?? []);

        [$announcement, $tone] = self::announcement($authored['announcement'] ?? null, $removed);

        $homepage = self::homepage($authored['homepage'] ?? []);

        $headHtml = self::headHtml($authored['head_html'] ?? null, $level);

        return new self($navigation, $footer, $announcement, $tone, $homepage, $headHtml, array_values(array_unique($removed)));
    }

    /** Rebuild from a stored row. @param array<array-key, mixed> $stored */
    public static function fromStorage(array $stored, CascadeLevel $level): self
    {
        /*
         * 🛑 Re-parsed, not trusted. §8.14.2's re-serialisation requirement is
         * written about token values and the reasoning applies identically
         * here: a stored announcement is a stored announcement whose parser has
         * not run yet, and the allowlist may have narrowed since it was
         * written.
         */
        return self::parse($stored, $level);
    }

    /** @return array<string, mixed> */
    public function toStorage(): array
    {
        $stored = [];

        if ($this->navigation !== []) {
            $stored['navigation'] = $this->navigation;
        }

        if ($this->footer !== []) {
            $stored['footer'] = $this->footer;
        }

        if ($this->announcement instanceof Announcement) {
            $stored['announcement'] = ['markup' => $this->announcement->markup, 'tone' => $this->announcementTone];
        }

        if ($this->homepage !== []) {
            $stored['homepage'] = $this->homepage;
        }

        if ($this->headHtml !== null) {
            $stored['head_html'] = $this->headHtml;
        }

        return $stored;
    }

    public function isEmpty(): bool
    {
        return $this->toStorage() === [];
    }

    /**
     * The `chrome` half of §8.14.14's `api_only` payload.
     *
     * 🛑 `head_html` is **absent**, and that is not an oversight. §8.14.8
     * admits installation-scope raw head HTML behind an unsafe flag for
     * DocUp's *own* pages; putting it in a payload would hand it to every
     * `api_only` consumer to inject, and most of them would use `innerHTML`.
     * A consumer who wants a script in their own head writes it themselves,
     * in their own application, where it is their decision.
     *
     * @return array{navigation: list<array{label: string, href: string}>, footer: list<array{label: string, links: list<array{label: string, href: string}>}>, announcement: array{markup: string, tone: string}|null, homepage: list<array<string, mixed>>}
     */
    public function toPayloadFragment(): array
    {
        return [
            'navigation' => $this->navigation,
            'footer' => $this->footer,
            'announcement' => $this->announcement === null ? null : [
                'markup' => $this->announcement->markup,
                'tone' => $this->announcementTone,
            ],
            'homepage' => $this->homepage,
        ];
    }

    /**
     * A bounded list of `{label, href}`.
     *
     * @return list<array{label: string, href: string}>
     *
     * @throws TokenRefused
     */
    private static function links(mixed $authored, string $path, int $limit): array
    {
        if ($authored === [] || $authored === null) {
            return [];
        }

        if (! is_array($authored)) {
            throw TokenRefused::of(TokenRejection::WrongType, $path, 'a list of {label, href}');
        }

        if (count($authored) > $limit) {
            throw TokenRefused::of(
                TokenRejection::TooManyEntries,
                $path,
                sprintf('%d links; the limit is %d', count($authored), $limit),
            );
        }

        $links = [];

        foreach (array_values($authored) as $index => $entry) {
            $at = $path.'['.$index.']';

            if (! is_array($entry)) {
                throw TokenRefused::of(TokenRejection::WrongType, $at, 'a link is {label, href}');
            }

            foreach (array_keys($entry) as $key) {
                if ($key !== 'label' && $key !== 'href') {
                    throw TokenRefused::of(TokenRejection::UnknownToken, $at, 'a link has only label and href');
                }
            }

            $links[] = [
                'label' => ShortTextValue::parse(is_string($entry['label'] ?? null) ? $entry['label'] : '', $at.'.label', 60)->text,
                'href' => SafeHref::parse(is_string($entry['href'] ?? null) ? $entry['href'] : '', $at.'.href'),
            ];
        }

        return $links;
    }

    /**
     * @return list<array{label: string, links: list<array{label: string, href: string}>}>
     *
     * @throws TokenRefused
     */
    private static function footerGroups(mixed $authored): array
    {
        if ($authored === [] || $authored === null) {
            return [];
        }

        if (! is_array($authored)) {
            throw TokenRefused::of(TokenRejection::WrongType, 'chrome.footer', 'a list of link groups');
        }

        $maxGroups = self::limit('max_footer_groups', 4);

        if (count($authored) > $maxGroups) {
            throw TokenRefused::of(
                TokenRejection::TooManyEntries,
                'chrome.footer',
                sprintf('%d groups; the limit is %d', count($authored), $maxGroups),
            );
        }

        $groups = [];

        foreach (array_values($authored) as $index => $group) {
            $at = 'chrome.footer['.$index.']';

            if (! is_array($group)) {
                throw TokenRefused::of(TokenRejection::WrongType, $at, 'a footer group is {label, links}');
            }

            $groups[] = [
                'label' => ShortTextValue::parse(is_string($group['label'] ?? null) ? $group['label'] : '', $at.'.label', 60)->text,
                'links' => self::links($group['links'] ?? [], $at.'.links', self::limit('max_footer_links_per_group', 8)),
            ];
        }

        return $groups;
    }

    /**
     * @param  list<string>  $removed
     * @return array{0: Announcement|null, 1: string}
     *
     * @throws TokenRefused
     */
    private static function announcement(mixed $authored, array &$removed): array
    {
        if ($authored === null || $authored === [] || $authored === '') {
            return [null, 'notice'];
        }

        if (! is_array($authored)) {
            throw TokenRefused::of(TokenRejection::WrongType, 'chrome.announcement', '{markup, tone}');
        }

        $markup = $authored['markup'] ?? '';

        if (! is_string($markup) || trim($markup) === '') {
            return [null, 'notice'];
        }

        $tone = is_string($authored['tone'] ?? null) ? strtolower($authored['tone']) : 'notice';

        if (! in_array($tone, ['notice', 'warning', 'danger'], true)) {
            throw TokenRefused::of(
                TokenRejection::NotAnOption,
                'chrome.announcement.tone',
                'one of notice, warning, danger',
            );
        }

        $sanitised = InlineMarkup::sanitise(
            $markup,
            'chrome.announcement.markup',
            self::limit('max_announcement_characters', 400),
        );

        foreach ($sanitised->removed as $entry) {
            $removed[] = 'announcement: '.$entry;
        }

        return [$sanitised, $tone];
    }

    /**
     * 🛑 §8.14.3's homepage blocks, each from {@see HomepageBlock}.
     *
     * @return list<array<string, mixed>>
     *
     * @throws TokenRefused
     */
    private static function homepage(mixed $authored): array
    {
        if ($authored === [] || $authored === null) {
            return [];
        }

        if (! is_array($authored)) {
            throw TokenRefused::of(TokenRejection::WrongType, 'chrome.homepage', 'a list of blocks');
        }

        $limit = self::limit('max_homepage_blocks', 8);

        if (count($authored) > $limit) {
            throw TokenRefused::of(
                TokenRejection::TooManyEntries,
                'chrome.homepage',
                sprintf('%d blocks; the limit is %d', count($authored), $limit),
            );
        }

        $blocks = [];

        foreach (array_values($authored) as $index => $block) {
            $at = 'chrome.homepage['.$index.']';

            if (! is_array($block)) {
                throw TokenRefused::of(TokenRejection::WrongType, $at, 'a block is an object with a type');
            }

            $type = HomepageBlock::tryFrom(is_string($block['type'] ?? null) ? $block['type'] : '');

            if ($type === null) {
                throw TokenRefused::of(
                    TokenRejection::UnknownBlockType,
                    $at.'.type',
                    'one of '.implode(', ', array_map(
                        static fn (HomepageBlock $candidate): string => $candidate->value,
                        HomepageBlock::cases(),
                    )),
                );
            }

            $blocks[] = ['type' => $type->value, ...self::blockFields($type, $block, $at)];
        }

        return $blocks;
    }

    /**
     * @param  array<array-key, mixed>  $block
     * @return array<string, mixed>
     *
     * @throws TokenRefused
     */
    private static function blockFields(HomepageBlock $type, array $block, string $at): array
    {
        $specification = $type->fields();

        foreach (array_keys($block) as $key) {
            if ($key !== 'type' && ! array_key_exists((string) $key, $specification)) {
                throw TokenRefused::of(
                    TokenRejection::UnknownToken,
                    $at.'.'.(string) $key,
                    sprintf('a %s block has only %s', $type->value, implode(', ', array_keys($specification))),
                );
            }
        }

        $fields = [];

        foreach ($specification as $name => $rule) {
            $value = $block[$name] ?? null;

            if ($value === null || $value === '') {
                if (($rule['required'] ?? false) === true) {
                    throw TokenRefused::of(TokenRejection::WrongType, $at.'.'.$name, 'required');
                }

                continue;
            }

            $fields[$name] = match ($rule['type']) {
                'text' => ShortTextValue::parse(
                    is_string($value) ? $value : '',
                    $at.'.'.$name,
                    $rule['max'] ?? 120,
                )->text,
                'href' => SafeHref::parse(is_string($value) ? $value : '', $at.'.'.$name),
                'count' => self::count($value, $at.'.'.$name, $rule['max'] ?? 20),
                'card_list' => self::links($value, $at.'.'.$name, $rule['max'] ?? 9),
                default => throw TokenRefused::of(TokenRejection::WrongType, $at.'.'.$name, 'unknown field type'),
            };
        }

        return $fields;
    }

    /** @throws TokenRefused */
    private static function count(mixed $value, string $path, int $max): int
    {
        if (! is_int($value) && (! is_string($value) || preg_match('/^\d+$/', $value) !== 1)) {
            throw TokenRefused::of(TokenRejection::WrongType, $path, 'a non-negative integer');
        }

        $count = (int) $value;

        if ($count < 1 || $count > $max) {
            throw TokenRefused::of(TokenRejection::NumericOutOfRange, $path, sprintf('1 to %d', $max));
        }

        return $count;
    }

    /**
     * 🛑 §8.14.8's installation-only raw head HTML.
     *
     * Two gates, and both are refusals rather than silent drops — because an
     * operator who put a tracking snippet in a project theme and saw it
     * disappear would conclude DocUp was broken, and the honest answer is that
     * DocUp will not do that.
     *
     * @throws TokenRefused
     */
    private static function headHtml(mixed $authored, CascadeLevel $level): ?string
    {
        if ($authored === null || $authored === '') {
            return null;
        }

        if ($level !== CascadeLevel::Installation) {
            throw TokenRefused::of(
                TokenRejection::TenantScriptRefused,
                'chrome.head_html',
                'raw HTML is refused at every scope below installation (§8.14.8); '
                .'build JavaScript is contained in its own origin and a chrome slot is not',
            );
        }

        if (config('docup.unsafe.allow_raw_html_branding') !== true) {
            throw TokenRefused::of(
                TokenRejection::TenantScriptRefused,
                'chrome.head_html',
                'DOCUP_ALLOW_RAW_HTML_BRANDING is not set; §20.4 documents this flag as code execution',
            );
        }

        if (! is_string($authored)) {
            throw TokenRefused::of(TokenRejection::WrongType, 'chrome.head_html', 'a string');
        }

        /*
         * 🛑 Stored verbatim, and that is what the flag is for. There is no
         * sanitisation here and pretending otherwise would be worse than not
         * having it: an operator who believed DocUp was filtering their head
         * HTML would write something dangerous expecting to be stopped.
         */
        return $authored;
    }

    private static function limit(string $key, int $fallback): int
    {
        $configured = config('branding.chrome.'.$key);

        return is_numeric($configured) ? (int) $configured : $fallback;
    }
}
