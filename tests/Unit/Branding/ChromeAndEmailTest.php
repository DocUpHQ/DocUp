<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Unit\Branding;

use App\Branding\CascadeLevel;
use App\Branding\Chrome\ChromeContent;
use App\Branding\Chrome\HomepageBlock;
use App\Branding\Chrome\InlineMarkup;
use App\Branding\Email\EmailSlot;
use App\Branding\Email\EmailSlots;
use App\Branding\Email\EmailVariables;
use App\Branding\Email\SlotMarkdown;
use App\Branding\TokenRefused;
use App\Branding\TokenRejection;
use Tests\TestCase;

/**
 * §8.14.3's structured chrome and §8.14.13's email slots, on the paths that
 * are supposed to work.
 *
 * 🛑 **The positive halves.** `BrandingCorpusTest` drives the hostile input;
 * a sanitiser that returned an empty string for everything would pass every
 * one of those cases. What is here is that a legitimate announcement keeps its
 * emphasis, that a legitimate link keeps its target, and that an email slot
 * renders the three constructs it promises.
 *
 * A Laravel test case rather than a bare PHPUnit one, because the bounds come
 * from `config/branding.php` — which is §8.14.3's own arrangement: an
 * unbounded navigation list is a payload a tenant can grow until the addons
 * response is the slowest thing on the page.
 */
final class ChromeAndEmailTest extends TestCase
{
    // ------------------------------------------------------------ chrome

    /** 🛑 §8.14.3's five inline elements survive, with their text. */
    public function test_the_announcement_keeps_the_five_elements_it_admits(): void
    {
        $announcement = InlineMarkup::sanitise(
            'Version <code>2.0</code> is <strong>out</strong> and <em>stable</em>.<br>'
            .'<a href="/en/2.0/">Read the notes</a>.',
            'chrome.announcement.markup',
            400,
        );

        $this->assertSame([], $announcement->removed);
        $this->assertStringContainsString('<code>2.0</code>', $announcement->markup);
        $this->assertStringContainsString('<strong>out</strong>', $announcement->markup);
        $this->assertStringContainsString('<em>stable</em>', $announcement->markup);
        $this->assertStringContainsString('<br>', $announcement->markup);

        /*
         * 🛑 `rel="noopener nofollow"` is added by DocUp rather than carried
         * from the input. A tenant's announcement link is untrusted editorial
         * content on the operator's page, so it does not get to pass window
         * references or search-engine endorsement along with it.
         */
        $this->assertStringContainsString('<a href="/en/2.0/" rel="noopener nofollow">Read the notes</a>', $announcement->markup);
    }

    /**
     * 🛑 A refused element goes and its **text stays**.
     *
     * An announcement wrapped in a stray `<p>` by a rich-text editor should not
     * lose its sentence. `<script>` and `<style>` are the two cases where the
     * subtree goes with the element, because their text is the payload.
     */
    public function test_a_refused_wrapper_loses_its_tag_and_keeps_its_text(): void
    {
        $wrapped = InlineMarkup::sanitise(
            '<p>Maintenance on <strong>Friday</strong>.</p>',
            'chrome.announcement.markup',
            400,
        );

        $this->assertSame('Maintenance on <strong>Friday</strong>.', $wrapped->markup);
        $this->assertContains('<p>', $wrapped->removed);

        $scripted = InlineMarkup::sanitise(
            'Notice<script>alert(1)</script>',
            'chrome.announcement.markup',
            400,
        );

        $this->assertSame('Notice', $scripted->markup);
        $this->assertStringNotContainsString('alert', $scripted->markup);
    }

    /**
     * 🛑 Escaped markup round-trips as text, at any encoding depth.
     *
     * The text node is escaped on the way out from the parser's **decoded**
     * text, so `&lt;script&gt;` in the input is text in the tree and
     * `&lt;script&gt;` in the output — it cannot become a tag however many
     * times it was encoded.
     */
    public function test_escaped_markup_stays_text(): void
    {
        $announcement = InlineMarkup::sanitise(
            'Use &lt;script&gt; carefully',
            'chrome.announcement.markup',
            400,
        );

        $this->assertSame('Use &lt;script&gt; carefully', $announcement->markup);
    }

    /** A complete, legitimate chrome payload parses and round-trips. */
    public function test_a_legitimate_chrome_payload_round_trips_through_storage(): void
    {
        $authored = [
            'navigation' => [
                ['label' => 'Guide', 'href' => '/en/latest/'],
                ['label' => 'Source', 'href' => 'https://example.com/source'],
            ],
            'footer' => [
                ['label' => 'Docs', 'links' => [['label' => 'Start', 'href' => '/en/latest/']]],
            ],
            'announcement' => ['markup' => 'Now in <strong>beta</strong>.', 'tone' => 'warning'],
            'homepage' => [
                ['type' => 'hero', 'heading' => 'Read the docs', 'body' => 'All of them.'],
                ['type' => 'versions', 'heading' => 'Versions', 'limit' => 5],
            ],
        ];

        $content = ChromeContent::parse($authored, CascadeLevel::Project);

        $this->assertCount(2, $content->navigation);
        $this->assertSame('Guide', $content->navigation[0]['label']);
        $this->assertSame('https://example.com/source', $content->navigation[1]['href']);
        $this->assertSame('warning', $content->announcementTone);
        $this->assertCount(2, $content->homepage);
        $this->assertSame(5, $content->homepage[1]['limit']);

        /*
         * 🛑 Re-parsed from storage rather than trusted, which is §8.14.2's
         * reasoning applied to chrome: a stored announcement is one whose
         * parser has not run yet, and the allowlist may have narrowed.
         */
        $reparsed = ChromeContent::fromStorage($content->toStorage(), CascadeLevel::Project);

        $this->assertSame($content->toStorage(), $reparsed->toStorage());
    }

    /** 🛑 §8.14.3's blocks come from a registry, and every type is covered. */
    public function test_every_homepage_block_type_parses(): void
    {
        $blocks = [
            ['type' => 'hero', 'heading' => 'Hello'],
            ['type' => 'cards', 'cards' => [['label' => 'One', 'href' => '/one.html']]],
            ['type' => 'versions'],
            ['type' => 'search', 'placeholder' => 'Search'],
            ['type' => 'prose', 'body' => 'Some prose.'],
            ['type' => 'callout', 'label' => 'Go', 'href' => '/go.html'],
        ];

        $this->assertCount(
            count(HomepageBlock::cases()),
            $blocks,
            'a block type was added to the registry without a case here',
        );

        $content = ChromeContent::parse(['homepage' => $blocks], CascadeLevel::Project);

        $this->assertCount(count(HomepageBlock::cases()), $content->homepage);
    }

    /** An unknown field on a known block is refused, not dropped. */
    public function test_an_unknown_block_field_is_refused(): void
    {
        try {
            ChromeContent::parse([
                'homepage' => [['type' => 'prose', 'body' => 'Text.', 'colour' => 'red']],
            ], CascadeLevel::Project);
            $this->fail('an unknown block field was accepted');
        } catch (TokenRefused $refused) {
            $this->assertSame(TokenRejection::UnknownToken, $refused->rejection);
        }
    }

    /** A required field that is absent is refused. */
    public function test_a_missing_required_block_field_is_refused(): void
    {
        $this->expectException(TokenRefused::class);

        ChromeContent::parse(['homepage' => [['type' => 'callout', 'label' => 'Go']]], CascadeLevel::Project);
    }

    /** 🛑 §8.14.3's collections are bounded, from config. */
    public function test_the_navigation_list_is_bounded(): void
    {
        config()->set('branding.chrome.max_navigation_links', 3);

        try {
            ChromeContent::parse([
                'navigation' => array_fill(0, 4, ['label' => 'Guide', 'href' => '/en/latest/']),
            ], CascadeLevel::Project);
            $this->fail('an over-long navigation list was accepted');
        } catch (TokenRefused $refused) {
            $this->assertSame(TokenRejection::TooManyEntries, $refused->rejection);
        }
    }

    /**
     * 🛑 §8.14.7 names a **404 page** among the customisable surfaces.
     *
     * A heading and a sentence, both plain text through the same rules a
     * wordmark goes through — so markup in a 404 page is refused at the grammar
     * like markup anywhere else in chrome.
     */
    public function test_the_404_page_is_structured_content(): void
    {
        $content = ChromeContent::parse([
            'not_found' => ['heading' => 'That page has moved', 'body' => 'Try the guide index.'],
        ], CascadeLevel::Project);

        $this->assertIsArray($content->notFound);
        $this->assertSame('That page has moved', $content->notFound['heading']);
        $this->assertSame('Try the guide index.', $content->notFound['body']);

        $stored = $content->toStorage();
        $this->assertSame($stored, ChromeContent::fromStorage($stored, CascadeLevel::Project)->toStorage());

        /* And it reaches §8.14.14's payload, so an api_only consumer renders it. */
        $this->assertSame($content->notFound, $content->toPayloadFragment()['not_found']);
    }

    /** A 404 page with no heading is refused, and markup in one is too. */
    public function test_the_404_page_needs_a_heading_and_refuses_markup(): void
    {
        try {
            ChromeContent::parse(['not_found' => ['body' => 'Only a body.']], CascadeLevel::Project);
            $this->fail('a 404 page with no heading was accepted');
        } catch (TokenRefused $refused) {
            $this->assertSame(TokenRejection::WrongType, $refused->rejection);
        }

        try {
            ChromeContent::parse([
                'not_found' => ['heading' => '<script>alert(1)</script>'],
            ], CascadeLevel::Project);
            $this->fail('markup was accepted in a 404 heading');
        } catch (TokenRefused $refused) {
            $this->assertSame(TokenRejection::MarkupRefused, $refused->rejection);
        }
    }

    /** An unknown top-level chrome key is refused. */
    public function test_an_unknown_chrome_key_is_refused(): void
    {
        $this->expectException(TokenRefused::class);

        ChromeContent::parse(['sidebar' => []], CascadeLevel::Project);
    }

    // ------------------------------------------------------------- email

    /** 🛑 §8.14.13's three constructs, and nothing else. */
    public function test_a_slot_renders_emphasis_a_link_and_a_paragraph_break(): void
    {
        $html = SlotMarkdown::render(
            "Your build for **{project}** finished.\n\nSee [the log](https://docs.example/log) or reply to us.",
            'email.intro',
            1200,
            ['project'],
        );

        $this->assertStringContainsString('<strong>{project}</strong>', $html);
        $this->assertStringContainsString('<a href="https://docs.example/log">the log</a>', $html);
        $this->assertSame(2, substr_count($html, '<p>'));
    }

    /** `mailto:` is admitted in an email and refused in chrome. */
    public function test_a_mailto_link_is_admitted_in_an_email(): void
    {
        $html = SlotMarkdown::render(
            'Reply to [support](mailto:support@example.com).',
            'email.footer_note',
            400,
            [],
        );

        $this->assertStringContainsString('<a href="mailto:support@example.com">support</a>', $html);
    }

    /**
     * 🛑 §8.14.13's "pre-escaped variable map", substituted once over finished
     * HTML.
     *
     * A project named `Smith & Sons` arrives escaped exactly once — the whole
     * point of escaping when the map is built rather than when it is used.
     */
    public function test_a_variable_is_escaped_once(): void
    {
        $escaped = EmailVariables::escape(['project' => 'Smith & <Sons>']);

        $html = SlotMarkdown::substitute(
            SlotMarkdown::render('Your build for {project} finished.', 'email.intro', 1200, ['project']),
            $escaped,
        );

        $this->assertStringContainsString('Smith &amp; &lt;Sons&gt;', $html);
        $this->assertStringNotContainsString('&amp;amp;', $html);
        $this->assertStringNotContainsString('<Sons>', $html);
    }

    /** 🛑 No slot offers a recipient placeholder, at any slot. */
    public function test_no_slot_offers_a_recipient_placeholder(): void
    {
        foreach (EmailSlot::cases() as $slot) {
            foreach (EmailVariables::availableTo($slot) as $name) {
                $this->assertStringNotContainsString('reader', $name, $slot->value);
                $this->assertStringNotContainsString('email', $name, $slot->value);
                $this->assertStringNotContainsString('recipient', $name, $slot->value);
            }
        }
    }

    /** 🛑 `{action_url}` is the intro's alone. */
    public function test_the_action_url_is_offered_to_one_slot_only(): void
    {
        $offered = [];

        foreach (EmailSlot::cases() as $slot) {
            if (in_array('action_url', EmailVariables::availableTo($slot), true)) {
                $offered[] = $slot->value;
            }
        }

        $this->assertSame(['intro'], $offered);
    }

    /** A legitimate slot map round-trips, storing the Markdown and not the HTML. */
    public function test_a_slot_map_stores_its_markdown(): void
    {
        $slots = EmailSlots::parse([
            'greeting' => 'Hello from **{installation}**.',
            'intro' => 'Your build finished. [See it]({action_url}).',
        ]);

        $this->assertTrue($slots->has(EmailSlot::Greeting));
        $this->assertTrue($slots->has(EmailSlot::Intro));
        $this->assertFalse($slots->has(EmailSlot::Outro));

        /*
         * 🛑 The stored value is the author's Markdown, not DocUp's HTML — so a
         * release that tightens the renderer applies to every email on the
         * next send rather than only to themes saved afterwards.
         */
        $stored = $slots->toStorage();
        $this->assertStringContainsString('**{installation}**', $stored['greeting']);
        $this->assertStringNotContainsString('<strong>', $stored['greeting']);

        $rendered = $slots->render(EmailSlot::Greeting, EmailVariables::escape(['installation' => 'Acme']));
        $this->assertSame('<p>Hello from <strong>Acme</strong>.</p>', $rendered);
    }

    /**
     * 🛑 A placeholder may be a whole link target, and may not be part of one.
     *
     * `[See it]({action_url})` is the most natural thing an operator writes in
     * the intro slot, and the first version of the grammar refused it — which
     * would have left `{action_url}` usable only as visible text, printing a URL
     * at the reader instead of linking it. It is also the safest target in the
     * grammar, because the value is DocUp's own rather than the tenant's.
     *
     * The anchored pattern is the whole control: a placeholder that could be a
     * **fragment** of a target would let a tenant build a URL out of DocUp's
     * value.
     */
    public function test_a_placeholder_may_be_a_whole_link_target_and_not_part_of_one(): void
    {
        $html = SlotMarkdown::substitute(
            SlotMarkdown::render('Your build finished. [See it]({action_url}).', 'email.intro', 1200, ['action_url']),
            EmailVariables::escape(['action_url' => 'https://docs.example/builds/1?a=1&b=2']),
        );

        $this->assertStringContainsString(
            '<a href="https://docs.example/builds/1?a=1&amp;b=2">See it</a>',
            $html,
        );

        foreach ([
            'javascript:{action_url}',
            '{action_url}@evil.example',
            '{action_url}.evil.example',
            'https://evil.example/{action_url}',
        ] as $target) {
            try {
                SlotMarkdown::render('[Go]('.$target.')', 'email.intro', 1200, ['action_url']);
                $this->fail('accepted '.$target);
            } catch (TokenRefused $refused) {
                $this->assertSame(TokenRejection::UnsafeLinkTarget, $refused->rejection, $target);
            }
        }
    }

    /** An empty slot is absent rather than an empty override. */
    public function test_an_empty_slot_is_dropped(): void
    {
        $slots = EmailSlots::parse(['greeting' => '', 'outro' => null]);

        $this->assertSame([], $slots->toStorage());
    }
}
