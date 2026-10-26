<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Unit\Domains;

use App\Domains\DomainRefused;
use App\Domains\DomainRejection;
use App\Domains\Hostname;
use PHPUnit\Framework\TestCase;

/**
 * 🛑 §8.10.7's normalisation and confusable rejection.
 *
 * > "Hostnames MUST be normalised to lowercase punycode A-labels, and
 * > mixed-script or Unicode-confusable hostnames MUST be rejected."
 *
 * Normalisation is a correctness requirement before it is a tidiness one:
 * §8.10.5's uniqueness index is over the stored string, so two spellings of
 * one hostname that normalise differently are two proven claims on one name.
 */
final class HostnameTest extends TestCase
{
    /** Case, trailing dot and Unicode all collapse to one spelling. */
    public function test_one_hostname_has_one_spelling(): void
    {
        $this->assertSame('example.com', Hostname::normalise('Example.COM'));
        $this->assertSame('example.com', Hostname::normalise('example.com.'));
        $this->assertSame('example.com', Hostname::normalise('  EXAMPLE.com  '));
        $this->assertSame('xn--mnchen-3ya.de', Hostname::normalise('München.de'));
    }

    /**
     * 🛑 A Cyrillic `а` in a Latin label is refused.
     *
     * `аpple.com` is a different hostname that looks identical in an address
     * bar. An installation that issued a certificate for it would be handing
     * out a phishing origin with its own sign-in branding.
     */
    public function test_a_mixed_script_label_is_refused(): void
    {
        $this->assertRefused("\u{0430}pple.com", DomainRejection::HostConfusable);
    }

    /**
     * 🛑 And so is the same attack spelled in punycode.
     *
     * `xn--pple-43d.com` is already ASCII, so the script check never sees it
     * unless something decodes it first. A normaliser that only inspected
     * non-ASCII input would accept the attack in its encoded form, which is
     * the form an attacker would use once they discovered the check.
     */
    public function test_a_pre_encoded_confusable_is_refused(): void
    {
        $this->assertRefused('xn--pple-43d.com', DomainRejection::HostConfusable);
    }

    /**
     * Japanese is not mixed script, although it uses three.
     *
     * Han with kana is one writing system, and refusing it would exclude a
     * language rather than an attack.
     */
    public function test_japanese_is_accepted(): void
    {
        // Katakana alone.
        $this->assertSame('xn--tckyb3bweh.jp', Hostname::normalise("\u{30D7}\u{30ED}\u{30C8}\u{30B3}\u{30EB}.jp"));

        // Han alone.
        $this->assertSame('xn--wgv71a119e.jp', Hostname::normalise("\u{65E5}\u{672C}\u{8A9E}.jp"));

        // 🛑 And the mixture, which is the case the exemption exists for.
        $this->assertSame('xn--lckxb533yncb.jp', Hostname::normalise("\u{65E5}\u{672C}\u{30AB}\u{30BF}.jp"));
    }

    /** The shape rules: labels, lengths, characters. */
    public function test_a_malformed_hostname_is_refused(): void
    {
        foreach (['', '.', 'a..b', 'a_b.example.com', '-lead.example.com', 'trail-.example.com'] as $host) {
            $this->assertRefused($host, DomainRejection::HostMalformed);
        }
    }

    /** 🛑 Over 253 bytes is not a DNS name, and the column is 253. */
    public function test_an_overlong_hostname_is_refused(): void
    {
        $label = str_repeat('a', 63);
        $this->assertRefused(implode('.', [$label, $label, $label, $label, 'com']), DomainRejection::HostMalformed);
    }

    /**
     * §8.10.4's challenge name is expressible.
     *
     * A normaliser that refused a leading underscore could not describe the
     * very record the proof requires, which would be a rule that made the
     * feature undocumentable.
     */
    public function test_the_challenge_label_normalises(): void
    {
        $this->assertSame(
            '_docup-challenge.example.com',
            Hostname::normalise('_DOCUP-Challenge.Example.com'),
        );
    }

    /**
     * 🛑 The parent apexes a host could be claimed under, longest first, and
     * **not** including the host itself.
     *
     * The exclusion matters: a parent claim binds hosts *under* an apex, and
     * including the host would let a per-host claim be read as a parent
     * claim over itself.
     */
    public function test_parent_apexes_exclude_the_host_itself(): void
    {
        $this->assertSame(
            ['api.example.com', 'example.com', 'com'],
            Hostname::parentApexes('docs.api.example.com'),
        );

        $this->assertSame(['com'], Hostname::parentApexes('example.com'));
        $this->assertSame([], Hostname::parentApexes('localhost'));
    }

    /** The suffix test both the HSTS rule and the parent claim rely on. */
    public function test_is_under_covers_the_host_and_its_descendants(): void
    {
        $this->assertTrue(Hostname::isUnder('example.com', 'example.com'));
        $this->assertTrue(Hostname::isUnder('docs.example.com', 'example.com'));

        // 🛑 Not a prefix match: `notexample.com` is a different registrant.
        $this->assertFalse(Hostname::isUnder('notexample.com', 'example.com'));
        $this->assertFalse(Hostname::isUnder('example.com', 'docs.example.com'));
    }

    private function assertRefused(string $host, DomainRejection $expected): void
    {
        try {
            Hostname::normalise($host);
        } catch (DomainRefused $refused) {
            $this->assertSame($expected, $refused->rejection, 'wrong refusal for "'.$host.'"');

            return;
        }

        $this->fail('"'.$host.'" was accepted and should have been refused');
    }
}
