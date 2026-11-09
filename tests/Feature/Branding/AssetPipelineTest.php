<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Branding;

use App\Auth\OrganisationContext;
use App\Branding\Assets\AcceptedAsset;
use App\Branding\Assets\AssetIntake;
use App\Branding\Assets\AssetKind;
use App\Branding\CascadeLevel;
use App\Branding\ThemeAssets;
use App\Branding\TokenRefused;
use App\Branding\TokenRejection;
use App\Http\Controllers\Branding\BrandingAssetController;
use App\Models\Organisation;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\Storage;
use Tests\TestCase;

/**
 * 🛑 §8.14.11's pipeline, end to end.
 *
 * > "Uploaded rasters MUST be content-sniffed and re-encoded server-side to
 * > strip metadata and defeat polyglots, pixel- and byte-capped,
 * > content-addressed with the uploaded filename discarded. SVG MUST be
 * > DOM-sanitised against an element and attribute allowlist, re-serialised,
 * > and rendered **only via `<img src>`** from a dedicated asset host carrying
 * > `default-src 'none'; sandbox`, `nosniff` and no cookies."
 *
 * The SVG half's exit criterion is in {@see ExitCriteriaTest}. What is here is
 * every other clause of that sentence, one test each — because the sentence has
 * seven clauses and a test per feature would have covered three of them.
 */
final class AssetPipelineTest extends TestCase
{
    use DatabaseTransactions;

    private OrganisationContext $context;

    private Organisation $organisation;

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('theme-assets');

        $this->context = app(OrganisationContext::class);
        $this->context->spanAllOrganisations();

        $this->organisation = Organisation::query()->create([
            'name' => 'Upload Co',
            'slug' => 'up-'.bin2hex(random_bytes(4)),
        ]);

        $this->context->for($this->organisation->id);
    }

    protected function tearDown(): void
    {
        $this->context->forget();

        parent::tearDown();
    }

    /**
     * 🛑 "re-encoded server-side to strip metadata and defeat polyglots".
     *
     * The fixture is a real polyglot: a valid GIF whose bytes continue into an
     * HTML document with a script in it. A sniffer calls it a GIF, a
     * content-sniffing browser might call it a document, and a metadata
     * stripper would leave the trailing bytes exactly where they are.
     *
     * After re-encoding the output is a PNG DocUp wrote from pixels, and the
     * attacker's bytes are not in it — which is a stronger statement than any
     * header makes.
     */
    public function test_a_polyglot_loses_everything_that_was_not_a_pixel(): void
    {
        $gif = self::gif(4, 4);
        $polyglot = $gif."\n<html><script>alert(document.domain)</script></html>";

        $accepted = $this->accept($polyglot, AssetKind::Logo);

        $this->assertSame('image/png', $accepted->asset->media_type);
        $this->assertSame('image/gif', $accepted->asset->source_media_type);

        $stored = (string) ThemeAssets::store()->get($accepted->asset->content_hash, 'png');

        $this->assertStringStartsWith("\x89PNG", $stored);
        $this->assertStringNotContainsString('script', $stored);
        $this->assertStringNotContainsString('alert', $stored);
        $this->assertStringNotContainsString('<html', $stored);
    }

    /**
     * 🛑 "content-addressed with the uploaded filename discarded".
     *
     * There is no parameter on {@see AssetIntake::accept()} that takes a
     * filename, which is the strongest form of "discarded" available — so this
     * asserts the other half: the address is over DocUp's **output**, so two
     * uploads that re-encode to the same pixels are one row and one URL.
     */
    public function test_the_address_is_over_the_output_so_two_uploads_deduplicate(): void
    {
        $gif = self::gif(4, 4);

        $first = $this->accept($gif, AssetKind::Logo, 'First upload');

        /*
         * The same image with trailing junk. Different input bytes, identical
         * pixels — so an address over the *input* would have produced two rows
         * and two URLs for one logo.
         */
        $second = $this->accept($gif."\x00trailing", AssetKind::Logo, 'Second upload');

        $this->assertSame($first->asset->content_hash, $second->asset->content_hash);
        $this->assertTrue($second->deduplicated);
        $this->assertSame((string) $first->asset->id, (string) $second->asset->id);

        /* And the label is the first one's: a re-upload is not a rename. */
        $this->assertSame('First upload', $second->asset->label);
    }

    /** 🛑 The byte cap, checked before anything parses the bytes. */
    public function test_an_oversized_upload_is_refused_by_the_byte_cap(): void
    {
        config()->set('branding.assets.max_bytes.logo', 512);

        try {
            $this->accept(self::gif(64, 64).str_repeat("\x00", 4096), AssetKind::Logo);
            $this->fail('an oversized upload was accepted');
        } catch (TokenRefused $refused) {
            $this->assertSame(TokenRejection::AssetTooLarge, $refused->rejection);
        }
    }

    /**
     * 🛑 The pixel cap, which is a different defence from the byte cap.
     *
     * A decompression bomb is small on disk: this fixture is a valid GIF header
     * declaring 20,000 × 20,000 pixels in a few dozen bytes. The byte cap
     * passes it; the pixel cap refuses it from the header, before GD is asked
     * to allocate 1.6 GB.
     */
    public function test_a_decompression_bomb_is_refused_from_its_header(): void
    {
        config()->set('branding.assets.max_pixels', 4_000_000);

        $bomb = self::gif(20_000, 20_000);

        $this->assertLessThan(1024, strlen($bomb), 'the fixture must be small on disk to be the right test');

        try {
            $this->accept($bomb, AssetKind::Logo);
            $this->fail('a 400-megapixel image was accepted');
        } catch (TokenRefused $refused) {
            $this->assertSame(TokenRejection::AssetTooManyPixels, $refused->rejection);
        }
    }

    /** 🛑 "content-sniffed": the bytes decide, never a claimed type. */
    public function test_bytes_that_are_not_an_image_are_refused_however_they_are_labelled(): void
    {
        try {
            $this->accept('%PDF-1.7 not an image at all', AssetKind::SocialCard);
            $this->fail('a PDF was accepted as a social card');
        } catch (TokenRefused $refused) {
            $this->assertSame(TokenRejection::AssetTypeNotSniffed, $refused->rejection);
        }
    }

    /** A truncated image is a different fault from an unrecognised one. */
    public function test_a_truncated_image_is_reported_as_undecodable(): void
    {
        $gif = self::gif(8, 8);

        try {
            $this->accept(substr($gif, 0, 20), AssetKind::Logo);
            $this->fail('a truncated image was accepted');
        } catch (TokenRefused $refused) {
            $this->assertContains($refused->rejection, [
                TokenRejection::AssetNotDecodable,
                TokenRejection::AssetTypeNotSniffed,
            ]);
        }
    }

    /** 🛑 Downscaled to the kind's ceiling, and never upscaled. */
    public function test_a_large_logo_is_downscaled_and_a_small_one_is_left_alone(): void
    {
        config()->set('branding.assets.max_edge.logo', 64);

        $large = $this->accept(self::gif(256, 128), AssetKind::Logo, 'Large');

        $this->assertSame(64, $large->asset->width);
        $this->assertSame(32, $large->asset->height);

        $small = $this->accept(self::gif(8, 4), AssetKind::Logo, 'Small');

        $this->assertSame(8, $small->asset->width, 'an 8-pixel logo must stay 8 pixels');
        $this->assertSame(4, $small->asset->height);
    }

    /** 🛑 An SVG may be a logo and may not be a favicon or a social card. */
    public function test_an_svg_is_refused_for_every_kind_but_a_logo(): void
    {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 8 8"><rect width="8" height="8"/></svg>';

        foreach ([AssetKind::Favicon, AssetKind::SocialCard] as $kind) {
            try {
                $this->accept($svg, $kind);
                $this->fail('an SVG was accepted as a '.$kind->value);
            } catch (TokenRefused $refused) {
                $this->assertSame(TokenRejection::WrongAssetKind, $refused->rejection, $kind->value);
            }
        }
    }

    /** 🛑 §8.14.2: a font upload is WOFF2 or nothing. */
    public function test_a_font_must_be_woff2(): void
    {
        try {
            $this->accept(self::gif(4, 4), AssetKind::Font);
            $this->fail('a GIF was accepted as a font');
        } catch (TokenRefused $refused) {
            $this->assertSame(TokenRejection::AssetTypeNotSniffed, $refused->rejection);
        }

        $accepted = $this->accept('wOF2'.str_repeat("\x00", 64), AssetKind::Font, 'Brand Sans');

        $this->assertSame('font/woff2', $accepted->asset->media_type);
        $this->assertNull($accepted->asset->width);
    }

    // ---------------------------------------------------------- the asset host

    /**
     * 🛑 Every clause of §8.14.11's header sentence, on a real response.
     */
    public function test_the_asset_host_carries_the_headers_the_requirement_names(): void
    {
        $accepted = $this->accept(self::gif(8, 8), AssetKind::Logo);

        $response = $this->get(ThemeAssets::urlFor($accepted->asset));

        $response->assertOk();
        $response->assertHeader('Content-Security-Policy', BrandingAssetController::POLICY);
        $response->assertHeader('X-Content-Type-Options', 'nosniff');
        $response->assertHeader('Cross-Origin-Resource-Policy', 'cross-origin');
        $response->assertHeader('Referrer-Policy', 'no-referrer');
        $response->assertHeader('Content-Type', 'image/png');

        /*
         * 🛑 §8.14.4's immutable year, on both axes.
         *
         * Asserted as **directives** rather than as a string, because Symfony
         * normalises a managed `Cache-Control` into alphabetical order — it
         * emits `immutable, max-age=31536000, public`, which is the same
         * header and not the same text. The CDN axis is not a managed header,
         * so it survives as written, and asserting that one as a string is
         * what keeps §8.14.4's own spelling in the test.
         */
        $this->assertTrue($response->headers->hasCacheControlDirective('public'));
        $this->assertTrue($response->headers->hasCacheControlDirective('immutable'));
        $this->assertSame('31536000', $response->headers->getCacheControlDirective('max-age'));
        $this->assertSame('public, max-age=31536000, immutable', $response->headers->get('CDN-Cache-Control'));

        /* 🛑 "and no cookies" — asserted, not assumed. */
        $this->assertSame([], $response->headers->getCookies());
        $this->assertNull($response->headers->get('Set-Cookie'));
    }

    /** A 404 still carries the policy, because a 404 still has a body. */
    public function test_a_missing_asset_is_refused_with_the_same_policy(): void
    {
        $response = $this->get(ThemeAssets::assetOrigin().'/'.str_repeat('a', 64).'.png');

        $response->assertNotFound();
        $response->assertHeader('Content-Security-Policy', BrandingAssetController::POLICY);
        $response->assertHeader('X-Content-Type-Options', 'nosniff');
        $this->assertTrue($response->headers->hasCacheControlDirective('private'));
        $this->assertTrue($response->headers->hasCacheControlDirective('no-store'));
    }

    /**
     * 🛑 A traversal never reaches the store, because the route pattern refuses
     * it first — and the store would refuse it too.
     */
    public function test_a_traversal_in_the_hash_does_not_route(): void
    {
        $this->get(ThemeAssets::assetOrigin().'/../../etc/passwd.png')->assertNotFound();
        $this->get(ThemeAssets::assetOrigin().'/'.str_repeat('a', 63).'.png')->assertNotFound();
        $this->get(ThemeAssets::assetOrigin().'/ZZZZ'.str_repeat('a', 60).'.png')->assertNotFound();
    }

    /** An extension the host does not serve is a 404, not a guess. */
    public function test_an_unserved_extension_is_refused(): void
    {
        $accepted = $this->accept('wOF2'.str_repeat("\x00", 64), AssetKind::Font, 'Brand Sans');

        /*
         * 🛑 A font is NOT served from the asset host. §8.14.10 grants
         * `img-src` to the asset host and keeps `font-src 'self'`, so the
         * WOFF2 is reachable on the application's own origins and not here.
         */
        $this->get(ThemeAssets::assetOrigin().'/'.$accepted->asset->content_hash.'.woff2')
            ->assertNotFound();
    }

    /** And the font IS reachable on the application's own origin. */
    public function test_a_font_is_served_from_the_application_origin(): void
    {
        $accepted = $this->accept('wOF2'.str_repeat("\x00", 64), AssetKind::Font, 'Brand Sans');

        $response = $this->get('/_/theme/font/'.$accepted->asset->content_hash.'.woff2');

        $response->assertOk();
        $response->assertHeader('Content-Type', 'font/woff2');
        $this->assertTrue($response->headers->hasCacheControlDirective('immutable'));
        $this->assertSame('31536000', $response->headers->getCacheControlDirective('max-age'));
    }

    // ------------------------------------------------------------- the fixtures

    private function accept(string $bytes, AssetKind $kind, string $label = 'A mark'): AcceptedAsset
    {
        return AssetIntake::make()->accept(
            bytes: $bytes,
            kind: $kind,
            label: $label,
            scope: CascadeLevel::Organisation,
            scopeId: (string) $this->organisation->id,
            organisationId: (string) $this->organisation->id,
        );
    }

    /**
     * 🛑 A GIF whose **header** declares `$width` × `$height`, written by hand.
     *
     * By hand and not by GD, because the decompression-bomb test needs a file
     * that is small on disk and enormous in its header — which is precisely
     * what no encoder will produce for you. The image data is a single
     * one-pixel LZW block, so the file stays under a kilobyte whatever the
     * header claims, and `getimagesizefromstring()` reports the declared size
     * because that is where the size lives.
     */
    private static function gif(int $width, int $height): string
    {
        $gif = 'GIF89a';
        $gif .= pack('vv', $width, $height);
        /* One bit of colour resolution, a two-entry global colour table. */
        $gif .= "\x80\x00\x00";
        $gif .= "\x00\x00\x00";   // black
        $gif .= "\xff\xff\xff";   // white
        /* Image descriptor: one pixel at the origin, no local table. */
        $gif .= "\x2c".pack('vvvv', 0, 0, 1, 1)."\x00";
        /* LZW minimum code size 2, one data block, a clear and an end code. */
        $gif .= "\x02\x02\x4c\x01\x00";
        $gif .= "\x3b";

        return $gif;
    }
}
