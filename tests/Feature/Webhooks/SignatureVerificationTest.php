<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Webhooks;

use App\Source\Provider;
use App\Webhooks\DeliveryHeaders;
use App\Webhooks\ProviderProfile;
use App\Webhooks\RawBodyVerifier;
use App\Webhooks\SignatureScheme;
use App\Webhooks\WebhookRejection;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

/**
 * §8.19.3's four signature schemes, with no database and no HTTP.
 *
 * > "Incoming provider webhooks MUST verify HMAC over the **raw** body with
 * > the provider's own scheme, constant-time comparison, and a 5-minute
 * > timestamp window where the provider supplies one."
 *
 * The database half — replay, audit, the 401 — is
 * {@see WebhookDeliveryTest}. This file is the cryptography, tested at the
 * level it is written at, so a failure says which scheme broke rather than
 * which route.
 */
final class SignatureVerificationTest extends TestCase
{
    private const SECRET = 'a-shared-secret-of-no-particular-shape';

    private const BODY = '{"ref":"refs/heads/main","after":"abc123"}';

    private RawBodyVerifier $verifier;

    protected function setUp(): void
    {
        parent::setUp();

        $this->verifier = new RawBodyVerifier;
    }

    /**
     * Every scheme accepts a signature it computed itself.
     *
     * @param  array<string, string>  $headers
     */
    #[DataProvider('validDeliveries')]
    public function test_a_genuine_signature_verifies(
        Provider $provider,
        SignatureScheme $scheme,
        array $headers,
    ): void {
        $this->assertNull(
            $scheme->verify(
                new DeliveryHeaders($headers),
                self::BODY,
                self::SECRET,
                ProviderProfile::for($provider),
                $this->verifier,
                1_800_000_000,
            ),
            $provider->value.' must accept a signature computed with its own scheme',
        );
    }

    /**
     * 🛑 Phase 11's exit criterion, for every scheme: "A forged signature
     * ... returns 401."
     *
     * The forgery here is the realistic one — a correctly shaped signature
     * computed with the wrong secret — rather than a malformed header,
     * because a scheme that only rejected garbage would pass a test built
     * from garbage.
     *
     * @param  array<string, string>  $headers
     */
    #[DataProvider('forgedDeliveries')]
    public function test_a_signature_made_with_the_wrong_secret_is_refused(
        Provider $provider,
        SignatureScheme $scheme,
        array $headers,
    ): void {
        $rejection = $scheme->verify(
            new DeliveryHeaders($headers),
            self::BODY,
            self::SECRET,
            ProviderProfile::for($provider),
            $this->verifier,
            1_800_000_000,
        );

        $this->assertSame(WebhookRejection::SignatureInvalid, $rejection);
        $this->assertSame(401, $rejection->status());
    }

    /**
     * 🛑 The raw body is what is signed, so one byte changes the answer.
     *
     * This is the test that would fail if somebody "tidied" the verifier to
     * use `json_encode($request->json()->all())` — a change that looks
     * harmless, passes every test built from a body the test itself
     * encoded, and breaks every genuine delivery.
     */
    public function test_a_body_altered_after_signing_is_refused(): void
    {
        $signature = 'sha256='.hash_hmac('sha256', self::BODY, self::SECRET);

        $rejection = SignatureScheme::HmacSha256Prefixed->verify(
            new DeliveryHeaders(['X-Hub-Signature-256' => $signature]),
            // Same JSON, one space added. A re-encoding would normalise it.
            '{"ref":"refs/heads/main", "after":"abc123"}',
            self::SECRET,
            ProviderProfile::for(Provider::GitHub),
            $this->verifier,
            1_800_000_000,
        );

        $this->assertSame(WebhookRejection::SignatureInvalid, $rejection);
    }

    /**
     * 🛑 GitHub's SHA-1 header must not be accepted in place of SHA-256.
     *
     * GitHub still sends `X-Hub-Signature` beside the SHA-256 one. SHA-1
     * has had practical collisions since 2017, and an implementation that
     * accepted whichever header arrived would let an attacker simply omit
     * the stronger one.
     */
    public function test_a_sha1_signature_is_not_accepted_for_github(): void
    {
        $rejection = SignatureScheme::HmacSha256Prefixed->verify(
            new DeliveryHeaders([
                'X-Hub-Signature' => 'sha1='.hash_hmac('sha1', self::BODY, self::SECRET),
            ]),
            self::BODY,
            self::SECRET,
            ProviderProfile::for(Provider::GitHub),
            $this->verifier,
            1_800_000_000,
        );

        $this->assertSame(
            WebhookRejection::SignatureMissing,
            $rejection,
            'the SHA-1 header is not even looked at: the profile lists only X-Hub-Signature-256',
        );
    }

    /**
     * 🛑 "a 5-minute timestamp window where the provider supplies one", and
     * the exit criterion: "a valid signature replayed outside the window
     * ... returns 401".
     *
     * The signature in this test is GENUINE. Only the clock has moved,
     * which is exactly what a captured-and-replayed delivery looks like.
     */
    public function test_a_valid_standard_webhooks_signature_outside_the_window_is_refused(): void
    {
        $signedAt = 1_800_000_000;
        $headers = new DeliveryHeaders($this->standardWebhooksHeaders($signedAt, self::SECRET));

        $this->assertNull(
            $this->verifyStandardWebhooks($headers, $signedAt + 299),
            'inside the window it verifies',
        );

        $rejection = $this->verifyStandardWebhooks($headers, $signedAt + 301);

        $this->assertNotNull($rejection);
        $this->assertSame(WebhookRejection::TimestampOutsideWindow, $rejection);
        $this->assertSame(401, $rejection->status());
    }

    /** 🛑 Both directions: a delivery from the future is a replay too. */
    public function test_a_timestamp_from_the_future_is_refused(): void
    {
        $signedAt = 1_800_000_000;
        $headers = new DeliveryHeaders($this->standardWebhooksHeaders($signedAt, self::SECRET));

        $this->assertSame(
            WebhookRejection::TimestampOutsideWindow,
            $this->verifyStandardWebhooks($headers, $signedAt - 301),
            'a one-sided window lets a captured delivery be replayed for ever with a future timestamp',
        );
    }

    /**
     * 🛑 The timestamp is inside the MAC, so moving it invalidates the
     * signature rather than widening the window.
     */
    public function test_editing_the_timestamp_header_invalidates_the_signature(): void
    {
        $signedAt = 1_800_000_000;
        $headers = $this->standardWebhooksHeaders($signedAt, self::SECRET);

        // Claim the delivery is current, keeping the original signature.
        $headers['webhook-timestamp'] = (string) ($signedAt + 100_000);

        $this->assertSame(
            WebhookRejection::SignatureInvalid,
            $this->verifyStandardWebhooks(new DeliveryHeaders($headers), $signedAt + 100_000),
        );
    }

    /** Standard Webhooks allows several versioned signatures; any one matching is a match. */
    public function test_a_rotated_standard_webhooks_secret_verifies_on_either_signature(): void
    {
        $signedAt = 1_800_000_000;
        $id = 'msg_rotation';

        $old = base64_encode(hash_hmac('sha256', $id.'.'.$signedAt.'.'.self::BODY, 'the-old-secret', true));
        $new = base64_encode(hash_hmac('sha256', $id.'.'.$signedAt.'.'.self::BODY, self::SECRET, true));

        $headers = new DeliveryHeaders([
            'webhook-id' => $id,
            'webhook-timestamp' => (string) $signedAt,
            'webhook-signature' => 'v1,'.$old.' v1,'.$new,
        ]);

        $this->assertNull($this->verifyStandardWebhooks($headers, $signedAt));
    }

    /**
     * 🛑 Three of the four schemes have NO timestamp, so three of the four
     * depend on the delivery-id ledger for replay protection.
     *
     * Read as "Bitbucket is the exception", §8.19.3 leaves GitHub, Gitea
     * and Forgejo unprotected — which is why this is asserted rather than
     * left to a comment.
     */
    public function test_only_standard_webhooks_carries_its_own_replay_protection(): void
    {
        $this->assertFalse(SignatureScheme::StandardWebhooks->needsDeliveryIdReplayProtection());

        foreach ([
            SignatureScheme::HmacSha256Prefixed,
            SignatureScheme::HmacSha256Hex,
            SignatureScheme::SharedToken,
        ] as $scheme) {
            $this->assertTrue(
                $scheme->needsDeliveryIdReplayProtection(),
                $scheme->value.' has no timestamp, so §8.19.3 falls back to delivery-id uniqueness',
            );
        }
    }

    /** 🛑 GitLab's legacy token signs nothing, and the product says so. */
    public function test_the_shared_token_scheme_reports_that_it_does_not_sign_the_body(): void
    {
        $this->assertFalse(SignatureScheme::SharedToken->signsTheBody());

        foreach ([
            SignatureScheme::HmacSha256Prefixed,
            SignatureScheme::HmacSha256Hex,
            SignatureScheme::StandardWebhooks,
        ] as $scheme) {
            $this->assertTrue($scheme->signsTheBody());
        }
    }

    /** A missing signature is refused rather than treated as empty. */
    public function test_an_absent_signature_header_is_refused(): void
    {
        foreach ([
            [Provider::GitHub, SignatureScheme::HmacSha256Prefixed],
            [Provider::Gitea, SignatureScheme::HmacSha256Hex],
            [Provider::GitLab, SignatureScheme::SharedToken],
            [Provider::GitLab, SignatureScheme::StandardWebhooks],
        ] as [$provider, $scheme]) {
            $this->assertSame(
                WebhookRejection::SignatureMissing,
                $scheme->verify(
                    new DeliveryHeaders([]),
                    self::BODY,
                    self::SECRET,
                    ProviderProfile::for($provider),
                    $this->verifier,
                    1_800_000_000,
                ),
                $scheme->value.' must refuse a delivery with no signature at all',
            );
        }
    }

    /** Header lookup is case-insensitive, because HTTP/2 lowercases everything. */
    public function test_a_lowercased_header_name_still_verifies(): void
    {
        $this->assertNull(
            SignatureScheme::HmacSha256Prefixed->verify(
                new DeliveryHeaders([
                    'x-hub-signature-256' => 'sha256='.hash_hmac('sha256', self::BODY, self::SECRET),
                ]),
                self::BODY,
                self::SECRET,
                ProviderProfile::for(Provider::GitHub),
                $this->verifier,
                1_800_000_000,
            ),
        );
    }

    /** @return array<string, array{0: Provider, 1: SignatureScheme, 2: array<string, string>}> */
    public static function validDeliveries(): array
    {
        $signature = hash_hmac('sha256', self::BODY, self::SECRET);

        return [
            'github' => [Provider::GitHub, SignatureScheme::HmacSha256Prefixed, [
                'X-Hub-Signature-256' => 'sha256='.$signature,
            ]],
            'bitbucket cloud' => [Provider::BitbucketCloud, SignatureScheme::HmacSha256Prefixed, [
                'X-Hub-Signature' => 'sha256='.$signature,
            ]],
            'bitbucket server' => [Provider::BitbucketServer, SignatureScheme::HmacSha256Prefixed, [
                'X-Hub-Signature' => 'sha256='.$signature,
            ]],
            'gitea' => [Provider::Gitea, SignatureScheme::HmacSha256Hex, [
                'X-Gitea-Signature' => $signature,
            ]],
            'forgejo' => [Provider::Forgejo, SignatureScheme::HmacSha256Hex, [
                'X-Forgejo-Signature' => $signature,
            ]],
            'generic' => [Provider::Generic, SignatureScheme::HmacSha256Hex, [
                'X-DocUp-Signature' => $signature,
            ]],
            'gitlab legacy token' => [Provider::GitLab, SignatureScheme::SharedToken, [
                'X-Gitlab-Token' => self::SECRET,
            ]],
            'gitlab standard webhooks' => [Provider::GitLab, SignatureScheme::StandardWebhooks, [
                'webhook-id' => 'msg_1',
                'webhook-timestamp' => '1800000000',
                'webhook-signature' => 'v1,'.base64_encode(
                    hash_hmac('sha256', 'msg_1.1800000000.'.self::BODY, self::SECRET, true)
                ),
            ]],
        ];
    }

    /** @return array<string, array{0: Provider, 1: SignatureScheme, 2: array<string, string>}> */
    public static function forgedDeliveries(): array
    {
        $wrong = hash_hmac('sha256', self::BODY, 'the-attackers-guess');

        return [
            'github' => [Provider::GitHub, SignatureScheme::HmacSha256Prefixed, [
                'X-Hub-Signature-256' => 'sha256='.$wrong,
            ]],
            'bitbucket cloud' => [Provider::BitbucketCloud, SignatureScheme::HmacSha256Prefixed, [
                'X-Hub-Signature' => 'sha256='.$wrong,
            ]],
            'gitea' => [Provider::Gitea, SignatureScheme::HmacSha256Hex, [
                'X-Gitea-Signature' => $wrong,
            ]],
            'gitlab legacy token' => [Provider::GitLab, SignatureScheme::SharedToken, [
                'X-Gitlab-Token' => 'the-attackers-guess',
            ]],
            'gitlab standard webhooks' => [Provider::GitLab, SignatureScheme::StandardWebhooks, [
                'webhook-id' => 'msg_1',
                'webhook-timestamp' => '1800000000',
                'webhook-signature' => 'v1,'.base64_encode(
                    hash_hmac('sha256', 'msg_1.1800000000.'.self::BODY, 'the-attackers-guess', true)
                ),
            ]],
        ];
    }

    /** @return array<string, string> */
    private function standardWebhooksHeaders(int $signedAt, string $secret): array
    {
        $id = 'msg_window';

        return [
            'webhook-id' => $id,
            'webhook-timestamp' => (string) $signedAt,
            'webhook-signature' => 'v1,'.base64_encode(
                hash_hmac('sha256', $id.'.'.$signedAt.'.'.self::BODY, $secret, true)
            ),
        ];
    }

    private function verifyStandardWebhooks(DeliveryHeaders $headers, int $now): ?WebhookRejection
    {
        return SignatureScheme::StandardWebhooks->verify(
            $headers,
            self::BODY,
            self::SECRET,
            ProviderProfile::for(Provider::GitLab),
            $this->verifier,
            $now,
        );
    }
}
