<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Webhooks;

/**
 * §11.1's four mutually incompatible webhook signature schemes, one adapter
 * each, all of them calling §11.1's one shared raw-body verifier.
 *
 * | Scheme | Providers | Header | Signed bytes | Timestamp |
 * |---|---|---|---|---|
 * | `hmac_sha256_prefixed` | GitHub, Bitbucket | `sha256=<hex>` | raw body | no |
 * | `hmac_sha256_hex` | Gitea, Forgejo, generic | bare `<hex>` | raw body | no |
 * | `standard_webhooks` | GitLab 19.1+ | `v1,<base64>` | `id.ts.body` | **yes** |
 * | `shared_token` | GitLab legacy | the secret itself | nothing | no |
 *
 * 🛑 **Three of the four have no timestamp**, which is why §8.19.3's
 * "5-minute timestamp window **where the provider supplies one**" has an
 * else branch at all, and why {@see WebhookRejection::DeliveryReplayed}
 * exists. Read as "Bitbucket is the exception" the requirement is
 * under-implemented: GitHub, Gitea and Forgejo are in exactly the same
 * position, and only GitLab's newer scheme carries a timestamp.
 *
 * 🛑 `shared_token` signs **nothing**. GitLab's legacy `X-Gitlab-Token` is a
 * bearer secret compared for equality, so a delivery body can be altered
 * freely by anyone who has the token, and anyone who can read one delivery
 * has it for ever. It is supported because GitLab instances below 19.1 send
 * nothing else, and it is a separate enum case rather than a flag so that
 * {@see signsTheBody()} can tell an operator which of their integrations are
 * in that position.
 */
enum SignatureScheme: string
{
    case HmacSha256Prefixed = 'hmac_sha256_prefixed';
    case HmacSha256Hex = 'hmac_sha256_hex';
    case StandardWebhooks = 'standard_webhooks';
    case SharedToken = 'shared_token';

    /** §8.19.3's window, in seconds, for the one scheme that has a timestamp. */
    public const TIMESTAMP_WINDOW_SECONDS = 300;

    /**
     * Whether the signature actually covers the request body.
     *
     * Surfaced rather than inferred, because an operator deciding whether to
     * upgrade their GitLab deserves a straight answer to "is my webhook
     * authenticated, or just gated?".
     */
    public function signsTheBody(): bool
    {
        return $this !== self::SharedToken;
    }

    /**
     * Whether this scheme's replay protection is the §8.19.3 fallback.
     *
     * 🛑 True for three of four. The fallback is weaker — see
     * {@see DeliveryLedger} — and the documentation says so.
     */
    public function needsDeliveryIdReplayProtection(): bool
    {
        return $this !== self::StandardWebhooks;
    }

    /**
     * Verify one delivery, or say why not.
     *
     * Returns null when the delivery is authentic. Every other return is a
     * §8.1.11 identifier, never a boolean: "it failed" and "the timestamp was
     * eleven minutes old" are the same fact to an attacker and very different
     * facts to the operator reading the audit log.
     *
     * @param  string  $rawBody  the bytes as received, never re-encoded
     * @param  string  $secret  the unsealed shared secret
     * @param  int  $now  unix seconds, injected so the window is testable
     */
    public function verify(
        DeliveryHeaders $headers,
        string $rawBody,
        string $secret,
        ProviderProfile $profile,
        RawBodyVerifier $verifier,
        int $now,
    ): ?WebhookRejection {
        return match ($this) {
            self::HmacSha256Prefixed => $this->verifyPrefixed($headers, $rawBody, $secret, $profile, $verifier),
            self::HmacSha256Hex => $this->verifyBareHex($headers, $rawBody, $secret, $profile, $verifier),
            self::StandardWebhooks => $this->verifyStandardWebhooks($headers, $rawBody, $secret, $verifier, $now),
            self::SharedToken => $this->verifySharedToken($headers, $secret, $profile, $verifier),
        };
    }

    /** GitHub and Bitbucket: `sha256=<lowercase hex>` over the raw body. */
    private function verifyPrefixed(
        DeliveryHeaders $headers,
        string $rawBody,
        string $secret,
        ProviderProfile $profile,
        RawBodyVerifier $verifier,
    ): ?WebhookRejection {
        $presented = $headers->first(...$profile->signatureHeaders);

        if ($presented === null) {
            return WebhookRejection::SignatureMissing;
        }

        /*
         * 🛑 The prefix names the algorithm, and a delivery claiming `sha1=`
         * is refused rather than quietly verified as SHA-256. GitHub still
         * sends a SHA-1 `X-Hub-Signature` beside the SHA-256 one for
         * compatibility; accepting the weaker header because it was there
         * would make the stronger one decorative.
         */
        if (! str_starts_with($presented, 'sha256=')) {
            return WebhookRejection::SignatureMalformed;
        }

        $digest = strtolower(substr($presented, 7));

        return $verifier->matches($rawBody, $secret, $digest, SignatureEncoding::Hex)
            ? null
            : WebhookRejection::SignatureInvalid;
    }

    /** Gitea, Forgejo and the generic provider: bare lowercase hex. */
    private function verifyBareHex(
        DeliveryHeaders $headers,
        string $rawBody,
        string $secret,
        ProviderProfile $profile,
        RawBodyVerifier $verifier,
    ): ?WebhookRejection {
        $presented = $headers->first(...$profile->signatureHeaders);

        if ($presented === null) {
            return WebhookRejection::SignatureMissing;
        }

        if (preg_match('/^[0-9a-fA-F]{64}$/', $presented) !== 1) {
            return WebhookRejection::SignatureMalformed;
        }

        return $verifier->matches($rawBody, $secret, strtolower($presented), SignatureEncoding::Hex)
            ? null
            : WebhookRejection::SignatureInvalid;
    }

    /**
     * GitLab 19.1+, the Standard Webhooks specification.
     *
     * 🛑 The only scheme with a timestamp, so the only one where §8.19.3's
     * five-minute window applies. The signed payload is
     * `{id}.{timestamp}.{body}` — the id and the timestamp are **inside** the
     * MAC, which is what makes the window meaningful: an attacker who could
     * edit the timestamp header without invalidating the signature would have
     * a window of any width they liked.
     */
    private function verifyStandardWebhooks(
        DeliveryHeaders $headers,
        string $rawBody,
        string $secret,
        RawBodyVerifier $verifier,
        int $now,
    ): ?WebhookRejection {
        $id = $headers->get('webhook-id');
        $timestamp = $headers->get('webhook-timestamp');
        $presented = $headers->get('webhook-signature');

        if ($presented === null || $presented === '') {
            return WebhookRejection::SignatureMissing;
        }

        if ($id === null || $id === '') {
            return WebhookRejection::DeliveryIdMissing;
        }

        if ($timestamp === null || preg_match('/^-?\d{1,19}$/', $timestamp) !== 1) {
            return WebhookRejection::TimestampMissing;
        }

        /*
         * 🛑 Both directions. A delivery from the future is as suspicious as
         * one from the past — more so, because clock skew large enough to
         * matter is itself a finding — and a one-sided check lets an attacker
         * with a captured delivery replay it indefinitely by sending a
         * timestamp far ahead.
         */
        if (abs($now - (int) $timestamp) > self::TIMESTAMP_WINDOW_SECONDS) {
            return WebhookRejection::TimestampOutsideWindow;
        }

        $signedPayload = $id.'.'.$timestamp.'.'.$rawBody;

        /*
         * The header is a space-separated list of `v<version>,<signature>` so
         * a sender can rotate secrets without a gap. Any one match is a
         * match; every candidate is compared, and each comparison is
         * constant-time, so the loop leaks only how many versions were
         * offered — which the header already states in the clear.
         */
        $matched = false;

        foreach (explode(' ', $presented) as $candidate) {
            if (! str_starts_with($candidate, 'v1,')) {
                continue;
            }

            $matched = $verifier->matches($signedPayload, $secret, substr($candidate, 3), SignatureEncoding::Base64)
                || $matched;
        }

        return $matched ? null : WebhookRejection::SignatureInvalid;
    }

    /** GitLab below 19.1: the secret itself, in a header. */
    private function verifySharedToken(
        DeliveryHeaders $headers,
        string $secret,
        ProviderProfile $profile,
        RawBodyVerifier $verifier,
    ): ?WebhookRejection {
        $presented = $headers->first(...$profile->signatureHeaders);

        if ($presented === null) {
            return WebhookRejection::SignatureMissing;
        }

        return $verifier->secretMatches($secret, $presented)
            ? null
            : WebhookRejection::SignatureInvalid;
    }
}
