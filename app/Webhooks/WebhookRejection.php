<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Webhooks;

use App\Config\ConfigRejection;
use App\Serving\RejectionReason;

/**
 * Why a delivery was refused, as a stable identifier.
 *
 * 🛑 §8.1.11 public contract, like {@see ConfigRejection} and
 * {@see RejectionReason} before it: these values reach the audit
 * log, an operator's alert rule and the webhook debugging panel, so renaming
 * one breaks something outside this repository.
 *
 * 🛑 **Every value here answers 401 except `unsupported_event` and
 * `ref_not_tracked`.** That split is the whole security posture: a request
 * that failed to prove who sent it is unauthorised, and a request that proved
 * it and asked for something we do not do is a 202 with a reason. Collapsing
 * them would either turn an ordinary `ping` into an alert or turn a forgery
 * into a shrug.
 */
enum WebhookRejection: string
{
    /*
     * 🛑 Deliberately indistinguishable from `signature_invalid` to the
     * caller, which gets 401 and nothing else. An unknown-integration 404
     * and a bad-signature 401 together enumerate which integration ids
     * exist, and the id is in the URL where anyone can try one.
     */
    case UnknownIntegration = 'webhook.unknown_integration';
    case IntegrationDisabled = 'webhook.integration_disabled';

    case SignatureMissing = 'webhook.signature_missing';
    case SignatureMalformed = 'webhook.signature_malformed';
    case SignatureInvalid = 'webhook.signature_invalid';

    /** The provider supplies a timestamp and this delivery had none. */
    case TimestampMissing = 'webhook.timestamp_missing';

    /** §8.19.3's five-minute window, in either direction. */
    case TimestampOutsideWindow = 'webhook.timestamp_outside_window';

    /** 🛑 §8.19.3's fallback where no timestamp exists (Bitbucket). */
    case DeliveryReplayed = 'webhook.delivery_replayed';

    /** No delivery id from a provider whose replay protection needs one. */
    case DeliveryIdMissing = 'webhook.delivery_id_missing';

    case BodyTooLarge = 'webhook.body_too_large';
    case BodyMalformed = 'webhook.body_malformed';

    /**
     * The payload named a repository this integration is not for.
     *
     * Not a forgery — the signature verified — but a provider
     * misconfiguration in which one repository's webhook points at another's
     * integration. Refused rather than followed, because following it would
     * let whoever controls repository A trigger builds of repository B.
     */
    case RepositoryMismatch = 'webhook.repository_mismatch';

    /** A `ping`, an issue comment, anything that is not a push. */
    case UnsupportedEvent = 'webhook.unsupported_event';

    /** A push to a ref no project tracks. Verified, understood, nothing to do. */
    case RefNotTracked = 'webhook.ref_not_tracked';

    /**
     * The HTTP status this rejection answers.
     *
     * 🛑 401 for everything that failed to establish authenticity, 202 for
     * everything that established it and had nothing to do. Never 500: a 5xx
     * teaches every provider in the list to redeliver, and a redelivery storm
     * against the one unauthenticated endpoint in the application is the
     * denial of service we would have built ourselves.
     */
    public function status(): int
    {
        return match ($this) {
            self::UnsupportedEvent, self::RefNotTracked => 202,
            default => 401,
        };
    }

    /**
     * Whether this rejection is worth an audit event.
     *
     * A forged signature is a security event; a `ping` is Tuesday. Auditing
     * both would bury the first under the second, which is the practical
     * form of not auditing it at all.
     */
    public function isSecuritySignificant(): bool
    {
        return $this->status() === 401;
    }
}
