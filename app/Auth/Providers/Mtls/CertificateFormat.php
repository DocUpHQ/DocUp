<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers\Mtls;

/**
 * 🛑 How the TLS terminator spells a client certificate in a header, as a
 * closed set of three.
 *
 * A certificate is PEM with embedded newlines, and a newline cannot travel in
 * an HTTP header — RFC 9110 §5.5 forbids it and every proxy in the path would
 * either reject the message or, worse, split it. So every terminator mangles
 * the certificate somehow, and they do not agree:
 *
 * | Terminator | Variable | This case |
 * |---|---|---|
 * | nginx | `$ssl_client_escaped_cert` | {@see self::EscapedPem} |
 * | nginx (legacy) | `$ssl_client_cert` | {@see self::Pem} — newlines become spaces or tabs |
 * | Caddy | `{http.request.tls.client.certificate_der_base64}` | {@see self::DerBase64} |
 * | Caddy | `{http.request.tls.client.certificate_pem}` | {@see self::Pem} |
 * | HAProxy | `ssl_c_der,base64` | {@see self::DerBase64} |
 * | Envoy | XFCC `Cert=` | {@see self::EscapedPem} |
 *
 * 🛑 **An enum rather than a guess.** The three spellings are distinguishable
 * by inspection — PEM armour, `%`-escapes, bare base64 — so sniffing would
 * work most of the time, and "most of the time" is the problem: a sniffer that
 * guesses wrong on one certificate in a thousand produces one reader who
 * cannot read anything and no diagnosis. The operator states the format, the
 * probe echoes it back, and a mismatch fails for everybody at once — which is
 * the failure that gets fixed.
 */
enum CertificateFormat: string
{
    /**
     * URL-encoded PEM, which is nginx's `$ssl_client_escaped_cert` and the one
     * to prefer.
     *
     * 🛑 The documented spelling for nginx since 1.11.6, and the reason
     * {@see self::Pem} exists only for compatibility: `$ssl_client_cert`
     * prefixes every continuation line with a tab, so the value depends on the
     * proxy's own header folding rather than on the certificate.
     */
    case EscapedPem = 'escaped_pem';

    /**
     * PEM whose newlines have become whitespace somewhere in the path.
     *
     * Normalised by stripping the armour and all whitespace and re-wrapping,
     * so a tab-folded, space-folded or newline-preserving variant all parse to
     * the same certificate.
     */
    case Pem = 'pem';

    /** Base64 of the DER, which is Caddy's and HAProxy's spelling. */
    case DerBase64 = 'der_base64';

    /**
     * The configured format, or the safe default.
     *
     * 🛑 Defaults to {@see self::EscapedPem} rather than refusing, because the
     * default is only reached on an installation that configured a certificate
     * header and not a format — and in that state the useful outcome is a
     * probe that names the format it assumed. Refusing would be a 500 on the
     * serving path for a field an operator left blank.
     */
    public static function configured(): self
    {
        $value = config('docup.auth.client_certificate.format');

        return is_string($value) ? (self::tryFrom($value) ?? self::EscapedPem) : self::EscapedPem;
    }
}
