<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

/*
|------------------------------------------------------------------------------
| TLS automation and certificate sources (SPEC 8.10.10 – 8.10.21)
|------------------------------------------------------------------------------
| 🛑 SPEC 8.10.11 gates on-demand issuance behind an internal permission
| endpoint, and SPEC 8.10.12 makes one configuration of it a **validation
| error**:
|
|   "The permission endpoint's own URL MUST NOT be HTTPS on any hostname the
|    installation serves. That configuration is a startup deadlock and MUST be
|    a validation error."
|
| The deadlock is worth spelling out because it is not obvious and it is
| unrecoverable without an operator at a console: the proxy cannot complete a
| handshake for a hostname until it has a certificate; it cannot get a
| certificate until the permission endpoint says yes; and if the endpoint is
| itself HTTPS on a hostname this installation serves, reaching it requires a
| certificate for that hostname. The installation comes up with no TLS at all
| and no error that names the cause.
|
| `App\Tls\PermissionEndpoint` refuses that configuration at boot. The default
| below is plaintext over loopback, which is what SPEC 8.10.11 asks for:
| "internal, session-free, plaintext".
*/

return [

    /*
     * Where the proxy asks. Plaintext, loopback, no session.
     *
     * 🛑 The port is the container's internal HTTP port, not the published
     * one: the proxy and the application are the same FrankenPHP process in
     * the shipped topology, so this request never leaves the container.
     */
    'permission_endpoint' => env('DOCUP_TLS_PERMISSION_ENDPOINT', 'http://127.0.0.1/_/edge/tls-permission'),

    /*
     * Where the proxy fetches a certificate it should serve from the database
     * (SPEC 8.10.14). Same reasoning, same shape.
     */
    'certificate_endpoint' => env('DOCUP_TLS_CERTIFICATE_ENDPOINT', 'http://127.0.0.1/_/edge/certificate'),

    /*
     * 🛑 SPEC 8.10.14: "The proxy admin API MUST stay **disabled** — it is
     * root-equivalent on the edge."
     *
     * Declared here so that `TlsConfigurationTest` can assert the shipped
     * Caddyfile agrees with it, byte for byte, the way SPEC 8.10.22's header
     * allowlist is asserted. A constant nobody checks against the thing it
     * describes is a comment.
     */
    'admin_api_enabled' => false,

    /*
     * SPEC 8.10.13's budget, as the CA states it. Changing these does not
     * change the CA's own limits — it only changes whether this installation
     * finds out from its own counter or from a rate-limit failure, and the
     * second costs authorization-failure budget as well.
     *
     * Re-read 2026-10-26 against a page last updated 2026-08-05 (SPEC 18.20).
     */
    'budget' => [
        'capacity' => 50,
        'refill_minutes' => 202,
        'warn_below' => 10,
    ],

    /*
     * Operator-declared public suffixes, for SPEC 8.10.13's "per registered
     * domain" bucketing.
     *
     * 🛑 Empty by default, and `App\Tls\RegisteredDomain` says why at length:
     * without the Public Suffix List, the last two labels are used, which
     * over-groups a multi-label suffix such as `co.uk` and therefore stops
     * issuing EARLIER than the CA would. Wrong in the safe direction. An
     * installation serving many hostnames under one multi-label suffix names
     * it here and gets the CA's own bucketing back.
     */
    'public_suffixes' => array_values(array_filter(
        array_map('trim', explode(',', (string) env('DOCUP_PUBLIC_SUFFIXES', ''))),
        static fn (string $suffix): bool => $suffix !== '',
    )),

    /*
     * SPEC 8.10.17's prober.
     *
     * > "A scheduled outbound TLS handshake prober MUST run against every
     * >  active domain at least every six hours, recording expiry, issuer and
     * >  error, **because the proxy never calls the permission endpoint back
     * >  on issuance failure**."
     *
     * 🛑 SPEC 18.20 predicted this interval would have to shorten as
     * certificate lifetimes fall, and the 2026-10-26 re-read says **not
     * yet**: production lifetimes drop from 90 to 64 days on 2027-02-10, and
     * at two-thirds-of-life renewal that still leaves 21 days between "should
     * have renewed" and "expires". Six hours is 1% of that. The interval
     * becomes worth revisiting at the 45-day lifetime scheduled for
     * 2028-02-16, where the slack is 15 days — still comfortable, which is
     * why this stays at six hours and the claim is recorded rather than the
     * number changed.
     */
    'probe' => [
        'interval_hours' => 6,
        'timeout_seconds' => 5,

        /*
         * How close to expiry counts as a problem worth an operator's
         * attention. 21 days is the renewal slack of a 64-day certificate,
         * so a certificate inside it is one whose renewal has not happened
         * when it should have.
         */
        'expiry_warning_days' => 21,
    ],

    /*
     * The ACME account the installation issues with, when it issues at all.
     * Empty by default: SPEC 8.10.11's design has the proxy obtain a custom
     * domain's public certificate on demand, so most installations configure
     * nothing here.
     *
     * 🛑 SPEC 18.20's consequence column: "P19 … requires an operator-supplied
     * ACME account". An installation that wants DocUp to hold the key supplies
     * the directory and a contact address; nothing is auto-registered against
     * a public CA on this installation's behalf.
     */
    'acme' => [
        'directory' => env('DOCUP_ACME_DIRECTORY', ''),
        'contact' => env('DOCUP_ACME_CONTACT', ''),
        'kind' => env('DOCUP_ACME_KIND', 'public'),
    ],

];
