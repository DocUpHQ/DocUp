<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

return [

    /*
    |---------------------------------------------------------------------------
    | Origins (SPEC 8.1.4, 8.1.5)
    |---------------------------------------------------------------------------
    | 🛑 The dashboard and published documentation MUST occupy distinct
    | registrable domains, and the application refuses to boot when they do not.
    | Built documentation is attacker-controlled HTML and JavaScript; on a shared
    | registrable domain it can toss cookies at the dashboard, Clear-Site-Data
    | spans tenants, and Laravel's TrustHosts default trusts subdomains of
    | APP_URL.
    |
    | The sole exception is DOCUP_UNSAFE_SINGLE_ORIGIN (SPEC 8.1.5), which forces
    | every project public and disables private sharing and tenant CSS.
    */
    'origins' => [
        'app' => env('DOCUP_APP_HOST'),
        'docs' => env('DOCUP_DOCS_APEX'),
        'preview' => env('DOCUP_PREVIEW_APEX'),
        'assets' => env('DOCUP_ASSET_HOST'),
    ],

    /*
    |---------------------------------------------------------------------------
    | Unsafe modes (SPEC 8.22.11, 20.4)
    |---------------------------------------------------------------------------
    | 🛑 One registry. Every installation-level escape hatch lives here, and an
    | architecture test asserts that no DOCUP_UNSAFE_*, DOCUP_DANGEROUSLY_*,
    | DOCUP_ACKNOWLEDGE_* or DOCUP_ALLOW_* variable exists outside it.
    |
    | Invariant: no security control sits behind a flag that defaults open.
    */
    'unsafe' => [
        'single_origin' => env('DOCUP_UNSAFE_SINGLE_ORIGIN', false),
        'acknowledge_unsandboxed' => env('DOCUP_ACKNOWLEDGE_UNSANDBOXED', false),
        'allow_unlisted_auth_types' => env('DOCUP_DANGEROUSLY_ALLOW_UNLISTED_AUTH_TYPES', false),
        'allow_raw_html_branding' => env('DOCUP_ALLOW_RAW_HTML_BRANDING', false),
        'allow_unverified_build_images' => env('DOCUP_ALLOW_UNVERIFIED_BUILD_IMAGES', false),
    ],

    /*
    |---------------------------------------------------------------------------
    | Multi-factor authentication (SPEC 8.13.4)
    |---------------------------------------------------------------------------
    | 🛑 "MFA MUST be enforceable per installation and per organisation,
    | required above `project_writer`, via TOTP."
    |
    | This is the **installation** half. The organisation half is a column, and
    | `App\Auth\MfaEnforcement` says why the two scopes have two mechanisms: an
    | installation posture belongs to whoever has a shell and a `.env`, and a
    | tenant's belongs to an `org_admin` who has neither.
    |
    | 🛑 This switch **dominates**: an organisation cannot opt out of a
    | requirement the installation imposes. The reverse ordering would make the
    | tenant switch a vulnerability with a checkbox.
    |
    | Default **off**, which is §8.13.4's own word — "enforceable", not
    | "enforced". Turning it on by default would lock every existing
    | administrator out on upgrade, including the one who would have to turn it
    | off. Surfacing the recommendation is `doctor`'s job (§15).
    |
    | 🛑 There is no passkey switch here. §8.13.4 says "with passkeys where the
    | library proves production-ready (§18)" and §18 carries **no passkey row**
    | — not an unverified one, none. `config/fortify.php` records the same gap
    | beside the commented-out `Features::passkeys()`. Phase 26a proposes the
    | amendment that adds the assumption rather than inventing a verdict for it.
    */
    'mfa' => [
        'required' => env('DOCUP_MFA_REQUIRED', false),
    ],

    /*
    |---------------------------------------------------------------------------
    | Quality gates (SPEC 9.4)
    |---------------------------------------------------------------------------
    | Three tiers. These thresholds are committed configuration protected by
    | CODEOWNERS, and `docup:gate --check-thresholds` fails when one DECREASES
    | relative to git HEAD - so a phase under time pressure cannot lower the bar
    | instead of fixing the code.
    */
    'gates' => [
        'baseline' => [
            'phpstan_level' => 8,
            'phpstan_level_strict_paths' => 9,
            'strict_paths' => [
                'app/Serving',
                'app/Auth',
                'app/Artifacts',
                'app/Config',
            ],
            'pest_presets' => ['php', 'security', 'laravel', 'strict'],
        ],
        'security_critical' => [
            'mutation_min_score' => 75,
            'requires_threat_model_delta' => true,
            'requires_abuse_corpus_case' => true,
        ],
        'release' => [
            'requires_asvs_matrix' => true,
            'requires_sbom' => true,
            'requires_signed_provenance' => true,
        ],
    ],

    /*
    |---------------------------------------------------------------------------
    | Artifact storage (SPEC 8.8.1, 10.3)
    |---------------------------------------------------------------------------
    | Write-once, keyed only by the build identifier. 🛑 No project slug, version
    | slug, language or user-supplied name may appear in a storage key, so that
    | renaming can never strand or invalidate stored artifacts.
    */
    'artifacts' => [
        'disk' => env('DOCUP_ARTIFACT_DISK', 'artifacts'),
        'max_files' => (int) env('DOCUP_ARTIFACT_MAX_FILES', 50_000),
        'max_bytes' => (int) env('DOCUP_ARTIFACT_MAX_BYTES', 5 * 1024 * 1024 * 1024),
        'max_file_bytes' => (int) env('DOCUP_ARTIFACT_MAX_FILE_BYTES', 1024 * 1024 * 1024),
        'max_compression_ratio' => (int) env('DOCUP_ARTIFACT_MAX_RATIO', 100),
    ],

    /*
    |---------------------------------------------------------------------------
    | Edge driver (SPEC 11.3, ADR 0001)
    |---------------------------------------------------------------------------
    | Both drivers exist from day one behind one ArtifactHandoff interface and
    | both run in the CI matrix. caddy-intercept is the default because it
    | preserves the application's response headers through the handoff natively;
    | nginx-accel replaces the whole header set and needs the re-emission list in
    | its own configuration (SPEC 8.9.8).
    */
    'edge' => [
        'driver' => env('DOCUP_EDGE_DRIVER', 'caddy-intercept'),
        'internal_prefix' => '/_internal',

        /*
        |-----------------------------------------------------------------------
        | 🛑 SPEC 8.9.4 and SPEC 17's Phase 26b criterion: the trusted hop count
        |-----------------------------------------------------------------------
        | Which addresses in front of the application are DocUp's own, so that
        | `$request->ip()` is the READER's address rather than the edge's.
        |
        | 🛑 Phase 26b found this unset, and found what that cost. With no
        | trusted proxy, `$request->ip()` returns `REMOTE_ADDR` — the edge
        | container — so SPEC 8.12.17's `ip_allowlist` gate was comparing the
        | EDGE's address against the operator's allowlist. Either it matched
        | nothing, or an operator debugging "my allowlist never works" read the
        | address out of their logs, allowlisted it, and made the gate satisfied
        | for every reader on the internet. SPEC 8.12.7 keeps a requirement from
        | resting on a gate alone, so the blast radius was a narrowing that did
        | not narrow rather than public access — silently, which is worse.
        |
        | Empty means trust nothing, which is SAFE and was the state before this
        | setting existed: `X-Forwarded-For` is ignored entirely and `ip()` is
        | the direct peer. An installation with no `ip_allowlist` binding needs
        | nothing here.
        |
        | `*` trusts whatever is in front, which is correct ONLY where the
        | application is unreachable except through that proxy — the shipped
        | compose topology, where the app port is not published. On a host where
        | the application port is reachable, `*` lets any client set its own
        | address: name the proxy's CIDR instead.
        */
        'trusted_proxies' => env('DOCUP_TRUSTED_PROXIES', ''),

        /*
        |-----------------------------------------------------------------------
        | 🛑 SPEC 8.12.13's enforcement ladder
        |-----------------------------------------------------------------------
        | Three topologies from one grant, and the default is the one with
        | nothing at the edge to misconfigure:
        |
        |   `a` — every request authorised in PHP, bytes handed off by internal
        |         redirect. The shipped compose file.
        |   `b` — nginx `auth_request` against `/_/authz`, cached on the opaque
        |         cache-key cookie, so one PHP call authorises a 60-asset page.
        |         Needs the `fastcgi_cache` directives in deploy/nginx.conf.
        |   `c` — edge-local token verification.
        |
        | 🛑 Tier C carries a MANDATORY condition and `docup:doctor` refuses it
        | without one: "the edge MUST consume a revocation epoch feed at
        | ≤5-second intervals and refuse any grant below the current epoch …
        | Without that feed, a project flipped public→private keeps serving to
        | anonymous readers for the grant lifetime — the largest exposure window
        | any design in this area produces."
        |
        | `epoch_feed_seconds` is the operator asserting how often their edge
        | polls SPEC 20.2's feed. Unset means "not configured", which is what
        | `doctor` refuses Tier C for — a default would be the application
        | asserting something only the edge knows.
        */
        'enforcement_tier' => env('DOCUP_ENFORCEMENT_TIER', 'a'),
        'epoch_feed_seconds' => env('DOCUP_EDGE_EPOCH_FEED_SECONDS'),
    ],

    /*
    |---------------------------------------------------------------------------
    | Reader authentication (SPEC 8.12.4, SPEC 8.12.17)
    |---------------------------------------------------------------------------
    | 🛑 Everything here is OFF unless an operator turns it on, and that is the
    | specification's own instruction rather than a cautious default: SPEC
    | 8.12.17 marks `header_trust` "installation only, off by default", and it is
    | the only one of eleven drivers so marked.
    |
    | `mtls` and `header_trust` authenticate a reader from a fact the TLS
    | terminator established and forwarded in a header. DocUp never terminates
    | TLS (SPEC 11.3), so there is no way for it to check that fact itself - and
    | an installation that has not said WHICH hop may assert must not believe
    | any of them. Hence the hard prerequisite below.
    |
    | 🛑 None of these headers resolves a project. SPEC 8.9.4: "No request
    | header MUST act as a project, version or tenant selector, in any
    | environment." The project comes from the Host and the path, and
    | `EdgeAssertion` refuses to read a header whose name is any spelling of the
    | host. These name a READER.
    */
    'auth' => [
        /*
        | SPEC 8.12.4's installation-level restriction on which driver types a
        | project administrator may configure. EMPTY means "every registered
        | type", which is the only safe default for an allowlist of features:
        | an empty-means-nothing default would leave a fresh installation unable
        | to configure any authentication at all, and the first thing an
        | operator would reach for is the flag that disables the check.
        |
        | 🛑 `header_trust` is NOT governed by this list, in either direction -
        | see `DriverRegistry::REQUIRES_NAMING`. It must be named explicitly and
        | the permissive default does not reach it.
        */
        'permitted_types' => array_values(array_filter(array_map(
            'trim',
            explode(',', (string) env('DOCUP_PERMITTED_AUTH_TYPES', '')),
        ))),

        /*
        | SPEC 8.12.17's `header_trust`: an identity the terminator asserts.
        |
        | 🛑 The secret header is not optional and the driver's probe fails
        | without it. A terminator that sets the subject header only for an
        | AUTHENTICATED reader passes an unauthenticated reader's own header
        | through untouched - which is oauth2-proxy's default - so the subject
        | header alone is forgeable with one curl. The shared secret is what
        | distinguishes the terminator's assertion from a client's copy of it.
        |
        | Set the same value at the terminator and on the binding, e.g.
        |   proxy_set_header X-DocUp-Assertion "<the binding's secret>";
        */
        'asserted_identity' => [
            'subject_header' => env('DOCUP_ASSERTED_SUBJECT_HEADER', ''),
            'secret_header' => env('DOCUP_ASSERTED_SECRET_HEADER', ''),
        ],

        /*
        | SPEC 8.12.17's `mtls`: a client certificate the terminator verified.
        |
        | 🛑 The verdict header is not optional either, and the bypass it closes
        | is worth knowing: nginx's `ssl_verify_client optional` forwards
        | `$ssl_client_escaped_cert` EVEN WHEN VERIFICATION FAILED. A driver
        | reading only the certificate would accept a self-signed one an
        | attacker minted with the right issuer DN, because the issuer DN is a
        | field in a document the attacker wrote. One line at the terminator:
        |   proxy_set_header X-Client-Verify $ssl_client_verify;    # nginx
        |   header_up X-Client-Verify SUCCESS                       # Caddy
        |
        | `format` names how the terminator spells a certificate in a header.
        | nginx's `$ssl_client_escaped_cert` is `escaped_pem`; Caddy's and
        | HAProxy's base64 DER is `der_base64`. Stated rather than sniffed: a
        | sniffer that guesses wrong on one certificate in a thousand produces
        | one reader who cannot read anything and no diagnosis.
        */
        'client_certificate' => [
            'header' => env('DOCUP_CLIENT_CERTIFICATE_HEADER', ''),
            'format' => env('DOCUP_CLIENT_CERTIFICATE_FORMAT', 'escaped_pem'),
            'verdict_header' => env('DOCUP_CLIENT_CERTIFICATE_VERDICT_HEADER', ''),
            'verdict_success' => env('DOCUP_CLIENT_CERTIFICATE_VERDICT_SUCCESS', 'SUCCESS'),
        ],
    ],

    /*
    |---------------------------------------------------------------------------
    | Search (SPEC 8.16.1, ADR 0004)
    |---------------------------------------------------------------------------
    | MySQL FULLTEXT is the shipped default so that a default installation needs
    | no search service. Measured at 200k sections: 10 ms unfiltered, 80 ms with
    | the mandatory scope filter, because the WHERE defeats the early-LIMIT
    | optimisation and cost scales with match-set size rather than result limit.
    */
    'search' => [
        'driver' => env('DOCUP_SEARCH_DRIVER', 'mysql_fulltext'),
        'meilisearch_recommended_above_sections' => 200_000,

        /*
         * SPEC 8.16.1's optional engine. Absent by default, which is the whole
         * point of the default driver: a fresh installation needs no service.
         *
         * 🛑 The key is read from the environment and NEVER committed. SPEC
         * 8.12.21 forbids a search-engine token reaching a browser at all —
         * "Meilisearch tenant tokens are plain HS256 — readable by the browser
         * and unrevocable before expiry" — and DocUp mints none: SPEC 8.16.6
         * requires search to be proxied server-side, so the only key in the
         * system is this admin key and it stays in the application process.
         *
         * `url` is INSTALLATION configuration, in the same class as `DB_HOST`,
         * which is why it is not subject to SPEC 8.3.9's address policy —
         * `App\Egress\MeilisearchTransport` says so at length and takes a path
         * rather than a URL so that nothing can point it elsewhere.
         */
        'meilisearch' => [
            'url' => env('DOCUP_MEILISEARCH_URL'),
            'key' => env('DOCUP_MEILISEARCH_KEY'),
            'index' => env('DOCUP_MEILISEARCH_INDEX', 'docup_search'),
            'timeout_seconds' => (int) env('DOCUP_MEILISEARCH_TIMEOUT', 5),
        ],
    ],

    /*
    |---------------------------------------------------------------------------
    | Telemetry (SPEC 8.22.12)
    |---------------------------------------------------------------------------
    | 🛑 Off by default, opt-in, aggregate only, and it will never gate a feature.
    */
    /*
    |---------------------------------------------------------------------------
    | Documentation Content-Security-Policy (SPEC 8.14.15, SPEC 8.14.10)
    |---------------------------------------------------------------------------
    | 🛑 PERMISSIVE by default, and SPEC 8.14.15 states the reason rather than
    | leaving it to taste: "A strict CSP breaks Sphinx inline scripts, MathJax
    | and Mermaid; shipping it by default produces a flood of bug reports and
    | operators who disable CSP entirely."
    |
    | The default policy is three directives — `frame-ancestors` (SPEC 8.14.16's
    | per-project token), `base-uri` and `object-src` — and nothing else. Strict
    | mode adds SPEC 8.14.10's `img-src`/`font-src`/`connect-src` set, which
    | exists to kill CSS exfiltration.
    |
    | 🛑 That vector arrives with SPEC 8.14.9's per-project custom CSS, which
    | SPEC 18.22's pre-decided consequence says not to build and which Phase 27
    | did not build. So an installation that has not enabled custom CSS — every
    | installation today — gains nothing from strict mode and may lose a
    | generator's inlined font. Off is the honest default.
    |
    | 🛑 CSP `sandbox` is NEVER emitted on documentation, at any setting:
    | SPEC 8.14.15 forbids it because an opaque origin cannot read the `__Host-`
    | cookie SPEC 8.12.10's reader session depends on. There is no flag for it.
    */
    'csp' => [
        'documentation_strict' => env('DOCUP_CSP_DOCUMENTATION_STRICT', false),
    ],

    'telemetry' => [
        'enabled' => env('DOCUP_TELEMETRY', false),
        'advisory_check' => env('DOCUP_ADVISORY_CHECK', false),
    ],

    /*
    |---------------------------------------------------------------------------
    | Audit log (SPEC 8.22.1, SPEC 20.3)
    |---------------------------------------------------------------------------
    | 🛑 `k_audit` is held OUTSIDE `APP_KEY`, which §8.22.1 requires and which
    | is worth understanding rather than copying.
    |
    | `APP_KEY` decrypts provider secrets and session payloads, so the
    | application needs it constantly and it is the key most likely to be
    | rotated, escrowed, copied into a second environment, or pasted into a
    | support channel. An audit key must be harder to reach than that: whoever
    | holds it can forge a chain that verifies, which is the one thing the chain
    | exists to prevent. Separating them also means rotating `APP_KEY` — which
    | §15.2 has a documented procedure for — does not invalidate the audit log.
    |
    | Rotation is a real operation and needs its own design (old events must
    | stay verifiable), so it is deliberately absent here rather than
    | half-implemented: Phase 35 owns it alongside key escrow.
    */
    'audit' => [
        'key' => env('DOCUP_AUDIT_KEY'),

        // §20.3: 400 days default, 365 minimum, no maximum. 400 satisfies
        // PCI DSS 4.0.1 §10.5.1 and cannot drop below a year if the operator
        // claims it. The purge job and `retention:report` read this one value.
        'retention_days' => (int) env('DOCUP_AUDIT_RETENTION_DAYS', 400),

        // 🛑 §8.22.1's separate maintenance principal: partition management and
        // retention purging, with its credentials absent from the application
        // container. Named here because the append-only triggers must let it
        // purge while still refusing the application — see the migration that
        // creates them for why this is a trigger rather than a GRANT.
        'maintenance_user' => env('DOCUP_AUDIT_MAINTENANCE_USER', 'docup_maintenance'),
    ],

];
