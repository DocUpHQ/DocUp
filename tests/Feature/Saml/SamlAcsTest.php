<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Saml;

use App\Auth\OrganisationContext;
use App\Auth\Providers\Bindings;
use App\Auth\Providers\BindingState;
use App\Auth\Providers\Saml\SamlExchange;
use App\Auth\Providers\Saml\SamlRejection;
use App\Models\Domain;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\User;
use App\Support\Uuid;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Testing\TestResponse;
use Tests\Support\HostileSamlResponses;
use Tests\TestCase;

/**
 * 🛑 §17's Phase 25 exit criterion, through the real route.
 *
 * > "A stripped signature, a wrapped signature, a replayed assertion, a wrong
 * > audience, an expired `NotOnOrAfter`, a comment-truncation payload and an
 * > XXE payload are each rejected with **distinct audit events**."
 *
 * `ResponseValidatorTest` asserts the refusals as *exceptions*, which is where
 * the logic lives. This file asserts the same seven as **audit events raised by
 * an HTTP request**, which is what the criterion actually says — and the two are
 * not the same claim. A validator that threw correctly while the controller
 * swallowed the reason, recorded one shared action, or leaked the detail to the
 * reader would pass the first file and fail the requirement.
 *
 * 🛑 So every case here checks three things together: the reader gets §8.12.23's
 * `deny_status` **with no body**, the chain gets this rejection's **own**
 * action, and the exchange is **spent**.
 */
final class SamlAcsTest extends TestCase
{
    use DatabaseTransactions;

    private OrganisationContext $context;

    private Organisation $organisation;

    private Project $project;

    private Domain $domain;

    private string $bindingId;

    private HostileSamlResponses $idp;

    private const string CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

    protected function setUp(): void
    {
        parent::setUp();

        Cache::flush();

        $this->idp = new HostileSamlResponses;

        $this->context = app(OrganisationContext::class);
        $this->context->spanAllOrganisations();

        $this->organisation = Organisation::query()->create([
            'name' => 'ACS Co',
            'slug' => 'acs-'.bin2hex(random_bytes(4)),
        ]);

        $this->context->for($this->organisation->id);

        $this->project = Project::query()->create([
            'slug' => 'acs-'.bin2hex(random_bytes(3)),
            'name' => 'Guarded',
            'visibility' => 'members',
        ]);

        $domainId = Uuid::toBytes(Uuid::v7());

        DB::table('domains')->insert([
            'id' => $domainId,
            'organisation_id' => $this->organisation->id,
            'host' => 'acs-'.bin2hex(random_bytes(3)).'.example.test',
            'kind' => 'default_subdomain',
            'state' => 'active',
            'verified_at' => now(),
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        DB::table('domain_mounts')->insert([
            'id' => Uuid::toBytes(Uuid::v7()),
            'organisation_id' => $this->organisation->id,
            'domain_id' => $domainId,
            'project_id' => $this->project->id,
            'path_prefix' => '',
            'mode' => 'canonical',
            'mount_exposure' => 'inherit',
            'position' => 0,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $domain = $this->context->acrossAllOrganisations(
            static fn (): ?Domain => Domain::query()->whereKey($domainId)->first(),
        );

        $this->assertInstanceOf(Domain::class, $domain);

        $this->domain = $domain;

        $operator = User::query()->create([
            'name' => 'Operator',
            'email' => 'acs-'.bin2hex(random_bytes(4)).'@example.test',
            'password' => 'x',
        ]);

        $bindings = app(Bindings::class);

        $this->bindingId = $bindings->create(
            scopeType: 'project',
            scopeId: $this->project->id,
            type: 'saml',
            name: 'the idp',
            config: [
                'idp_entity_id' => HostileSamlResponses::ISSUER,
                'sso_url' => 'https://idp.example.test/realms/acme/protocol/saml',
                'certificate' => $this->idp->certificate(),
                'provisioning' => 'create_reader',
            ],
            organisationId: $this->organisation->id,
        );

        $bindings->transition($this->bindingId, BindingState::Verifying);
        $bindings->recordTestLogin($this->bindingId, $operator->id);

        /*
         * 🛑 §8.12.19: a binding authenticates nobody until it is `active`,
         * and reaching `active` needs **both** a recorded test login and a
         * passing probe. Omitting either produced a `saml.config_invalid`
         * refusal that reads like a bad certificate — the wrong diagnosis for
         * an inactive binding, and worth the comment.
         *
         * 🛑 The **real** probe runs here, not a stub, and it can: a SAML
         * probe makes no outbound request. Its trust anchor is the configured
         * certificate rather than a discovery document, so there is nothing to
         * fetch — which is why `OidcExchangeTest` needs a transport fake and
         * this does not.
         */
        $probe = $bindings->probe($this->bindingId);

        $this->assertTrue($probe->passed, 'the fixture certificate should probe clean: '.$probe->summary);

        $bindings->transition($this->bindingId, BindingState::Active);
    }

    protected function tearDown(): void
    {
        $this->context->forget();

        parent::tearDown();
    }

    // ------------------------------------------------- the flow that works

    /**
     * A signed, in-window, correctly addressed assertion mints a handoff code.
     *
     * 🛑 The positive case first, because every refusal below is only
     * meaningful if the same harness can produce an acceptance. A test file
     * where everything 404s passes whether the controller works or is a
     * `return 404`.
     */
    public function test_a_valid_assertion_mints_a_handoff_and_provisions_a_reader(): void
    {
        $opened = $this->open();

        $response = $this->acs($this->idp->valid($opened['request_id']), $opened['relay_state']);

        $this->assertSame(302, $response->getStatusCode());

        $location = (string) $response->headers->get('Location');

        $this->assertStringContainsString(
            $this->domain->host,
            $location,
            '🛑 §8.12.10: the return address comes from the verified domain row',
        );
        $this->assertStringContainsString('/_/auth/callback', $location);

        /* §8.12.1: keyed on the NameID, and the reader exists now. */
        $identity = DB::table('reader_identities')->where('binding_id', $this->bindingId)->first();

        $this->assertNotNull($identity, '🛑 §8.13.7: `create_reader` provisions on first login');

        $this->assertAudited(['saml.login.succeeded']);

        /* 🛑 And the handoff code names the reader identity, not a user. */
        $code = DB::table('reader_handoff_codes')
            ->where('reader_identity_id', $identity->id)
            ->first();

        $this->assertNotNull($code, '🛑 §8.12.1: the two principal populations are disjoint');
    }

    /**
     * 🛑 And no reader-visible detail, ever.
     *
     * §8.12.23 makes a failed login the project's `deny_status` with no body.
     * Asserted on the refusal every reader is most likely to provoke, because
     * the temptation to help is strongest exactly where a login is failing.
     */
    public function test_a_refusal_tells_the_reader_nothing(): void
    {
        $opened = $this->open();

        $response = $this->acs($this->idp->unsigned($opened['request_id']), $opened['relay_state']);

        $this->assertSame(404, $response->getStatusCode());
        $this->assertSame('', $response->getContent());
    }

    // ----------------------------------------- §17's seven, one test each

    /** `saml-001`: the signature stripped altogether. */
    public function test_a_stripped_signature_is_refused_with_its_own_event(): void
    {
        $this->assertRefusal(
            SamlRejection::SignatureMissing,
            fn (string $requestId): string => $this->idp->unsigned($requestId),
        );
    }

    /**
     * `saml-004`: a signature that verifies over an element DocUp is not about
     * to trust.
     *
     * 🛑 The fixture keeps the identity provider's real signature and points
     * the reference at a hidden copy, so the document *is* signed and the
     * signature *does* verify — which is why "is this document signed" is a
     * useless question and `SignatureVerifier` compares the covered node by
     * identity instead.
     */
    public function test_a_wrapped_signature_is_refused_with_its_own_event(): void
    {
        $this->assertRefusal(
            SamlRejection::SignatureWrapped,
            fn (string $requestId): string => $this->idp->signature_wrapping_reference($requestId),
        );
    }

    /** `saml-011`: the same assertion id a second time. */
    public function test_a_replayed_assertion_is_refused_with_its_own_event(): void
    {
        $first = $this->open();

        $this->assertSame(
            302,
            $this->acs($this->idp->valid($first['request_id']), $first['relay_state'])->getStatusCode(),
        );

        /*
         * 🛑 A **fresh exchange** for the replay, which is what makes this test
         * about the replay cache rather than about the `RelayState` latch. An
         * attacker who captured an assertion would start their own flow to get
         * a usable `RelayState`; the thing that stops them is DocUp remembering
         * the assertion id.
         */
        $second = $this->open();

        $replay = $this->idp->valid($second['request_id'], assertionId: 'assertion-1');

        $response = $this->acs($replay, $second['relay_state']);

        $this->assertSame(404, $response->getStatusCode());
        $this->assertAudited([SamlRejection::AssertionReplayed->auditAction()]);
    }

    /** `saml-007`: an assertion minted for another service provider. */
    public function test_a_wrong_audience_is_refused_with_its_own_event(): void
    {
        $this->assertRefusal(
            SamlRejection::AudienceMismatch,
            fn (string $requestId): string => $this->idp->wrong_audience($requestId),
        );
    }

    /** `saml-009`: `NotOnOrAfter` in the past, beyond the skew. */
    public function test_an_expired_window_is_refused_with_its_own_event(): void
    {
        $this->assertRefusal(
            SamlRejection::ConditionsExpired,
            fn (string $requestId): string => $this->idp->expired_notonorafter($requestId),
        );
    }

    /**
     * `saml-013`: CVE-2017-11427's comment truncation.
     *
     * The signed value and the value a first-text-node reader sees differ,
     * because canonicalisation strips the comment and a naive read does not.
     * DocUp refuses the value rather than normalising it: a value containing a
     * comment is not a value anybody meant to send.
     */
    public function test_a_comment_truncation_payload_is_refused_with_its_own_event(): void
    {
        $this->assertRefusal(
            SamlRejection::CommentInValueRefused,
            fn (string $requestId): string => $this->idp->comment_truncation($requestId),
        );
    }

    /**
     * `saml-014`: an external entity declaration.
     *
     * 🛑 §17 wants the payload to "provably never reach an entity-expanding
     * parser", which is why `SafeXml` refuses on the **bytes** before any
     * `DOMDocument` exists. Asserted here through the route so the proof covers
     * the path a real payload would take.
     */
    public function test_an_xxe_payload_is_refused_with_its_own_event(): void
    {
        $this->assertRefusal(
            SamlRejection::EntityDeclarationRefused,
            fn (string $requestId): string => $this->idp->xxe_external_entity($requestId),
        );
    }

    /** And the billion-laughs variant, which needs no external entity at all. */
    public function test_an_entity_expansion_payload_is_refused_with_its_own_event(): void
    {
        $this->assertRefusal(
            SamlRejection::EntityDeclarationRefused,
            fn (string $requestId): string => $this->idp->xxe_billion_laughs($requestId),
        );
    }

    // --------------------------------------- the controller's own refusals

    /**
     * 🛑 §8.12.18's "IdP-initiated off by default", at the route.
     *
     * An unsolicited response carries no `InResponseTo`, so it cannot match a
     * stored request id — which is how the requirement is met without a flag.
     * It still needs a `RelayState` to get as far as being judged, which is
     * itself the point: an identity provider cannot start a login DocUp did not
     * ask for, because it has no `RelayState` to send.
     */
    public function test_an_idp_initiated_response_is_refused(): void
    {
        $opened = $this->open();

        $response = $this->acs($this->idp->idp_initiated(), $opened['relay_state']);

        $this->assertSame(404, $response->getStatusCode());
        $this->assertAudited([SamlRejection::InResponseToUnknown->auditAction()]);
    }

    /**
     * 🛑 A forged `RelayState` resolves nothing, and costs no XML parsing.
     *
     * The ordering matters: the exchange is consumed before the document is
     * looked at, so a replayed or invented POST is one indexed read. A
     * controller that parsed first would let anybody make DocUp do the
     * expensive half.
     */
    public function test_a_forged_relay_state_is_refused(): void
    {
        $response = $this->acs($this->idp->valid('whatever'), 'not-a-relay-state-docup-issued');

        $this->assertSame(404, $response->getStatusCode());
        $this->assertAudited([SamlRejection::RelayStateUnknown->auditAction()]);
    }

    /**
     * 🛑 A `RelayState` from one exchange cannot carry another's assertion.
     *
     * The stored row holds the binding, the domain, the project *and* the
     * request id, so an assertion answering exchange A presented with exchange
     * B's `RelayState` fails `InResponseTo`. That is §8.12.10's "an index into
     * verified state, never the URL itself" applied in the other direction.
     */
    public function test_an_assertion_cannot_be_moved_between_exchanges(): void
    {
        $first = $this->open();
        $second = $this->open();

        $response = $this->acs($this->idp->valid($first['request_id']), $second['relay_state']);

        $this->assertSame(404, $response->getStatusCode());
        $this->assertAudited([SamlRejection::InResponseToUnknown->auditAction()]);
    }

    /**
     * 🛑 A second POST of the same response is refused by the latch.
     *
     * Which is what the HTTP-POST binding's back button produces, so it is an
     * ordinary thing rather than an attack — but it is refused all the same,
     * because distinguishing a browser's re-POST from a capture is not
     * something the request carries enough information to do.
     */
    public function test_the_same_response_cannot_be_posted_twice(): void
    {
        $opened = $this->open();
        $xml = $this->idp->valid($opened['request_id']);

        $this->assertSame(302, $this->acs($xml, $opened['relay_state'])->getStatusCode());

        $response = $this->acs($xml, $opened['relay_state']);

        $this->assertSame(404, $response->getStatusCode());
        $this->assertAudited([SamlRejection::RelayStateExpired->auditAction()]);
    }

    /**
     * 🛑 A POST missing either field raises **no** audit event.
     *
     * A crawler, a stale bookmark or a provider configured for the wrong
     * binding is not a security event, and an operator reading a burst of
     * `saml.*.refused` needs them all to mean something went wrong.
     */
    public function test_an_empty_post_is_a_plain_404_with_no_event(): void
    {
        $before = DB::table('audit_events')->count();

        $this->assertSame(404, $this->post('/_/auth/saml/acs', [])->getStatusCode());

        $this->assertSame(
            $before,
            DB::table('audit_events')->count(),
            '🛑 a malformed POST is noise, not an event',
        );
    }

    /**
     * 🛑 The ACS accepts a cross-origin POST with no CSRF token, by design.
     *
     * Asserted because it is a deliberate exemption and therefore the kind of
     * thing a later change could remove without anybody noticing until SAML
     * stopped working. §8.12.18's `InResponseTo` is the control that replaces
     * the token, and the test above proves it binds.
     */
    public function test_the_acs_does_not_require_a_csrf_token(): void
    {
        $opened = $this->open();

        /*
         * `post()` without `withoutMiddleware`, so the real middleware stack
         * runs — including the CSRF check this route opts out of.
         */
        $response = $this->post('/_/auth/saml/acs', [
            'SAMLResponse' => base64_encode($this->idp->valid($opened['request_id'])),
            'RelayState' => $opened['relay_state'],
        ]);

        $this->assertNotSame(
            419,
            $response->getStatusCode(),
            '🛑 a CSRF refusal here would break every genuine SAML login',
        );
        $this->assertSame(302, $response->getStatusCode());
    }

    // ---------------------------------------------------------- fixtures

    /**
     * Open an exchange the way the start leg does, and hand back both halves.
     *
     * 🛑 The request id is read from the row rather than returned by `open()`,
     * which is the one liberty this harness takes: a real reader never sees it.
     * It is stored in the clear precisely so the validator can compare against
     * it, so reading it here is reading what the controller reads.
     *
     * @return array{relay_state: string, request_id: string}
     */
    private function open(): array
    {
        $requestId = '_'.bin2hex(random_bytes(16));

        $relayState = app(SamlExchange::class)->open(
            organisationId: (string) $this->organisation->id,
            bindingId: $this->bindingId,
            domainId: $this->domain->id,
            projectId: $this->project->id,
            requestId: $requestId,
            handoffChallenge: self::CHALLENGE,
            returnPath: '/',
        );

        return ['relay_state' => $relayState, 'request_id' => $requestId];
    }

    /**
     * POST a response to the real ACS route, as an identity provider's
     * auto-submitting form would.
     */
    private function acs(string $xml, string $relayState): TestResponse
    {
        $request = Request::create(
            'https://'.$this->dashboard().'/_/auth/saml/acs',
            'POST',
            ['SAMLResponse' => base64_encode($xml), 'RelayState' => $relayState],
            [],
            [],
            ['REMOTE_ADDR' => '127.0.0.1'],
        );

        return TestResponse::fromBaseResponse($this->app->handle($request));
    }

    /**
     * One refusal: a 404 with no body, its own audit action, and a spent
     * exchange.
     *
     * 🛑 All three, because §17's criterion is about what an operator can see
     * and what a reader cannot. Any one of them alone would pass while the
     * requirement failed.
     *
     * @param  callable(string): string  $build  the response, given a request id
     */
    private function assertRefusal(SamlRejection $expected, callable $build): void
    {
        $opened = $this->open();

        $response = $this->acs($build($opened['request_id']), $opened['relay_state']);

        $this->assertSame(404, $response->getStatusCode(), '🛑 §8.12.23: the project deny status');
        $this->assertSame('', $response->getContent(), '🛑 §8.12.23: and no detail');

        $this->assertAudited([$expected->auditAction()]);

        $this->assertNotNull(
            DB::table('saml_auth_requests')
                ->where('binding_id', $this->bindingId)
                ->whereNotNull('consumed_at')
                ->first(),
            '🛑 a refused response still spends its exchange',
        );
    }

    /**
     * 🛑 §17's "distinct audit events", asserted against the chain.
     *
     * Scoped to the most recent events rather than the whole table, because the
     * table is shared with everything else that has run — and asserted by
     * intersection rather than by equality, because one request legitimately
     * raises more than one event.
     *
     * @param  list<string>  $wanted
     */
    private function assertAudited(array $wanted): void
    {
        $actions = [];

        foreach (DB::table('audit_events')->orderByDesc('occurred_at')->limit(20)->get(['action']) as $row) {
            $actions[] = (string) $row->action;
        }

        $this->assertNotEmpty(
            array_intersect($wanted, $actions),
            '🛑 §17: the outcome must raise its own audit event; wanted one of '
                .implode(', ', $wanted).' and the chain holds '.implode(', ', $actions),
        );
    }

    /**
     * 🛑 Read, never set. Route host constraints are compiled before `setUp`
     * runs, so overriding `docup.origins.app` would move the URLs the
     * application *builds* and not the ones it *matches* — the trap
     * `TwoRealmLoginTest` records. The fixtures' `Destination` and `Audience`
     * are built from the same config, so reading it keeps all three in step.
     */
    private function dashboard(): string
    {
        $host = config('docup.origins.app');

        return is_string($host) && $host !== '' ? $host : 'docup.localhost';
    }
}
