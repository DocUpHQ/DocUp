<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Egress;

use App\Egress\AddressGuard;
use App\Egress\EgressOptions;
use App\Egress\EgressRefused;
use App\Egress\EgressRejection;
use App\Egress\HardenedEgressClient;
use App\Egress\IpAddressClassifier;
use App\Egress\PinnedCurlTransport;
use Tests\Support\FakeDnsResolver;
use Tests\Support\LoopbackHttpServer;
use Tests\TestCase;

/**
 * §8.3.9's clauses, against a **running** origin.
 *
 * 🛑 Phase 04's §18.18 finding, applied: "a config asserted only against a
 * constant is a config nobody has run". Three of the clauses below are
 * claims about libcurl rather than about DocUp, and the only way to check a
 * claim about libcurl is to make a request:
 *
 *  - a 3xx is not followed (`CURLOPT_FOLLOWLOCATION`);
 *  - the transfer is aborted **mid-flight** at the cap, not buffered whole
 *    and then measured (`CURLOPT_WRITEFUNCTION`);
 *  - the connection goes to the pinned address rather than to whatever the
 *    system resolver would say (`CURLOPT_RESOLVE`).
 *
 * The last is proven by pinning a name that **does not resolve at all**. If
 * cURL were consulting the resolver the request could not complete, so a
 * successful response is the evidence.
 */
final class HardenedEgressClientTest extends TestCase
{
    private ?LoopbackHttpServer $server = null;

    protected function tearDown(): void
    {
        $this->server?->stop();
        $this->server = null;

        parent::tearDown();
    }

    /**
     * 🛑 The connection goes to the pinned address, and carries the original
     * name.
     *
     * `pinned.test` is not in DNS anywhere. The request succeeding is the
     * proof that the transport used the pin; the recorded `Host` header is
     * the proof that it did not rewrite the request to the literal address,
     * which would break virtual hosting and certificate validation alike.
     */
    public function test_it_connects_to_the_pinned_address_and_sends_the_original_host(): void
    {
        $this->server = (new LoopbackHttpServer(<<<'PHP'
            <?php
            header('Content-Type: text/plain');
            echo $_SERVER['HTTP_HOST'] ?? '';
            PHP))->start();

        $response = $this->client()->get($this->url('pinned.test', '/probe'));

        $this->assertSame(200, $response->status);
        $this->assertSame('pinned.test:'.$this->server->port(), $response->body);
        $this->assertSame('127.0.0.1', $response->pinnedAddress);
    }

    /**
     * 🛑 The §8.3.9 byte cap, aborted **mid-transfer**.
     *
     * The origin writes a marker file only after it has finished sending.
     * The client's cap is reached two chunks in, the connection drops, the
     * origin's next write fails and the script dies — so the marker is never
     * written. Asserting only on the exception would pass equally well
     * against a client that buffered 1 MB and then complained, which is the
     * implementation the cap exists to avoid.
     */
    public function test_it_aborts_a_response_that_exceeds_the_cap_rather_than_buffering_it(): void
    {
        $marker = tempnam(sys_get_temp_dir(), 'docup-egress-complete');
        unlink($marker);

        $this->server = (new LoopbackHttpServer(<<<PHP
            <?php
            header('Content-Type: application/octet-stream');

            for (\$i = 0; \$i < 64; \$i++) {
                echo str_repeat('x', 16384);
                flush();
                usleep(10000);
            }

            file_put_contents('{$marker}', 'completed');
            PHP))->start();

        try {
            $this->client(maxResponseBytes: 32768)->get($this->url('capped.test', '/big'));
            $this->fail('the oversized response was accepted');
        } catch (EgressRefused $refused) {
            $this->assertSame(EgressRejection::ResponseTooLarge, $refused->rejection);
        }

        $this->assertFileDoesNotExist(
            $marker,
            'the origin finished sending, so the transfer was buffered rather than aborted at the cap',
        );
    }

    /** §8.3.9's 5-second budget, as a ceiling on the whole transfer. */
    public function test_it_times_out(): void
    {
        $this->server = (new LoopbackHttpServer(<<<'PHP'
            <?php
            sleep(5);
            echo 'too late';
            PHP))->start();

        try {
            $this->client(timeoutSeconds: 1)->get($this->url('slow.test', '/slow'));
            $this->fail('the slow response was accepted');
        } catch (EgressRefused $refused) {
            $this->assertSame(EgressRejection::Timeout, $refused->rejection);
        }
    }

    /** A response under the cap is returned whole, headers included. */
    public function test_it_returns_a_bounded_response(): void
    {
        $this->server = (new LoopbackHttpServer(<<<'PHP'
            <?php
            header('Content-Type: application/json');
            header('X-Provider: gitea');
            echo json_encode(['id' => 42, 'full_name' => 'acme/docs']);
            PHP))->start();

        $response = $this->client()->get($this->url('api.test', '/repos/acme/docs'));

        $this->assertTrue($response->successful());
        $this->assertSame('gitea', $response->header('X-Provider'));
        $this->assertSame(['id' => 42, 'full_name' => 'acme/docs'], $response->json());
    }

    /**
     * The scheme allowlist, and the credential check that precedes it.
     *
     * 🛑 The ordering assertion matters: `ftp://user:token@host/` reports the
     * credential, not the scheme. Reporting the scheme would send the
     * operator to fix the wrong half of a line that has just put a token on
     * their clipboard.
     */
    public function test_it_refuses_a_disallowed_scheme_and_reports_a_credential_first(): void
    {
        $client = $this->client();

        foreach ([
            'file:///etc/passwd' => EgressRejection::SchemeNotAllowed,
            'gopher://example.com/x' => EgressRejection::SchemeNotAllowed,
            'ftp://user:token@example.com/x' => EgressRejection::CredentialsInUrl,
            'https://user:token@example.com/x' => EgressRejection::CredentialsInUrl,
            'not a url at all' => EgressRejection::MalformedUrl,
        ] as $url => $expected) {
            try {
                $client->get($url);
                $this->fail($url.' was accepted');
            } catch (EgressRefused $refused) {
                $this->assertSame($expected, $refused->rejection, $url.' produced the wrong identifier');
            }
        }
    }

    /** A header value containing a line break is header injection, not input. */
    public function test_it_refuses_an_injected_header(): void
    {
        $this->server = (new LoopbackHttpServer("<?php echo 'ok';"))->start();

        $this->expectException(\InvalidArgumentException::class);

        $this->client()->get($this->url('inject.test', '/x'), ['X-Thing' => "a\r\nX-Smuggled: b"]);
    }

    /**
     * A client reaching the loopback server, with the address policy stood
     * down — see {@see LoopbackHttpServer} for why that is test isolation
     * rather than a weakened gate.
     */
    private function client(int $timeoutSeconds = 5, int $maxResponseBytes = 262144): HardenedEgressClient
    {
        $port = (int) $this->server?->port();

        $resolver = (new FakeDnsResolver)
            ->stable('pinned.test', ['127.0.0.1'])
            ->stable('capped.test', ['127.0.0.1'])
            ->stable('slow.test', ['127.0.0.1'])
            ->stable('api.test', ['127.0.0.1'])
            ->stable('inject.test', ['127.0.0.1'])
            ->stable('example.com', ['93.184.216.34']);

        return new HardenedEgressClient(
            new AddressGuard($resolver, new IpAddressClassifier),
            new PinnedCurlTransport,
            new EgressOptions(
                allowedSchemes: ['http', 'https'],
                allowedPorts: $port === 0 ? [] : [$port],
                timeoutSeconds: $timeoutSeconds,
                maxResponseBytes: $maxResponseBytes,
                enforceAddressPolicy: false,
            ),
        );
    }

    private function url(string $host, string $path): string
    {
        return 'http://'.$host.':'.(int) $this->server?->port().$path;
    }
}
