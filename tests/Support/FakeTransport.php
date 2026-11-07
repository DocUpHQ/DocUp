<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Support;

use App\Egress\EgressOptions;
use App\Egress\EgressResponse;
use App\Egress\Transport;

/**
 * A `Transport` that answers from a fixture instead of from the network.
 *
 * 🛑 **The seam is the transport, not the client.** `HardenedEgressClient` is
 * `final` and that is deliberate — §8.3.9 wants one of it, and a subclassable
 * one is a second one waiting to be written. {@see Transport} is the interface
 * it was given for exactly this: everything before the wire still runs, so a
 * test that stubs here still exercises the scheme allowlist, the
 * resolve-then-pin, the port policy and the redirect refusal.
 *
 * That matters more than convenience. A test that mocked the client would
 * assert that DocUp's OIDC code handles a JSON document; a test that stubs the
 * transport asserts that it does so *through the hardened path*, which is the
 * property §8.3.9 is about.
 */
final class FakeTransport implements Transport
{
    /** @var array<string, array{int, string, array<string, list<string>>}> */
    private array $answers = [];

    /** @var array<string, int> */
    private array $calls = [];

    /** @var list<array{method: string, url: string, body: ?string, headers: array<string, string>}> */
    public array $requests = [];

    /**
     * Answer this URL with a JSON body.
     *
     * @param  array<string, mixed>  $document
     */
    public function json(string $url, array $document, int $status = 200): self
    {
        return $this->raw($url, (string) json_encode($document), $status, ['content-type' => ['application/json']]);
    }

    /**
     * @param  array<string, list<string>>  $headers  one name may repeat, as in
     *                                                a real response
     */
    public function raw(string $url, string $body, int $status = 200, array $headers = []): self
    {
        $this->answers[$url] = [$status, $body, $headers];

        return $this;
    }

    /** How many times this URL was fetched. */
    public function callsFor(string $url): int
    {
        return $this->calls[$url] ?? 0;
    }

    /** The most recent request's body, for asserting what DocUp sent. */
    public function lastBody(): ?string
    {
        $last = end($this->requests);

        return $last === false ? null : $last['body'];
    }

    /** @param  array<string, string>  $headers */
    public function send(
        string $method,
        string $url,
        string $host,
        int $port,
        string $pinnedAddress,
        array $headers,
        EgressOptions $options,
        ?string $body = null,
    ): EgressResponse {
        $this->calls[$url] = ($this->calls[$url] ?? 0) + 1;
        $this->requests[] = ['method' => $method, 'url' => $url, 'body' => $body, 'headers' => $headers];

        /*
         * 🛑 An unstubbed URL is a 404 rather than an exception, because that
         * is what an unconfigured provider endpoint actually looks like — and a
         * test asserting DocUp's behaviour on a 404 should not have to catch a
         * test-double error to get one.
         */
        [$status, $answer, $responseHeaders] = $this->answers[$url] ?? [404, '', []];

        return new EgressResponse(
            status: $status,
            headers: $responseHeaders,
            body: $answer,
            pinnedAddress: $pinnedAddress,
        );
    }
}
