<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Egress;

/**
 * cURL, configured so that none of its defaults can undo §8.3.9.
 *
 * 🛑 **Why raw cURL and not Guzzle or the `Http` facade.** Guzzle's
 * `allow_redirects` default is **on**. The single most important behaviour in
 * this file — that a 3xx is a refusal and never a second request — would then
 * be one forgotten option away from being untrue, in a dependency whose
 * defaults change between majors. §8.3.9 asks for one class that is the sole
 * call site; making that class own the handle outright means the unsafe
 * defaults are never in play, rather than being overridden somewhere a later
 * refactor can drop them.
 *
 * Every option below either implements a clause of §8.3.9 or closes a way of
 * getting round one, and each says which.
 */
final class PinnedCurlTransport implements Transport
{
    /**
     * Cap on response headers, independent of the body cap.
     *
     * A server that never sends a body can still send headers forever, and
     * `CURLOPT_WRITEFUNCTION` never fires for them. 8 KiB is generous for an
     * API response and small enough that the attack is not worth mounting.
     */
    private const MAX_HEADER_BYTES = 8192;

    public function send(
        string $method,
        string $url,
        string $host,
        int $port,
        string $pinnedAddress,
        array $headers,
        EgressOptions $options,
    ): EgressResponse {
        $handle = curl_init();

        if ($handle === false) {
            throw new EgressRefused(EgressRejection::TransportFailure, $host);
        }

        $body = '';
        $headerBytes = 0;
        $rawHeaders = [];
        $exceededBody = false;
        $exceededHeaders = false;

        curl_setopt_array($handle, [
            CURLOPT_URL => $url,
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_NOBODY => $method === 'HEAD',

            /*
             * 🛑 §8.3.9 resolve-then-pin. The URL keeps the hostname — so
             * `Host`, SNI and certificate verification all use the real name —
             * while the connection goes to the address AddressGuard already
             * classified. Passing the IP in the URL instead would break
             * certificate validation and virtual hosting; passing the hostname
             * with no pin would let the resolver answer a second time, which
             * is the window the guard exists to close.
             */
            CURLOPT_RESOLVE => [$host.':'.$port.':'.$pinnedAddress],

            /*
             * 🛑 §8.3.9 "disabled redirects". Belt and braces: the client
             * refuses a 3xx on its own, and cURL is told it may not follow one
             * even if that check were ever removed. The empty redirect
             * protocol set makes a followed redirect impossible rather than
             * merely unconfigured.
             */
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_MAXREDIRS => 0,

            // §8.3.9 scheme allowlist, enforced by libcurl as well as by us,
            // so a scheme smuggled past the parser still cannot be spoken.
            ...$this->protocolOptions($options),

            // §8.3.9's 5-second budget, as a wall-clock ceiling on the whole
            // transfer. A per-read timeout would let a slow-drip server hold
            // a worker open indefinitely while never technically stalling.
            CURLOPT_TIMEOUT => $options->timeoutSeconds,
            CURLOPT_CONNECTTIMEOUT => $options->timeoutSeconds,
            CURLOPT_NOSIGNAL => true,

            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,

            /*
             * A reused connection was pinned by whichever request opened it.
             * Reuse would mean a later request to the same host travelling to
             * an address this request never validated.
             */
            CURLOPT_FRESH_CONNECT => true,
            CURLOPT_FORBID_REUSE => true,

            // Never: these are the two options that would put a credential on
            // the wire or in a log without the vault being involved.
            CURLOPT_HTTPAUTH => CURLAUTH_NONE,
            CURLOPT_UNRESTRICTED_AUTH => false,
            CURLOPT_VERBOSE => false,

            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => $this->formatHeaders($headers),

            /*
             * 🛑 §8.3.9's 256 KiB cap, enforced **mid-transfer**. Checking the
             * length after the fact is not a cap: by then the bytes are in the
             * worker's memory, which is the resource the cap protects.
             * `CURLOPT_MAXFILESIZE` is not a substitute either — it trusts
             * `Content-Length`, and a hostile server simply omits it.
             */
            CURLOPT_WRITEFUNCTION => function (\CurlHandle $_, string $chunk) use (&$body, &$exceededBody, $options): int {
                if (strlen($body) + strlen($chunk) > $options->maxResponseBytes) {
                    $exceededBody = true;

                    return 0;   // anything short of the chunk length aborts the transfer
                }

                $body .= $chunk;

                return strlen($chunk);
            },

            CURLOPT_HEADERFUNCTION => function (\CurlHandle $_, string $line) use (&$rawHeaders, &$headerBytes, &$exceededHeaders): int {
                $headerBytes += strlen($line);

                if ($headerBytes > self::MAX_HEADER_BYTES) {
                    $exceededHeaders = true;

                    return 0;
                }

                $rawHeaders[] = $line;

                return strlen($line);
            },
        ]);

        $ok = curl_exec($handle);
        $errno = curl_errno($handle);
        $status = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
        curl_close($handle);

        if ($exceededBody || $exceededHeaders) {
            throw new EgressRefused(EgressRejection::ResponseTooLarge, $host, ['pinned' => $pinnedAddress]);
        }

        if ($errno === CURLE_OPERATION_TIMEOUTED) {
            throw new EgressRefused(EgressRejection::Timeout, $host, ['pinned' => $pinnedAddress]);
        }

        if ($ok === false || $errno !== CURLE_OK || $status === 0) {
            /*
             * The cURL error number travels; the error *string* does not. It
             * embeds the effective URL, and §8.3.3 does not want a URL in a log
             * line we cannot see the contents of in advance.
             */
            throw new EgressRefused(EgressRejection::TransportFailure, $host, [
                'curl_errno' => $errno,
                'pinned' => $pinnedAddress,
            ]);
        }

        return new EgressResponse($status, $this->parseHeaders($rawHeaders), $body, $pinnedAddress);
    }

    /**
     * Restrict libcurl to the allowed schemes, and forbid every redirect
     * protocol outright.
     *
     * `CURLOPT_PROTOCOLS_STR` supersedes the integer bitmask and is what
     * libcurl 7.85+ wants; the bitmask is kept for older builds so this file
     * does not silently apply no restriction at all on one of them.
     *
     * @return array<int, int|string>
     */
    private function protocolOptions(EgressOptions $options): array
    {
        if (defined('CURLOPT_PROTOCOLS_STR')) {
            return [
                CURLOPT_PROTOCOLS_STR => implode(',', $options->allowedSchemes),
                CURLOPT_REDIR_PROTOCOLS_STR => '',
            ];
        }

        $mask = 0;

        foreach ($options->allowedSchemes as $scheme) {
            $mask |= match (strtolower($scheme)) {
                'https' => CURLPROTO_HTTPS,
                'http' => CURLPROTO_HTTP,
                default => 0,
            };
        }

        return [CURLOPT_PROTOCOLS => $mask, CURLOPT_REDIR_PROTOCOLS => 0];
    }

    /**
     * @param  array<string, string>  $headers
     * @return list<string>
     */
    private function formatHeaders(array $headers): array
    {
        $formatted = [];

        foreach ($headers as $name => $value) {
            // A newline in either half is header injection; there is no
            // legitimate caller, so this is a programming error, not input.
            if (preg_match('/[\r\n]/', $name.$value) === 1) {
                throw new \InvalidArgumentException('header name or value contains a line break');
            }

            $formatted[] = $name.': '.$value;
        }

        return $formatted;
    }

    /**
     * @param  list<string>  $lines
     * @return array<string, list<string>>
     */
    private function parseHeaders(array $lines): array
    {
        $headers = [];

        foreach ($lines as $line) {
            $position = strpos($line, ':');

            if ($position === false) {
                continue;   // the status line, and the blank line that ends the block
            }

            $name = strtolower(trim(substr($line, 0, $position)));
            $headers[$name][] = trim(substr($line, $position + 1));
        }

        return $headers;
    }
}
