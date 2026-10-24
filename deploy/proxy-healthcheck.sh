#!/bin/sh
# SPDX-FileCopyrightText: 2026 The DocUp contributors
# SPDX-License-Identifier: Apache-2.0
#
# 🛑 The healthcheck asks whether the POLICY is in force, not whether the
# port answers.
#
# A proxy whose allowlist failed to render — or rendered empty, or rendered
# permissive — still accepts connections on 3128 and still looks perfectly
# healthy to a port probe. What distinguishes a working §8.5.9 proxy from a
# broken one is that it **refuses** a host nobody allowlisted, so that is
# what is checked. `example.invalid` is in a TLD reserved by RFC 2606 and
# can never be registered, so this check can never become a real request.
#
# A script rather than a `CMD-SHELL` one-liner in compose, because the
# request needs CRLF and YAML's double-quoted scalars eat `\r\n` as escapes
# of their own — the first version of this check sent a malformed request
# line and reported the proxy permanently unhealthy while it was working.

set -eu

PORT="${DOCUP_PROXY_PORT:-3128}"

printf 'CONNECT example.invalid:443 HTTP/1.1\r\nHost: example.invalid:443\r\n\r\n' \
    | nc -w 5 127.0.0.1 "$PORT" \
    | head -n 1 \
    | grep -q '403'
