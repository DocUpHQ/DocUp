#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 The DocUp contributors
# SPDX-License-Identifier: Apache-2.0
#
# 🛑 SPEC 18.18's permanent integration test, against a RUNNING edge.
#
# SPEC 8.9.8: "A permanent integration test MUST assert, on every driver in the
# CI matrix, that each header is present and not duplicated — allowing multiple
# `Vary` headers with DISTINCT values."
#
# tests/Feature/Serving/HandoffHeaderParityTest.php asserts that the application
# sets the headers and that deploy/nginx.conf names them. It cannot assert that a
# running nginx EMITS them, and that is the half that matters: SPEC 18.18's
# failure mode is "silent security degradation, not a visible error", and a
# configuration that fails to apply looks exactly like one that works.
#
# One script for both drivers, because the assertions are the driver-independent
# part. What differs is which stack is up, and that is the caller's business.
#
# 🛑 It runs OUTSIDE the containers, against a published port, because the two
# drivers differ in where a shell can live: the caddy-intercept image serves
# HTTP itself, while the nginx-accel application image is php-fpm and speaks no
# HTTP at all. Running curl inside the application container would therefore work
# for one driver and not the other, and the point of this script is that both get
# the same assertions.
#
# So seeding is delegated: SEED_CMD names however the caller reaches PHP.
#
# Usage:
#   deploy/verify-edge.sh <base-url> <docs-apex> <driver>
#
# Environment:
#   SEED_CMD  how to run deploy/seed-edge-fixture.php
#             (default: php deploy/seed-edge-fixture.php)
#
# Against the default caddy-intercept stack:
#   SEED_CMD='docker compose exec -T app php deploy/seed-edge-fixture.php' \
#     deploy/verify-edge.sh http://localhost:8080 docup-docs.localhost caddy-intercept
#
# Against the nginx-accel stack:
#   SEED_CMD='docker compose -f compose.nginx.yaml exec -T app php deploy/seed-edge-fixture.php' \
#     deploy/verify-edge.sh http://localhost:8081 docup-docs.localhost nginx-accel

set -euo pipefail

BASE="${1:?usage: verify-edge.sh <base-url> <docs-apex> <driver>}"
APEX="${2:?usage: verify-edge.sh <base-url> <docs-apex> <driver>}"
DRIVER="${3:?usage: verify-edge.sh <base-url> <docs-apex> <driver>}"

FAILURES=0

fail() {
    printf '  FAIL  %s\n' "$1" >&2
    FAILURES=$((FAILURES + 1))
}

pass() {
    printf '  ok    %s\n' "$1"
}

# Header values for one name, one per line, from a saved header dump. Folded to
# lowercase names because HTTP field names are case-insensitive and the two
# edges do not agree on their casing.
header_values() {
    local name="$1" file="$2"
    tr -d '\r' < "$file" \
        | awk -v n="$(printf '%s' "$name" | tr '[:upper:]' '[:lower:]')" \
            'BEGIN{IGNORECASE=1} index(tolower($0), n ":")==1 { sub(/^[^:]*:[ \t]*/, ""); print }'
}

header_count() {
    header_values "$1" "$2" | grep -c . || true
}

printf '\nSPEC 18.18 edge verification — driver=%s base=%s\n\n' "$DRIVER" "$BASE"

# --------------------------------------------------------------- the fixtures
SEED="$(${SEED_CMD:-php deploy/seed-edge-fixture.php})"

field() {
    printf '%s\n' "$SEED" | tr -d '\r' | sed -n "s/^$1=//p"
}

HOST="$(field host)"
PRIVATE_HOST="$(field private_host)"
PUBLIC_PATH="$(field public_path)"
TOKEN="$(field token)"
ARCHIVE="$(field archive)"
UPLOAD_PUBLIC="$(field upload_public)"
UPLOAD_PRIVATE="$(field upload_private)"

if [ -z "$HOST" ] || [ -z "$PRIVATE_HOST" ] || [ -z "$TOKEN" ]; then
    printf 'the fixture script printed no usable output; cannot continue\n' >&2
    printf '%s\n' "$SEED" >&2
    exit 1
fi

printf 'driver=%s host=%s private=%s\n\n' "$DRIVER" "$HOST" "$PRIVATE_HOST"

req() {
    local host="$1" path="$2" out="$3"
    shift 3
    curl -sS -D "$out" -o /dev/null -H "Host: ${host}" "$@" "${BASE}${path}"
}

# ------------------------------------------------------------- publish, over HTTP
#
# 🛑 Through the real API, not by calling the Publisher. Laravel's
# `UploadedFile(..., test: true)` bypasses PHP's upload machinery, so the whole
# Phase 03 suite exercised the ingestor without ever sending a multipart body —
# which is how `upload_max_filesize=2M` survived in the image while SPEC 8.21.6
# documented 1 GB. This is the step that found it.
#
# The archive lives wherever the seeding PHP wrote it, which for a containerised
# run is inside that container. `curl --form` needs it locally, so it is copied
# out through the same channel the seed came from when SEED_CMD is a docker exec.
if [ -n "${SEED_CMD:-}" ] && [ ! -f "$ARCHIVE" ]; then
    LOCAL_ARCHIVE="$(mktemp /tmp/docup-edge-XXXXXX.tar)"
    # Re-use SEED_CMD's prefix to read the file back out of the container.
    ${SEED_CMD% php*} sh -c "cat ${ARCHIVE}" > "$LOCAL_ARCHIVE"
    ARCHIVE="$LOCAL_ARCHIVE"
fi

if [ ! -f "$ARCHIVE" ]; then
    printf 'the fixture archive is not readable at %s\n' "$ARCHIVE" >&2
    exit 1
fi

for pair in "${HOST}|${UPLOAD_PUBLIC}" "${PRIVATE_HOST}|${UPLOAD_PRIVATE}"; do
    h="${pair%%|*}"
    u="${pair##*|}"

    code="$(curl -sS -o /tmp/edge-publish.json -w '%{http_code}' \
        -H "Host: ${h}" \
        -H "Authorization: Bearer ${TOKEN}" \
        -F "archive=@${ARCHIVE}" \
        "${BASE}${u}")"

    if [ "$code" = "201" ]; then
        pass "published to ${h} over HTTP (201)"
    else
        fail "publishing to ${h} returned ${code}: $(tr -d '\n' < /tmp/edge-publish.json | head -c 300)"
        printf '\ncannot verify headers without a published document\n' >&2
        exit 1
    fi
done

printf '\n'

# ------------------------------------------------- a public document, 200 ----
req "$HOST" "$PUBLIC_PATH" /tmp/edge-public.h

if ! grep -qiE '^HTTP/[0-9.]+ 200' /tmp/edge-public.h; then
    fail "a published document must serve 200 (got: $(head -1 /tmp/edge-public.h | tr -d '\r'))"
else
    pass 'a published document serves 200 through the edge'
fi

# 🛑 The whole point: every preserved header present, exactly once.
#
# Content-Encoding and Cache-Tag are conditional — one needs a sidecar, the
# other a publicly cacheable response — so they are asserted where they apply
# rather than here.
for h in Cache-Control CDN-Cache-Control Content-Type ETag X-Content-Type-Options; do
    n="$(header_count "$h" /tmp/edge-public.h)"

    if [ "$n" -eq 1 ]; then
        pass "${h} present exactly once"
    else
        fail "${h} appeared ${n} times (SPEC 8.9.8 requires exactly one)"
    fi
done

# 🛑 Vary may appear more than once, but only with DISTINCT values. Two
# identical values are a duplicate, not the semantic union SPEC 8.9.8 permits —
# which is a real bug this script found on caddy-intercept.
VARY_TOTAL="$(header_count Vary /tmp/edge-public.h)"
VARY_UNIQUE="$(header_values Vary /tmp/edge-public.h | tr ',' '\n' | sed 's/^ *//;s/ *$//' \
    | tr '[:upper:]' '[:lower:]' | grep -c . || true)"
VARY_DEDUPED="$(header_values Vary /tmp/edge-public.h | tr ',' '\n' | sed 's/^ *//;s/ *$//' \
    | tr '[:upper:]' '[:lower:]' | sort -u | grep -c . || true)"

if [ "$VARY_TOTAL" -ge 1 ] && [ "$VARY_UNIQUE" -eq "$VARY_DEDUPED" ]; then
    pass "Vary carries ${VARY_DEDUPED} distinct value(s) with no duplicate"
else
    fail "Vary repeats a value ($(header_values Vary /tmp/edge-public.h | tr '\n' '|'))"
fi

if header_values Vary /tmp/edge-public.h | grep -qi 'accept-encoding'; then
    pass 'Vary includes Accept-Encoding (SPEC 8.9.13)'
else
    fail 'Vary must include Accept-Encoding'
fi

# SPEC 9.3.3: a public response carries cache tags scoped to mount, project,
# version and build.
for scope in 'm-' 'p-' 'v-' 'b-'; do
    if header_values Cache-Tag /tmp/edge-public.h | grep -q -- "$scope"; then
        pass "Cache-Tag carries the ${scope} scope"
    else
        fail "Cache-Tag must carry a ${scope} scope (SPEC 9.3.3)"
    fi
done

# 🛑 The internal path must never reach the reader. SPEC 8.9.8 requires the
# handoff location to be externally unreachable, which is easier to keep true
# when nobody has been handed its address.
if header_count X-Accel-Redirect /tmp/edge-public.h | grep -q '^0$'; then
    pass 'X-Accel-Redirect is stripped before the reader sees it'
else
    fail 'X-Accel-Redirect leaked to the reader'
fi

# SPEC 8.9.8: the payoff. The edge's file server answers ranges, which is what
# proves the bytes never went through PHP.
if header_values Accept-Ranges /tmp/edge-public.h | grep -qi bytes; then
    pass 'Accept-Ranges: bytes — the edge is serving the file'
else
    fail 'Accept-Ranges must be bytes; the edge is not serving the file'
fi

# --------------------------------------- 🛑 a PRIVATE document, SPEC 9.3.2 ----
#
# The single most important assertion in this file. SPEC 18.18: without
# re-emission "a private document is served with no `private, no-store` and no
# `Vary: Cookie`: SPEC 9.3.2's failure arriving silently behind a correct-looking
# 200."
req "$PRIVATE_HOST" "$PUBLIC_PATH" /tmp/edge-private.h

for axis in Cache-Control CDN-Cache-Control; do
    v="$(header_values "$axis" /tmp/edge-private.h | tr '[:upper:]' '[:lower:]')"

    if printf '%s' "$v" | grep -q 'private' && printf '%s' "$v" | grep -q 'no-store'; then
        pass "${axis} is private, no-store on a non-public project"
    else
        fail "${axis} must be private and no-store, got: ${v:-<absent>}"
    fi

    if printf '%s' "$v" | grep -q 'public'; then
        fail "${axis} must not be public on a non-public project"
    fi
done

if header_values Vary /tmp/edge-private.h | grep -qi cookie; then
    pass 'Vary includes Cookie on a private response (SPEC 9.3.2)'
else
    fail 'Vary must include Cookie on a private response'
fi

# SPEC 9.3.2: "and never a cache tag". A tag is a purge handle, and a private
# response carrying one has told the CDN it is cacheable content worth tracking.
if [ "$(header_count Cache-Tag /tmp/edge-private.h)" -eq 0 ]; then
    pass 'a private response carries no cache tag'
else
    fail 'a private response must carry no Cache-Tag'
fi

# ------------------------------------------- SPEC 9.3.2 on the 304 path ------
#
# 🛑 The same private-response assertions again, on a conditional request.
# SPEC 8.9.9 makes 304 the COMMON case for a repeat reader, so this is the path
# most responses take — and it is the one where the headers are easiest to lose:
# nginx omits an `add_header` on a 304 unless it carries `always`, and a 304 for
# a private document with no `private, no-store` is the same leak as a 200 with
# none. A config that forgot `always` passes every check above and fails here.
ETAG="$(header_values ETag /tmp/edge-private.h | head -1 | tr -d "\r")"

if [ -z "$ETAG" ]; then
    fail 'a private response carries no ETag, so the 304 path cannot be checked'
else
    req "$PRIVATE_HOST" "$PUBLIC_PATH" /tmp/edge-304.h -H "If-None-Match: ${ETAG}"

    if grep -qiE '^HTTP/[0-9.]+ 304' /tmp/edge-304.h; then
        pass 'a repeat private request is 304 (SPEC 8.9.9)'

        for axis in Cache-Control CDN-Cache-Control; do
            v="$(header_values "$axis" /tmp/edge-304.h | tr '[:upper:]' '[:lower:]')"

            case "$v" in
                *private*no-store*|*no-store*private*)
                    pass "${axis} is still private, no-store on the 304" ;;
                *)
                    fail "${axis} on a 304 must be private, no-store (got: '${v}')" ;;
            esac
        done

        if header_values Vary /tmp/edge-304.h | grep -qi cookie; then
            pass 'Vary still includes Cookie on the 304'
        else
            fail "Vary on a 304 must include Cookie (got: $(header_values Vary /tmp/edge-304.h))"
        fi

        if [ "$(header_count Cache-Tag /tmp/edge-304.h)" -eq 0 ]; then
            pass 'the 304 carries no cache tag'
        else
            fail 'a private 304 must carry no Cache-Tag'
        fi
    else
        fail "a repeat private request must be 304 (got: $(head -1 /tmp/edge-304.h | tr -d '\r'))"
    fi
fi

# ----------------------------------------------- SPEC 8.9.6, before anything --
#
# The rejection must come from the application, through the edge, unchanged.
#
# 🛑 `--path-as-is` is mandatory and this check is worthless without it. curl
# resolves dot segments CLIENT-side by default, so the first version of this
# probe sent `/etc/passwd` and recorded the honest 404 as a failure to reject a
# traversal. Browsers normalise too — which is the whole reason SPEC 8.9.6
# exists: the requests that arrive non-canonical come from clients that do not,
# so this script has to behave like one of those.
#
# Four forms, because they fail different branches of the gate and an edge that
# normalised before PHP would pass the first and fail the rest.
for probe in \
    '/en/latest/../../etc/passwd' \
    '/en/latest/%2e%2e/%2e%2e/etc/passwd' \
    '/en/latest/..%2f..%2fetc/passwd' \
    '/en/latest/%2E%2E/etc/passwd'
do
    curl -sS --path-as-is -D /tmp/edge-traversal.h -o /dev/null \
        -H "Host: ${HOST}" "${BASE}${probe}"

    if grep -qiE '^HTTP/[0-9.]+ 400' /tmp/edge-traversal.h; then
        pass "400 at the edge: ${probe}"
    else
        fail "${probe} must be 400 (got: $(head -1 /tmp/edge-traversal.h | tr -d '\r'))"
    fi

    # 🛑 And the rejection must NAME its rule. SPEC 8.9.6 puts this gate ahead of
    # every cache lookup and resolution, and a 400 with no reason cannot be told
    # apart from a 400 that happened later for some other cause — which is the
    # difference between an auditable ordering and an assumed one.
    reason="$(header_values X-DocUp-Resolver /tmp/edge-traversal.h | tr -d '\r')"

    case "$reason" in
        path.*) pass "the rejection names its rule: ${reason}" ;;
        *)      fail "X-DocUp-Resolver must name a path rule (got: '${reason}')" ;;
    esac
done

# ------------------------------------------------- SPEC 8.9.3, the hard 404 ---
req "nothing.${APEX}" '/en/latest/' /tmp/edge-unknown.h

if grep -qiE '^HTTP/[0-9.]+ 404' /tmp/edge-unknown.h; then
    pass 'an unknown host is a hard 404 and serves no default project'
else
    fail "an unknown host must be 404 (got: $(head -1 /tmp/edge-unknown.h | tr -d '\r'))"
fi

# ----------------------------------------------------------------- the result
printf '\n'

if [ "$FAILURES" -gt 0 ]; then
    printf '%s: %d assertion(s) failed\n\n' "$DRIVER" "$FAILURES" >&2
    exit 1
fi

printf '%s: every SPEC 18.18 assertion passed\n\n' "$DRIVER"
