#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 The DocUp contributors
# SPDX-License-Identifier: Apache-2.0
#
# ------------------------------------------------------------------------------
# Trust the test certificate authority, for the TLS integration suite.
# ------------------------------------------------------------------------------
#
# Phase 19's exit criteria include "an internal ACME directory issues for an
# air-gapped name" and SPEC 18.17's "the edge … falls back to on-demand ACME on
# a negative answer". Both need a certificate authority the stack can really
# talk to, which means the application and the proxy have to trust it.
#
# 🛑 TWO DIFFERENT CERTIFICATES, AND CONFLATING THEM WASTES AN AFTERNOON.
#
#   - `pebble.minica.pem` signs Pebble's **own server certificate**, the one
#     presented at https://pebble:14000/dir. Trusting it is what lets
#     HardenedEgressClient talk to the directory with CURLOPT_SSL_VERIFYPEER
#     still on. It is baked into the image, so it is copied out with
#     `docker compose cp` — a file copy, no TLS, nothing to verify.
#
#   - `roots/0` is the **issuance root**, regenerated on every Pebble start.
#     Trusting it is what lets a client verify a certificate Pebble ISSUED. It
#     exists only in the running process, so it is fetched over the management
#     API — verified against minica, which the previous step just installed.
#
# Neither is fetched with verification disabled. That matters: a setup script
# that reached for `-k` would be teaching the suite the habit the thing under
# test exists to prevent.
#
# Usage: deploy/tls-test-setup.sh [compose args...]
set -euo pipefail

COMPOSE=(docker compose -f compose.yaml -f compose.tls.yaml)
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "==> waiting for pebble"
for _ in $(seq 1 60); do
  if "${COMPOSE[@]}" ps pebble --format '{{.Health}}' 2>/dev/null | grep -q healthy; then
    break
  fi
  sleep 2
done

echo "==> copying pebble's own CA out of the image"
"${COMPOSE[@]}" cp pebble:/test/certs/pebble.minica.pem "$WORK/pebble.minica.pem"

echo "==> installing it in the app container"
"${COMPOSE[@]}" cp "$WORK/pebble.minica.pem" app:/usr/local/share/ca-certificates/pebble-minica.crt
"${COMPOSE[@]}" exec -T app update-ca-certificates

echo "==> fetching the issuance root, verified against that CA"
"${COMPOSE[@]}" exec -T app sh -c \
  'curl -fsS --cacert /usr/local/share/ca-certificates/pebble-minica.crt https://pebble:15000/roots/0 > /tmp/pebble-root.pem'

"${COMPOSE[@]}" exec -T app sh -c \
  'cp /tmp/pebble-root.pem /usr/local/share/ca-certificates/pebble-root.crt && update-ca-certificates'

echo "==> verifying the directory is reachable with verification ON"
"${COMPOSE[@]}" exec -T app curl -fsS -o /dev/null https://pebble:14000/dir

# 🛑 Pebble is NOT declared in deploy/internal-destinations.conf here, and
# that is deliberate. It resolves to a private address, so reaching it needs
# the §8.10.14 carve-out — but the shipped file must stay empty, and
# `EgressConfigurationTest::test_the_shipped_destination_file_declares_nothing`
# asserts that it does. A setup script that edited the committed allowlist
# would make the shipped default wrong in order to test something else.
#
# `AcmeIssuanceTest::setUp()` sets the config value instead. Everything below
# it is the real path: the real parse, the real AddressGuard, the real client.

echo "==> done"
