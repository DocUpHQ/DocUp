#!/bin/sh
# SPDX-FileCopyrightText: 2026 The DocUp contributors
# SPDX-License-Identifier: Apache-2.0
#
# §8.5.9's layer-3 backstop: "plus an nftables backstop inside the build
# network namespace so proxy bypass still fails at layer 3".
#
# 🛑 THE SHAPE IS THE WHOLE IDEA, so it is written down here rather than
# only in the runner.
#
# nftables needs CAP_NET_ADMIN. A build container has every capability
# dropped (§8.5.8) and must keep it that way, so the rules cannot be
# installed by the thing they constrain. Instead this container — the
# "warden" — is started first WITH CAP_NET_ADMIN, installs the ruleset into
# its own network namespace, and then does nothing for the rest of the
# build. The build container is started with `--network container:<warden>`,
# which puts it inside that already-locked namespace with no capabilities of
# its own. It inherits the rules and cannot reach the ruleset to change
# them: `nft` requires CAP_NET_ADMIN and it has none.
#
# Three things the backstop stops that the proxy alone does not:
#
#   1. a build that simply ignores http_proxy and opens a socket itself;
#   2. a build reaching ANOTHER BUILD on the same sandbox network — the
#      cross-tenant channel an `internal: true` network does not close,
#      because "internal" means no route off the host, not no route to a
#      sibling;
#   3. a build reaching 169.254.169.254, which no proxy ACL can be trusted
#      to be the only line against.
#
# Measured on Linux 5.15 (WSL2) before the design was committed to: with
# the ruleset installed, a joined `--cap-drop ALL` container resolved names
# through Docker's embedded resolver and reached the proxy, while a sibling
# container and the metadata endpoint were both unreachable.

set -eu

PROXY_IP="${DOCUP_PROXY_IP:-}"
PROXY_PORT="${DOCUP_PROXY_PORT:-3128}"
TTL="${DOCUP_WARDEN_TTL:-3600}"

case "$PROXY_IP" in
    '')
        # 🛑 No proxy means NO EGRESS, not open egress. §8.5.9's default is an
        # allowlist; a warden that could not be told where the proxy is would
        # otherwise fail open, which is the one failure mode this file exists
        # to prevent.
        PROXY_RULE=''
        ;;
    *[!0-9.]*)
        echo "docup-warden: DOCUP_PROXY_IP '$PROXY_IP' is not an IPv4 address" >&2
        exit 1
        ;;
    *)
        PROXY_RULE="ip daddr $PROXY_IP tcp dport $PROXY_PORT accept"
        ;;
esac

case "$PROXY_PORT" in
    ''|*[!0-9]*)
        echo "docup-warden: DOCUP_PROXY_PORT '$PROXY_PORT' is not a port" >&2
        exit 1
        ;;
esac

# 🛑 `policy drop` on both hooks, with the accepts enumerated. A ruleset
# written the other way round — accept by default, drop the known-bad — is
# the thing an attacker only has to find one gap in.
#
# `127.0.0.11` is Docker's embedded resolver. Name resolution has to work or
# every build fails at its first `pip install`, and the resolver is inside
# the namespace rather than on the network, so permitting it grants nothing
# the proxy would not also have to resolve.
#
# 🛑 The named counter is not instrumentation, it is evidence. A build that
# ignores http_proxy and opens a socket itself is dropped here — and from
# outside, that is indistinguishable from a dependency server being down:
# "Connection timed out" is what both look like. The runner reads this
# counter after a failed stage, so `user.egress_blocked_at_layer3` is a fact
# rather than a guess from the build's own wording (§8.5.15 wants a stable
# identifier, and an identifier inferred from prose is neither).
nft -f - <<EOF
table inet docup {
  counter blocked {
  }

  chain output {
    type filter hook output priority 0; policy drop;
    oifname "lo" accept
    ct state established,related accept
    ip daddr 127.0.0.11 accept
    $PROXY_RULE
    counter name "blocked" drop
  }

  chain input {
    type filter hook input priority 0; policy drop;
    iifname "lo" accept
    ct state established,related accept
  }

  chain forward {
    type filter hook forward priority 0; policy drop;
  }
}
EOF

echo "docup-warden: ruleset installed (proxy=${PROXY_IP:-none}:${PROXY_PORT})"
nft list ruleset

# 🛑 Holds the namespace open and nothing else. No shell loop, no network
# tool, no package manager: if the build container ever escaped into this
# one, `sleep` is the entire attack surface it would find. The TTL is the
# runner's backstop against a warden outliving its build.
exec sleep "$TTL"
