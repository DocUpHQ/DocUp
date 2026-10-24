#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 The DocUp contributors
# SPDX-License-Identifier: Apache-2.0
#
# SPEC 18.14's remaining half, measured: does SPARSE CHECKOUT work through the
# SPEC 8.5.9 CONNECT proxy, on all five providers, without silently falling
# back to a full checkout?
#
# ADR 0010 verified the clone filter and ADR 0011 verified the proxy; both
# recorded sparse checkout as "still unverified, and not claimed". This script
# is what settles it, and it runs the SHIPPED fetcher image with the SHIPPED
# entrypoint in the SHIPPED sandbox - not an approximation of them - because
# the question is whether DocUp's own two-pass fetch narrows a checkout, not
# whether git can.
#
# 🛑 The control is what makes the rows mean anything. For each provider the
# same repository is fetched twice: once with sparse patterns and once
# without. A sparse row that reported fewer files than its own control is a
# narrowing; a sparse row that matched its control is the silent fall back
# SPEC 8.4.11 forbids, and the fetcher is expected to have exited 64 before
# reaching that point.
#
#   ./deploy/verify-sparse.sh
#
# Needs: the `docup/fetch:1` image, the `docup_sandboxes` network and the
# egress proxy - i.e. a running `docker compose up`.

set -euo pipefail

NETWORK="${DOCUP_SANDBOX_NETWORK:-docup_sandboxes}"
IMAGE="${DOCUP_IMAGE_FETCH:-docup/fetch:1}"
WORKROOT="${DOCUP_VERIFY_ROOT:-/tmp/docup-sparse}"

PROXY=$(docker ps --filter 'label=docup.role=egress-proxy' --format '{{.Names}}' | head -n1)

if [ -z "$PROXY" ]; then
    echo "no egress proxy is running (label docup.role=egress-proxy)" >&2
    exit 1
fi

PROXY_URL="http://${PROXY}:${DOCUP_PROXY_PORT:-3128}"

# provider | clone url | ref | sparse directory
#
# 🛑 The directory has to EXIST at that ref, and two of these did not on the
# first run: neither `atlassian/aui` nor `forgejo/forgejo` has a top-level
# `docs/`. The fetcher refused both - which is the check working, because
# cone mode always materialises the repository root, so a mistyped pattern
# narrows beautifully and gives the build nothing it asked for.
CASES=$(cat <<'EOF'
GitHub|https://github.com/mkdocs/mkdocs|master|docs
GitLab|https://gitlab.com/gitlab-org/gitlab-runner.git|main|docs
Bitbucket|https://bitbucket.org/atlassian/aui|master|packages
Codeberg|https://codeberg.org/forgejo/forgejo|forgejo|contrib
Gitea|https://gitea.com/gitea/tea|main|docs
EOF
)

printf '| Provider | files (sparse) | files (control) | narrowed |\n'
printf '|---|---|---|---|\n'

run_fetch() {
    local name="$1" url="$2" ref="$3" mode="$4" sparse="$5"
    local dir="${WORKROOT}/${name}-${sparse:-full}"

    rm -rf "$dir"
    mkdir -p "$dir"
    chmod 0777 "$dir"

    # The probe, then the checkout: the same two passes the pipeline runs.
    for pass in probe checkout; do
        # shellcheck disable=SC2086
        docker run --rm \
            --network "$NETWORK" \
            --cap-drop ALL --security-opt no-new-privileges --read-only \
            --tmpfs /run:rw,noexec,nosuid,nodev,uid=10001,gid=10001,mode=0700,size=1m \
            --tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777 \
            --user 10001:10001 \
            -e "http_proxy=${PROXY_URL}" \
            -e "https_proxy=${PROXY_URL}" \
            -e "HTTP_PROXY=${PROXY_URL}" \
            -e "HTTPS_PROXY=${PROXY_URL}" \
            -v "$dir:/workspace" \
            "$IMAGE" "$url" "$ref" /workspace/source "" "$pass" $sparse \
            < /dev/null > "$dir/${pass}.log" 2>&1 || {
                echo "    ${name} ${pass} failed:" >&2
                tail -5 "$dir/${pass}.log" >&2
                echo "ERROR"
                return 0
            }
    done

    find "$dir/source" -type f ! -path '*/.git/*' | wc -l | tr -d ' '
}

echo "$CASES" | while IFS='|' read -r name url ref dir; do
    [ -n "$name" ] || continue

    sparse_count=$(run_fetch "$name" "$url" "$ref" checkout "$dir")
    control_count=$(run_fetch "$name" "$url" "$ref" checkout "")

    if [ "$sparse_count" = "ERROR" ] || [ "$control_count" = "ERROR" ]; then
        narrowed="REFUSED"
    elif [ "$sparse_count" -lt "$control_count" ]; then
        narrowed="yes"
    else
        narrowed="**NO**"
    fi

    printf '| %s | %s | %s | %s |\n' "$name" "$sparse_count" "$control_count" "$narrowed"
done
