#!/bin/sh
# SPDX-FileCopyrightText: 2026 The DocUp contributors
# SPDX-License-Identifier: Apache-2.0
#
# The SPEC 8.5.7 fetcher.
#
#   "`fetch` MUST run in a DocUp-authored image containing no repository code,
#    with credentials supplied only through a git credential helper reading a
#    file descriptor - never argv, never the remote URL, never the environment.
#    All user-defined hooks including `post_checkout` MUST run in the build
#    sandbox, never the fetcher."
#
# 🛑 The credential arrives on STDIN and nowhere else. That is the whole point
# of this file, and each of the three channels the specification forbids is
# forbidden for a reason an operator can check:
#
#   argv         /proc/<pid>/cmdline is world-readable on the host
#   environment  `docker inspect` returns Config.Env to anyone with the socket
#   the URL      every proxy, every `git remote -v`, every error message
#
# Stdin is none of those. It is written by the runner, read once here, and
# placed on a tmpfs that exits with the container.
#
# 🛑 This script runs NO repository code. It clones and it stops. post_checkout
# and every other hook run in the build sandbox, which has no credential -
# Read the Docs runs post_checkout here instead, and SPEC 8.5.7 says plainly
# that doing so "voids the entire credential separation".

set -eu

CLONE_URL="${1:?clone url}"
REF="${2:?ref}"
TARGET="${3:?target directory}"
# SPEC 8.4.1: configuration discovery runs relative to the component's
# source_path, not to the repository root. Empty means the root.
SOURCE_PATH="${4:-}"

CRED_FILE=/run/cred

# One read, always. The runner always opens stdin for this stage and always
# writes something - the credential, or nothing at all for a public repository
# - then closes. A conditional read would block for ever the first time
# somebody forgot the close.
cat > "$CRED_FILE" 2>/dev/null || : > "$CRED_FILE"
chmod 600 "$CRED_FILE"

# SPEC 8.3.4's git safety, restated here rather than inherited: this container
# has no global or system git configuration, and these flags are the only
# thing standing between a hostile URL and git's remote-helper machinery.
# `App\Source\GitSafety` produces the same set for the application side; the
# two are asserted equal by GitSafetyParityTest, because a divergence would
# mean the policy the application validates against is not the policy the
# fetcher enforces.
set -- \
    -c protocol.allow=never \
    -c protocol.https.allow=always \
    -c protocol.ssh.allow=always \
    -c protocol.file.allow=never \
    -c protocol.ext.allow=never \
    -c protocol.git.allow=never \
    -c protocol.http.allow=never \
    -c http.followRedirects=false \
    -c submodule.recurse=false \
    -c fetch.recurseSubmodules=false \
    -c core.hooksPath=/dev/null \
    -c core.symlinks=false \
    -c transfer.fsckObjects=true \
    -c fetch.fsckObjects=true \
    -c gc.auto=0 \
    -c core.askPass=

if [ -s "$CRED_FILE" ]; then
    # The helper reads a file on tmpfs. git opens it with a file descriptor,
    # which is what SPEC 8.5.7 asks for; the value is never an argument to
    # anything and never enters this shell's environment.
    set -- "$@" -c "credential.helper=!cat $CRED_FILE"
else
    # No credential: make sure git cannot fall back to asking anybody.
    set -- "$@" -c credential.helper=
fi

export GIT_TERMINAL_PROMPT=0
export GIT_ASKPASS=
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_SYSTEM=/dev/null
export GIT_ALLOW_PROTOCOL=https:ssh
export GIT_PROTOCOL_FROM_USER=0

mkdir -p "$TARGET"

# ADR 0010: `--depth=1 --single-branch` is what makes this cheap; the filter is
# near-free and becomes load-bearing the moment depth is lifted. Measured on
# all five providers, none of which silently ignored it.
git "$@" clone \
    --depth=1 \
    --single-branch \
    --branch "$REF" \
    --filter=blob:none \
    --no-tags \
    "$CLONE_URL" "$TARGET"

# 🛑 Gone before anything else runs. The build stage mounts the same volume,
# and /run is a separate tmpfs, but a credential that outlives its one use is
# a credential waiting for a mistake.
rm -f "$CRED_FILE"

# ADR 0010 / SPEC 18.14: the "filter honoured" flag. The failure this records
# is SILENT - a server without partial-clone support completes the clone
# perfectly and says nothing - so the evidence has to be read out of the
# clone's own configuration and carried back.
PROMISOR=$(git -C "$TARGET" config --get remote.origin.promisor 2>/dev/null || echo false)
FILTER=$(git -C "$TARGET" config --get remote.origin.partialclonefilter 2>/dev/null || echo "")
SHALLOW=$(git -C "$TARGET" rev-parse --is-shallow-repository)
SHA=$(git -C "$TARGET" rev-parse HEAD)
FILES=$(git -C "$TARGET" ls-files | wc -l | tr -d ' ')
BYTES=$(du -sb "$TARGET/.git" 2>/dev/null | cut -f1 || echo 0)

# SPEC 8.4.1's discovery order, relative to source_path. Reported rather than
# parsed: SPEC 8.4.9 requires configuration to be parsed "outside any sandbox
# under hard caps", and this container is the one place a repository's bytes
# and a credential have been in the same process. All it does is name the file
# and digest it; the worker decides what the contents mean.
#
# 🛑 The digest feeds SPEC 8.5.2's plan_digest, which decides whether a build
# runs at all. `mkdocs.yml` is in the fallback because in Phase 06 it is what
# actually determines the output - a config digest that ignored the generator's
# own configuration would short-circuit a rebuild after somebody edited it.
DISCOVERY_ROOT="$TARGET"
if [ -n "$SOURCE_PATH" ]; then
    DISCOVERY_ROOT="$TARGET/$SOURCE_PATH"
fi

CONFIG_FILE=""
for candidate in .docup.yaml .docup.yml .readthedocs.yaml .readthedocs.yml mkdocs.yml mkdocs.yaml; do
    if [ -f "$DISCOVERY_ROOT/$candidate" ]; then
        CONFIG_FILE="$candidate"
        break
    fi
done

MKDOCS_PRESENT=false
if [ -f "$DISCOVERY_ROOT/mkdocs.yml" ] || [ -f "$DISCOVERY_ROOT/mkdocs.yaml" ]; then
    MKDOCS_PRESENT=true
fi

if [ -n "$CONFIG_FILE" ]; then
    # SPEC 8.4.9's 256 KiB ceiling, applied before anything reads the file.
    CONFIG_BYTES=$(wc -c < "$DISCOVERY_ROOT/$CONFIG_FILE" | tr -d ' ')
    if [ "$CONFIG_BYTES" -gt 262144 ]; then
        CONFIG_DIGEST="oversize"
    else
        CONFIG_DIGEST=$(sha256sum "$DISCOVERY_ROOT/$CONFIG_FILE" | cut -d' ' -f1)
    fi
else
    CONFIG_DIGEST=$(printf '' | sha256sum | cut -d' ' -f1)
fi

cat > /workspace/fetch-result.json <<JSON
{
  "commit_sha": "$SHA",
  "filter_honoured": $( [ "$PROMISOR" = "true" ] && echo true || echo false ),
  "partial_clone_filter": "$FILTER",
  "shallow": $SHALLOW,
  "worktree_files": $FILES,
  "fetched_bytes": $BYTES,
  "config_found": $MKDOCS_PRESENT,
  "config_file": "$CONFIG_FILE",
  "config_digest": "$CONFIG_DIGEST"
}
JSON

# 🛑 The clone's own git metadata is removed before the build stage mounts the
# volume. A `.git` directory in the build sandbox is a credential cache
# waiting to be written to, a remote URL to exfiltrate to, and a way for
# repository code to learn things about the fetch it has no business knowing.
rm -rf "$TARGET/.git"
