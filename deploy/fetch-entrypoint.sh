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
#
# ---------------------------------------------------------------------------
# THREE MODES, and SPEC 8.4.11 is why there is more than one.
#
#   full      clone and check out, in one pass. What Phase 06 shipped, and
#             still what a build with no configuration file needs.
#   probe     clone with NO WORKING TREE, then read the four SPEC 8.4.1
#             candidate files and the file list straight out of the object
#             store. Cheap: `--filter=blob:none` means the blobs are not
#             fetched, so this costs the commit and the trees.
#   checkout  check out the clone `probe` left behind, applying the sparse
#             patterns the worker passed after parsing the configuration.
#
# 🛑 The split exists because SPEC 8.4.9 requires configuration to be parsed
# "outside any sandbox", which means in the worker - and SPEC 8.4.11's
# `sparse` key, which decides WHAT to check out, is inside the file being
# checked out. Probing first is the only ordering in which a declarative
# sparse key can take effect on the build that declares it, and it costs one
# extra container start rather than a second clone.

set -eu

MODE="${5:-full}"

CLONE_URL="${1:?clone url}"
REF="${2:?ref}"
TARGET="${3:?target directory}"
# SPEC 8.4.1: configuration discovery runs relative to the component's
# source_path, not to the repository root. Empty means the root.
SOURCE_PATH="${4:-}"

echo "docup-fetch: pass=${MODE} ref=${REF}" >&2

CRED_FILE=/run/cred
RESULT=/workspace/fetch-result.json
SPARSE_FILE=/tmp/docup-sparse

# SPEC 8.4.9's ceiling, applied to a candidate before anything reads it.
MAX_CONFIG_BYTES=262144

# SPEC 8.4.11's patterns, from the 6th argument onwards. Present only in
# `checkout` mode, and only when the configuration declared them.
#
# 🛑 Saved to a file BEFORE the git flags are built. The flags are assembled
# with `set --`, which replaces the positional parameters - so reading the
# patterns afterwards would read the flags instead, apply nothing, and
# (because SPEC 8.4.11 forbids a silent fall back) fail every sparse build
# with a message about sparse not narrowing anything.
: > "$SPARSE_FILE"

if [ "$#" -gt 5 ]; then
    shift 5

    for pattern in "$@"; do
        printf '%s\n' "$pattern" >> "$SPARSE_FILE"
    done
fi

# One read, always, in every mode. The runner always opens stdin for this
# stage and always writes something - the credential, or nothing at all for a
# public repository - then closes. A conditional read would block for ever the
# first time somebody forgot the close.
#
# 🛑 `checkout` needs the credential as much as `probe` does: the clone is
# `--filter=blob:none`, so materialising the working tree fetches blobs from
# the promisor remote, and on a private repository that is an authenticated
# request.
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

# The path prefix inside the tree, for `git show <ref>:<path>`. Empty at the
# repository root, where a leading slash would make git refuse the pathspec.
tree_prefix() {
    if [ -n "$SOURCE_PATH" ]; then
        printf '%s/' "$SOURCE_PATH"
    fi
}

# ---------------------------------------------------------------------------
# probe and full: the clone
# ---------------------------------------------------------------------------
if [ "$MODE" = "full" ] || [ "$MODE" = "probe" ]; then
    mkdir -p "$TARGET"

    # ADR 0010: `--depth=1 --single-branch` is what makes this cheap; the
    # filter is near-free and becomes load-bearing the moment depth is lifted.
    # Measured on all five providers, none of which silently ignored it.
    if [ "$MODE" = "probe" ]; then
        # 🛑 No working tree at all. The point of the probe is to read four
        # small files out of the object store before deciding which of the
        # other ten thousand to materialise (SPEC 8.4.11).
        git "$@" clone \
            --depth=1 \
            --single-branch \
            --branch "$REF" \
            --filter=blob:none \
            --no-tags \
            --no-checkout \
            --sparse \
            "$CLONE_URL" "$TARGET"
    else
        git "$@" clone \
            --depth=1 \
            --single-branch \
            --branch "$REF" \
            --filter=blob:none \
            --no-tags \
            "$CLONE_URL" "$TARGET"
    fi
fi

# ---------------------------------------------------------------------------
# checkout: materialise the tree the worker asked for
# ---------------------------------------------------------------------------
SPARSE_REQUESTED=false
SPARSE_APPLIED=false

if [ "$MODE" = "checkout" ]; then
    if [ -s "$SPARSE_FILE" ]; then
        SPARSE_REQUESTED=true

        # Cone mode: directory prefixes, which is what a monorepo narrowing
        # actually wants and what git can satisfy without evaluating a
        # pattern against every path in the index. `--stdin` rather than argv
        # because the patterns are repository-supplied and a pattern
        # beginning with a dash would otherwise be read as an option.
        git -C "$TARGET" sparse-checkout set --cone --stdin < "$SPARSE_FILE"
    else
        # 🛑 DISABLED, not left alone. The probe clones with `--sparse`,
        # which initialises a cone containing ONLY the repository root - so a
        # build that declared no `sparse` key would otherwise check out the
        # top-level files and nothing else. Measured in Phase 09: every
        # sub-path component built against an empty worktree and failed on a
        # missing configuration file, which reads exactly like the author's
        # mistake.
        git -C "$TARGET" sparse-checkout disable
    fi

    # 🛑 `reset --hard`, not `checkout "$REF"`. After `clone --no-checkout`
    # HEAD is ALREADY on the requested branch, so `git checkout master`
    # reports "Already on 'master'" and populates nothing - the build stage
    # then sees an empty worktree and the generator fails on a missing
    # configuration file, which looks exactly like an author's mistake.
    # `reset --hard` writes the index and the worktree from HEAD, honours the
    # sparse patterns set above, and fetches the missing blobs from the
    # promisor remote.
    git "$@" -C "$TARGET" reset --hard --quiet HEAD

    if [ "$SPARSE_REQUESTED" = "true" ]; then
        # 🛑 SPEC 8.4.11: "MUST fail loudly rather than silently falling back
        # to a full clone." git reports `core.sparseCheckout` and the skipped
        # entries, and BOTH are checked: the setting can be true while every
        # entry is still materialised, which is the exact silent failure the
        # requirement is about.
        if [ "$(git -C "$TARGET" config --get core.sparseCheckout 2>/dev/null || echo false)" = "true" ]; then
            # `S` marks an index entry git deliberately did NOT materialise.
            # One of those is the proof that the narrowing took effect.
            SKIPPED=$(git -C "$TARGET" ls-files -t | grep -c '^S ' || true)

            if [ "${SKIPPED:-0}" -gt 0 ]; then
                SPARSE_APPLIED=true
            fi
        fi

        if [ "$SPARSE_APPLIED" != "true" ]; then
            echo "docup-fetch: sparse checkout was requested and narrowed nothing" >&2
            exit 64
        fi

        # 🛑 ...and every requested path produced something.
        #
        # Cone mode ALWAYS materialises the repository root, so a mistyped
        # pattern narrows perfectly and leaves a worktree with the top-level
        # files and nothing else - which passes the check above and is not
        # what the author asked for. The build would then fail on a missing
        # configuration file, which reads as their mistake rather than as
        # their typo three lines up. Measured in Phase 09.
        while IFS= read -r pattern; do
            [ -n "$pattern" ] || continue

            if [ ! -e "$TARGET/$pattern" ]; then
                echo "docup-fetch: sparse path '$pattern' does not exist at this commit" >&2
                exit 64
            fi
        done < "$SPARSE_FILE"
    fi
fi

# ---------------------------------------------------------------------------
# the facts
# ---------------------------------------------------------------------------

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

# SPEC 8.4.1's discovery order, relative to source_path, read from the OBJECT
# STORE rather than from a working tree - `probe` has no working tree, and
# reading the same way in every mode means the four candidates are found at
# the same point in the same order whichever mode ran.
#
# 🛑 Named and digested here; NOT parsed. SPEC 8.4.9 requires configuration to
# be parsed "outside any sandbox under hard caps", and this container is the
# one place a repository's bytes and a credential have been in the same
# process. The worker decides what the contents mean.
PREFIX=$(tree_prefix)
CONFIG_FILE=""
CONFIG_B64=""
CONFIG_OVERSIZE=false

for candidate in .docup.yaml .docup.yml .readthedocs.yaml .readthedocs.yml; do
    if git -C "$TARGET" cat-file -e "HEAD:${PREFIX}${candidate}" 2>/dev/null; then
        CONFIG_FILE="$candidate"
        break
    fi
done

if [ -n "$CONFIG_FILE" ]; then
    CONFIG_BYTES=$(git -C "$TARGET" cat-file -s "HEAD:${PREFIX}${CONFIG_FILE}")

    if [ "$CONFIG_BYTES" -gt "$MAX_CONFIG_BYTES" ]; then
        # SPEC 8.4.9's 256 KiB ceiling, applied before the bytes are read into
        # anything. The worker turns this into `config.too_large`.
        CONFIG_OVERSIZE=true
        CONFIG_DIGEST="oversize"
    else
        git -C "$TARGET" cat-file blob "HEAD:${PREFIX}${CONFIG_FILE}" > /tmp/docup-config
        CONFIG_DIGEST=$(sha256sum /tmp/docup-config | cut -d' ' -f1)
        CONFIG_B64=$(base64 -w0 < /tmp/docup-config)
        rm -f /tmp/docup-config
    fi
else
    CONFIG_DIGEST=$(printf '' | sha256sum | cut -d' ' -f1)
fi

# The shallow file list a toolchain preset detects on and resolves its
# generator configuration from (SPEC 11.4). Three levels deep and 400 entries,
# because the deepest thing any shipped preset looks for is
# `docs/.vitepress/config.ts` - an unbounded listing of a monorepo would be
# megabytes of JSON for an answer that is four paths long.
FILE_LIST=$(git -C "$TARGET" ls-tree -r --name-only HEAD -- "${PREFIX}" 2>/dev/null \
    | if [ -n "$PREFIX" ]; then sed "s|^${PREFIX}||"; else cat; fi \
    | awk -F/ 'NF <= 3' \
    | head -n 400 \
    | sed 's/"/\\"/g' \
    | awk '{ printf "%s\"%s\"", (NR>1 ? "," : ""), $0 }')

cat > "$RESULT" <<JSON
{
  "mode": "$MODE",
  "commit_sha": "$SHA",
  "filter_honoured": $( [ "$PROMISOR" = "true" ] && echo true || echo false ),
  "partial_clone_filter": "$FILTER",
  "shallow": $SHALLOW,
  "worktree_files": $FILES,
  "fetched_bytes": $BYTES,
  "sparse_requested": $SPARSE_REQUESTED,
  "sparse_applied": $SPARSE_APPLIED,
  "config_found": $( [ -n "$CONFIG_FILE" ] && echo true || echo false ),
  "config_file": "$CONFIG_FILE",
  "config_oversize": $CONFIG_OVERSIZE,
  "config_digest": "$CONFIG_DIGEST",
  "config_b64": "$CONFIG_B64",
  "files": [$FILE_LIST]
}
JSON

# 🛑 The clone's own git metadata is removed before the build stage mounts the
# volume. A `.git` directory in the build sandbox is a credential cache
# waiting to be written to, a remote URL to exfiltrate to, and a way for
# repository code to learn things about the fetch it has no business knowing.
#
# Kept in `probe` mode, which is not an exception to that: the probe has no
# working tree for a build to be started from, and the `checkout` pass that
# follows removes it here before anything mounts the workspace.
if [ "$MODE" != "probe" ]; then
    rm -rf "$TARGET/.git"
fi

rm -f "$CRED_FILE" "$SPARSE_FILE"
