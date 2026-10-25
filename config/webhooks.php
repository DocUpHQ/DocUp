<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

/*
|---------------------------------------------------------------------------
| Incoming webhooks (§8.19.3, §8.5.4)
|---------------------------------------------------------------------------
|
| 🛑 §8.19.3: "An **unsigned** generic webhook endpoint MUST NOT exist."
| There is deliberately no flag here that would create one. If you are
| looking for the setting that turns off signature verification so a `curl`
| can trigger a build, it does not exist and will not be added: Read the Docs
| ships one and it is a build-trigger oracle.
*/

return [

    /*
    |-----------------------------------------------------------------------
    | Body cap
    |-----------------------------------------------------------------------
    |
    | 🛑 Applied to the RAW BYTES before anything parses them, exactly as
    | §8.4.9 does for `.docup.yaml`. A monorepo push with 3,000 commits is a
    | large payload from a legitimate provider, so the cap is generous; what
    | it refuses is the unbounded one. GitHub's own documented ceiling is
    | 25 MB, and the rest sit below it.
    |
    | The HMAC is computed over the body, so a body we refuse to read is a
    | body we cannot verify — the cap therefore answers 401 like every other
    | verification failure, not 413. A 413 would tell an unauthenticated
    | caller that their guess at an integration id was right.
    */
    'max_body_bytes' => (int) env('DOCUP_WEBHOOK_MAX_BODY_BYTES', 26_214_400),

    /*
    |-----------------------------------------------------------------------
    | §8.5.4's truncation ceilings
    |-----------------------------------------------------------------------
    |
    | 🛑 "a per-provider commit or file ceiling held as **configuration with
    | a documented default, never as a hard-coded fact**, because providers
    | change these limits without notice."
    |
    | A payload at or above its provider's ceiling is treated as "everything
    | changed" (§8.5.4), which disables changed-path skip rules for that
    | delivery. Getting the number wrong in the cautious direction costs
    | build time; getting it wrong the other way silently stops rebuilding
    | the components that changed, which is why it is configuration an
    | operator can raise the day a provider does.
    |
    | Defaults as documented by each provider on 2026-10-25:
    |
    |   - GitHub: `commits` is capped at 20 entries; `added`/`removed`/
    |     `modified` are capped at 3,000 files across the push, and the
    |     payload carries no truncation flag at all.
    |   - GitLab: `commits` is capped at 20 entries, with `total_commits_count`
    |     carrying the real number — which IS a truncation signal, and is
    |     read as one below.
    |   - Bitbucket Cloud and Server: no file arrays in the push payload at
    |     all, which is §8.5.4's case (c). Every Bitbucket push is therefore
    |     treated as "everything changed", and no configuration can make it
    |     otherwise.
    |   - Gitea and Forgejo: `commits` capped by the instance's
    |     `webhook.PAGING_NUM`, default 10.
    */
    'truncation' => [
        'github' => ['commits' => 20, 'files' => 3000],
        'gitlab' => ['commits' => 20, 'files' => null],
        'bitbucket_cloud' => ['commits' => null, 'files' => null],
        'bitbucket_server' => ['commits' => null, 'files' => null],
        'gitea' => ['commits' => 10, 'files' => null],
        'forgejo' => ['commits' => 10, 'files' => null],
        'generic' => ['commits' => null, 'files' => null],
    ],

    /*
    |-----------------------------------------------------------------------
    | Delivery-id retention (§20)
    |-----------------------------------------------------------------------
    |
    | 🛑 §8.19.3's replay protection for the three schemes with no timestamp
    | is delivery-id uniqueness, and uniqueness is only as long as this
    | window. §20's table gives webhook deliveries a 30-day default with a
    | 7-day floor and a 90-day ceiling; the floor is what bounds how weak the
    | fallback may be made.
    */
    'delivery_retention_days' => (int) env('DOCUP_WEBHOOK_DELIVERY_RETENTION_DAYS', 30),

    /*
    |-----------------------------------------------------------------------
    | `ls-remote` polling (§8.5.3)
    |-----------------------------------------------------------------------
    |
    | The fallback for a repository whose webhook could not be provisioned
    | (§8.3.6's `manual_required`), and the only trigger an air-gapped
    | installation behind a firewall the provider cannot reach ever gets.
    |
    | 🛑 Polling is OFF for repositories whose webhook IS provisioned. A poll
    | beside a working webhook doubles the ref advertisements against the
    | provider for no new information, and providers rate-limit.
    */
    'polling' => [
        'interval_minutes' => (int) env('DOCUP_POLL_INTERVAL_MINUTES', 15),

        // Per tick, so one installation with 4,000 unprovisioned
        // repositories does not open 4,000 connections at :00.
        'batch_size' => (int) env('DOCUP_POLL_BATCH_SIZE', 50),
    ],

];
