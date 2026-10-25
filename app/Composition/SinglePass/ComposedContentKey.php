<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Composition\SinglePass;

use App\Audit\CanonicalJson;
use App\Builds\BuildPlan;
use App\Builds\ContentKey;

/**
 * 🛑 §8.7.9's content key, for a build that has several components.
 *
 * > "Builds MUST be identified by a content key over `organisation_id`,
 * > `component_id`, `commit_sha`, config digest, builder image, builder
 * > version, and — only when `base_url_mode='injected'` — the mount path;
 * > enforced `UNIQUE`, and satisfied from an existing successful build
 * > with the same key."
 *
 * Every noun in that sentence is singular, because when it was written a
 * build had one component. §8.7.12's `single_pass` build has several, so
 * the key is over the **ordered set** of them. Recorded as a proposed
 * amendment to §8.7.9, which assumes one component per build throughout.
 *
 * 🛑 **A schema of its own**, so no composed key can ever equal a
 * mount-mode key. The two mean different things — one artifact is a
 * component's pages, the other is a whole site — and a collision would
 * publish one where the other was expected. {@see ContentKey}
 * is deliberately untouched: bumping its schema would invalidate every key
 * already in the table for a mode that does not use this one.
 *
 * 🛑 **The project is not an input**, which is what keeps §8.7.9's reuse
 * real in this mode too: two projects composing the same sources with the
 * same configuration and the same image share a key and therefore a build.
 * That is rarer than the mount-mode case — §8.7.13 says `single_pass`
 * output is "not cacheable per source" — but rarer is not never, and
 * putting the project in the key would make it never by construction.
 */
final readonly class ComposedContentKey
{
    private const SCHEMA = 'docup.content-key/single-pass/1';

    /**
     * @param  string  $organisationId  raw 16 bytes
     */
    public static function compute(string $organisationId, BuildPlan $plan): string
    {
        return hash('sha256', CanonicalJson::encode([
            'schema' => self::SCHEMA,
            'organisation' => bin2hex($organisationId),

            /*
             * Sorted by {@see BuildPlan::orderedSources()}, which is what
             * makes two triggers that resolved the same sources in a
             * different order produce one key. Without it a monorepo push
             * fanning out to three projects would compute three keys for
             * one composition and build it three times.
             */
            'sources' => $plan->orderedSources(),
            'config_digest' => $plan->configDigest,
            'env_digest' => $plan->envDigest,
            'pipeline_version' => $plan->pipelineVersion,
        ]));
    }
}
