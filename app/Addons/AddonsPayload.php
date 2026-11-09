<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Addons;

use App\Artifacts\ChromeInjector;
use App\Artifacts\InjectionCoverage;
use App\Branding\ApiOnlyChrome;
use App\Branding\DeliveredTheme;
use App\Branding\ThemeDelivery;
use App\Branding\ThemeTarget;
use App\Http\Controllers\Serving\DownloadController;
use App\Models\Build;
use App\Serving\CanonicalLocations;
use App\Serving\ManifestReader;
use App\Serving\OfflineFormat;
use App\Serving\VersionUrl;
use App\Support\Uuid;

/**
 * 🛑 §8.15.2's payload, assembled.
 *
 * > "All request-scoped data MUST come from `GET /_/addons`, resolved from the
 * > **request's** host and path, authorised identically to the HTML, with
 * > `Vary: Cookie`: branding tokens, version list and sort, flyout
 * > configuration, notifications, search configuration, merged navigation,
 * > cross-reference map, canonical URL and analytics opt-in."
 *
 * Nine named fields plus §8.15.11's offline formats. Each is a key here, and
 * `AddonsPayloadTest` asserts the set — so a field removed by a refactor fails
 * a test rather than silently leaving a feature with no data.
 *
 * ## 🛑 Why the theme payload is nested rather than merged
 *
 * `theme` is {@see DeliveredTheme::toPayload()} verbatim, which
 * **is** §8.14.14's `api_only` contract and carries its own `contract` version.
 * Merging its keys into this envelope would make the reference example
 * (`resources/themes/api-only-reference.json`) a fragment of a larger document
 * rather than a document, and would tie the two version numbers together —
 * which {@see AddonsContract} explains is exactly what must not happen, because
 * a new banner and a new branding token are changes for different consumers.
 */
final readonly class AddonsPayload
{
    public function __construct(
        private Flyout $flyout,
        private Notifications $notifications,
        private CrossReferenceMap $crossReferences,
        private ManifestReader $manifests,
        private CanonicalLocations $canonical,
    ) {}

    /**
     * @return array<string, mixed>
     */
    public function for(AddonsContext $context): array
    {
        $project = $context->project;
        $version = $context->version;
        $manifestId = $version?->publishedManifestId;

        /*
         * 🛑 All four of §8.14.1's rungs, because the request resolved all four.
         *
         * This is what makes §17's exit criterion "changing a branding token
         * changes the rendered chrome with the **same build id**" true. Nothing
         * about the theme comes from the artifact: §8.15.1 permits only the
         * build id in the injected markup, so the artifact cannot carry a
         * stylesheet reference and a token edit has nothing to invalidate.
         *
         * The mount and version rungs matter here and nowhere else in the
         * product so far — a domain-mount override is §8.14.1's deepest rung and
         * the version overlay is what carries `banner.text` (§8.14.1 confines it
         * to three tokens). A payload resolved for the project alone would make
         * both unreachable for a reader, which is the only consumer they have.
         */
        $delivered = ThemeDelivery::make(
            organisationId: $project->organisation_id,
            projectId: $project->id,
        )->deliver(new ThemeTarget(
            organisationId: $project->organisation_id,
            projectId: $project->id,
            mountId: $context->mount->id === '' ? null : $context->mount->id,
            versionId: $version?->id,
        ));

        return [
            'contract' => AddonsContract::VERSION,

            /*
             * 🛑 §8.15.7's mode, as **applied**. The project's own column is
             * what it asked for; a build whose artifact could not be injected
             * serves `api_only` whatever the project chose (§8.15.4), and the
             * runtime has to know which — it is loaded by the injected script,
             * so on an `api_only` build it is not running at all, and on an
             * `off` project it must take no action even though the historical
             * artifact still carries the tags.
             */
            'chrome_mode' => $this->appliedChromeMode($context),

            /*
             * The build id, echoed so the runtime can assert that the payload
             * describes the document it was loaded by. A mismatch means the
             * reader is looking at a cached page from before a publish, which
             * is a thing the runtime should be able to notice rather than
             * render stale chrome over.
             */
            'build' => $this->buildIdOf($manifestId),
            'injector_version' => ChromeInjector::VERSION,

            'project' => [
                'slug' => (string) $project->slug,
                'name' => (string) $project->name,
            ],

            'version' => $version === null ? null : [
                'slug' => $version->slug,
                'language' => $version->language,
                'kind' => (string) ($context->versionRow()->kind ?? 'channel'),
                'root' => VersionUrl::root($context->mount, $context->mount->versioningScheme(), $version),
            ],

            /*
             * §8.15.2's "canonical URL". From {@see CanonicalLocations}, which
             * is §8.10.2's `canonical_for_project_id` — the same answer the
             * `Link rel=canonical` header carries, so chrome and the header
             * cannot name two different canonical hosts.
             */
            'canonical' => $this->canonicalUrl($context),

            /*
             * §8.15.2's "branding tokens" — and all of §8.14.14's contract,
             * nested verbatim. Named `branding` rather than `theme` because the
             * document it carries has its own `theme` key, and
             * `payload.theme.theme.tokens` is the kind of shape that gets
             * mis-read by whoever writes the second consumer.
             */
            'branding' => $delivered->toPayload(),
            'branding_contract' => ApiOnlyChrome::VERSION,

            // §8.15.2's "version list and sort" plus "flyout configuration".
            'flyout' => [
                'configuration' => $this->flyout->configuration($project),
                'versions' => $this->flyout->versions($context),
            ],

            // §8.15.2's "notifications" — §8.15.6's three, plus §8.6.13's.
            'notifications' => array_map(
                static fn (Banner $banner): array => $banner->toArray(),
                $this->notifications->for($context),
            ),

            // §8.15.2's "search configuration"; §8.15.12's takeover.
            'search' => $this->search($context),

            /*
             * §8.15.2's "merged navigation" — §8.7.6's spliced tree, read from
             * the version manifest where the publish path put it. Empty for a
             * generator that ships no nav fragment, which is most of them: the
             * chrome's navigation is §8.14.3's structured links, and this is the
             * documentation's own tree for a consumer that wants to render it.
             */
            'navigation' => $manifestId === null ? [] : $this->manifests->navigation($manifestId),

            // §8.15.2's "cross-reference map" — §8.7.17.
            'cross_references' => $this->crossReferences->for($context),

            // §8.15.11's offline formats, so the flyout needs no second round trip.
            'downloads' => $this->flyout->downloads($context, $this->availableFormats($manifestId)),

            // §8.15.2's "analytics opt-in".
            'analytics' => $this->analytics(),
        ];
    }

    /**
     * §8.15.4's applied mode for the build actually being served.
     *
     * A project on `api_only` or `off` chose that, and §8.15.4 does not let a
     * build override a deliberate choice. A project on `injected` whose build
     * could not be injected serves `api_only`, and `builds.chrome_mode_applied`
     * is where the publish path recorded that decision — read rather than
     * recomputed, because recomputing it would need the coverage record and
     * would be a second implementation of {@see InjectionCoverage}.
     */
    private function appliedChromeMode(AddonsContext $context): string
    {
        $mode = (string) $context->project->chrome_mode;

        if ($mode !== 'injected') {
            return $mode;
        }

        $build = $this->buildOf($context->version?->publishedManifestId);

        return $build->chrome_mode_applied ?? 'injected';
    }

    /**
     * §8.15.2's "search configuration".
     *
     * 🛑 `enabled` is **false** and will stay false until Phase 29 ships the
     * index, and that is the honest state rather than a stub: §17 puts the
     * `SearchEngine` seam, the index and the query path in Phase 29 and the
     * search UX in Phase 30. The runtime renders the combobox either way —
     * §8.15.8 makes its keyboard behaviour a 🛑 requirement of this phase — and
     * with `enabled: false` it says so instead of querying an endpoint that
     * does not exist.
     *
     * A flag claiming otherwise would be the failure Phase 26b recorded: "a
     * config key nothing reads is a key an operator believes is doing
     * something."
     *
     * @return array{enabled: bool, endpoint: string|null, takeover: bool, selector: string}
     */
    private function search(AddonsContext $context): array
    {
        $project = $context->project;

        return [
            'enabled' => false,
            'endpoint' => null,

            /*
             * 🛑 §8.15.12: the takeover "MUST leave the generator's own search
             * working untouched when `chrome_mode` is `off` or takeover is
             * disabled". Both halves are expressed here, so the runtime has one
             * boolean to read and cannot implement half the rule.
             */
            'takeover' => $this->appliedChromeMode($context) !== 'off'
                && (bool) $project->addons_search_takeover,

            // §8.15.12's own default, applied when the project has not chosen.
            'selector' => $this->selectorFor($project->addons_search_selector),
        ];
    }

    /**
     * §8.15.12's selector, defaulted.
     *
     * The requirement states the default in full — "defaulting to
     * `input[type='search'], [role='search'] input`" — so it is a literal here
     * rather than a configuration value: an installation-wide override would
     * make the documented default untrue for exactly the operator reading the
     * documentation.
     */
    private function selectorFor(?string $stored): string
    {
        $stored = $stored === null ? '' : trim($stored);

        return $stored === '' ? "input[type='search'], [role='search'] input" : $stored;
    }

    /**
     * §8.15.2's "analytics opt-in", and §8.15.6's beacon.
     *
     * 🛑 **Off, with no setting that can turn it on.** §17 puts the rollup
     * tables, the consent hook and the salt rotation in Phase 31, whose exit
     * criteria include "Analytics is **off on a fresh install**". So this phase
     * ships the client beacon — §17 names it among Phase 28's deliverables —
     * and the flag that gates it, and deliberately ships **no operator toggle**:
     * a toggle an operator could set while nothing recorded a page view would
     * be worse than its absence, which is Phase 26b's finding and the same
     * reasoning §8.14.16's token carries in its own purpose text.
     *
     * @return array{enabled: bool, endpoint: string|null}
     */
    private function analytics(): array
    {
        return ['enabled' => false, 'endpoint' => null];
    }

    /** The absolute canonical URL for the page being read, or null. */
    private function canonicalUrl(AddonsContext $context): ?string
    {
        $location = $this->canonical->for(
            $context->mount->project->id,
            $context->mount->project->routingEpoch,
        );

        if ($location === null || $context->version === null) {
            return null;
        }

        $mount = $location->mountFor($context->mount->project);

        return $location->origin.VersionUrl::document(
            $mount,
            $mount->versioningScheme(),
            $context->version,
            $context->route->remainder,
        );
    }

    /**
     * The offline formats the published build emitted (§8.15.11).
     *
     * Asked of the file manifest rather than of `build_outputs`, because that is
     * what {@see DownloadController} asks — and a
     * flyout offering a download the downloads endpoint would 404 is worse than
     * one offering none.
     *
     * @param  string|null  $manifestId  raw 16 bytes
     * @return list<string>
     */
    private function availableFormats(?string $manifestId): array
    {
        if ($manifestId === null) {
            return [];
        }

        $primary = null;

        foreach ($this->manifests->mounts($manifestId) as $mount) {
            // §8.7.19: only the primary mount may emit offline formats.
            if ($mount['is_primary'] && $mount['build_id'] !== null) {
                $primary = $mount['build_id'];

                break;
            }
        }

        if ($primary === null) {
            return [];
        }

        $files = $this->manifests->files($primary);
        $formats = [];

        foreach (OfflineFormat::cases() as $format) {
            if (array_key_exists($format->manifestPath(), $files)) {
                $formats[] = $format->value;
            }
        }

        return $formats;
    }

    /** The primary build's id as text, or null. */
    private function buildIdOf(?string $manifestId): ?string
    {
        if ($manifestId === null) {
            return null;
        }

        foreach ($this->manifests->mounts($manifestId) as $mount) {
            if ($mount['is_primary'] && $mount['build_id'] !== null) {
                return $mount['build_id'];
            }
        }

        return null;
    }

    /** The primary build row, for `chrome_mode_applied`. */
    private function buildOf(?string $manifestId): ?Build
    {
        $buildId = $this->buildIdOf($manifestId);

        if ($buildId === null) {
            return null;
        }

        return Build::withoutGlobalScopes()
            ->whereKey(Uuid::tryToBytes($buildId) ?? str_repeat("\xff", 16))
            ->first();
    }
}
