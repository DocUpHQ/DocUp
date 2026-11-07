<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Readers;

use App\Auth\OrganisationContext;
use App\Http\Controllers\Health\SelfTestController;
use App\Serving\RoutingSnapshotLoader;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Storage;

/**
 * 🛑 §8.12.22's containment proof: the plan and the verdict.
 *
 * > "The system MUST ship automated proof of its own containment: a boot-time
 * > **and** CI check that fetches a known-private asset through the real edge
 * > with no credentials and **fails on any 200**."
 *
 * ## 🛑 Why this class does not make the request
 *
 * The requirement says "through the real edge", which means an HTTP request
 * leaving the application and coming back through the proxy. PHP cannot make
 * that request here: §8.3.9 routes "every outbound request derived from
 * user-supplied configuration" through the one `HardenedEgressClient`, and that
 * client denies private and loopback addresses by design — which is every
 * address the edge has. The architecture test enforcing it allows exactly one
 * exemption and says in as many words that "an allowlist that grows by one
 * legitimate case per phase stops being a gate".
 *
 * So the division is: this class answers **what to probe** and stores **what
 * happened**, and `deploy/containment-self-test.sh` does the fetching with
 * `curl`. The script is what §8.12.22 means by the system shipping the check;
 * it runs at start-up and in CI against both edge drivers, and
 * {@see SelfTestController} reports its verdict at
 * §8.1.10's `/_/health/self-test`.
 *
 * ## 🛑 Why a missing verdict is not a pass
 *
 * Same argument §8.5.12's sandbox verdict makes: "No verdict means no runner
 * has started since this spool existed, so nothing has checked the sandbox —
 * which is the same operational fact as a failure". An installation with no
 * non-public project has nothing to probe and says `not_applicable`; one that
 * has something to probe and no verdict says `never_run`, and the health
 * endpoint is 503 for it.
 */
final readonly class Containment
{
    /**
     * Where the verdict lives.
     *
     * 🛑 A file rather than the cache. A verdict that a `cache:clear` erases
     * would make the health endpoint report `never_run` after an ordinary
     * deploy step, and an operator who sees that twice stops reading it.
     */
    private const string VERDICT_PATH = 'containment-self-test.json';

    public function __construct(private OrganisationContext $context) {}

    /**
     * A known-private asset to probe: its host and its path.
     *
     * 🛑 **Chosen by the application, not configured.** An operator-supplied
     * host would be one they could point at a public project by mistake, and
     * the check would then pass forever while proving nothing. The query asks
     * for what §8.12.22 needs: a project the lattice should refuse an anonymous
     * reader, with a published version, on a host the edge actually serves.
     *
     * Returns null when the installation has nothing private published — a
     * fresh install, or one that serves only public documentation. That is
     * reported as `not_applicable` rather than as a pass.
     *
     * @return array{host: string, path: string}|null
     */
    public function plan(): ?array
    {
        /*
         * 🛑 Across every organisation. The probe is the installation's own
         * assertion about itself and there is no tenant making it; the only
         * thing taken from the row is a hostname and a version slug, both of
         * which the edge already serves publicly as URLs.
         */
        $row = $this->context->acrossAllOrganisations(static fn (): ?object => DB::table('domain_mounts')
            ->join('domains', 'domains.id', '=', 'domain_mounts.domain_id')
            ->join('projects', 'projects.id', '=', 'domain_mounts.project_id')
            ->join('project_versions', 'project_versions.project_id', '=', 'projects.id')
            ->whereNull('projects.deleted_at')
            ->whereNotNull('project_versions.published_manifest_id')
            /*
             * 🛑 Either axis being non-public is enough, because §12.3's
             * intersection takes the **maximum**: a public project with a
             * `members` version is just as private at that URL as a private
             * project, and an installation whose only private thing is a
             * version must still be probed.
             */
            ->where(function ($query): void {
                $query->where('projects.visibility', '!=', 'public')
                    ->orWhere('project_versions.visibility', '!=', 'public');
            })
            ->where('domain_mounts.path_prefix', '')
            ->orderBy('projects.created_at')
            ->first([
                'domains.host',
                'domains.kind',
                'domains.state',
                'domains.verified_at',
                'project_versions.slug as version_slug',
                'project_versions.language',
            ]));

        if ($row === null || ! is_string($row->host)) {
            return null;
        }

        /*
         * 🛑 §8.10.6's predicate, through the resolver's own copy of it. A host
         * the edge will not serve cannot prove containment: it answers §8.9.3's
         * hard 404 for *every* request, so the probe would pass for the wrong
         * reason and keep passing after the containment broke.
         */
        $servable = RoutingSnapshotLoader::canServe(
            is_string($row->kind) ? $row->kind : '',
            is_string($row->state) ? $row->state : '',
            is_string($row->verified_at) ? $row->verified_at : null,
        );

        if (! $servable) {
            return null;
        }

        $language = is_string($row->language) && $row->language !== '' ? $row->language : 'en';
        $slug = is_string($row->version_slug) && $row->version_slug !== '' ? $row->version_slug : 'latest';

        return ['host' => $row->host, 'path' => '/'.$language.'/'.$slug.'/'];
    }

    /**
     * Store what the probe saw.
     *
     * @param  int  $status  the status the edge answered with no credentials
     * @param  string  $summary  fixed vocabulary; reaches an operator, never a
     *                           reader
     */
    public function record(bool $passed, int $status, string $summary, ?string $host = null): void
    {
        $payload = (string) json_encode([
            'passed' => $passed,
            'status' => $status,
            'summary' => $summary,
            'host' => $host,
            'at' => now()->toIso8601String(),
        ]);

        try {
            Storage::disk('local')->put(self::VERDICT_PATH, $payload);
        } catch (\Throwable) {
            /*
             * 🛑 Swallowed, like §20.3's decision log. A containment probe that
             * could not write its verdict must not take the application down —
             * the health endpoint reports `never_run`, which is the honest
             * answer and is already treated as a failure.
             */
        }
    }

    /**
     * The stored verdict, or null when none has been written.
     *
     * @return array{passed: bool, status: int, summary: string, host: string|null, at: string}|null
     */
    public function verdict(): ?array
    {
        try {
            if (! Storage::disk('local')->exists(self::VERDICT_PATH)) {
                return null;
            }

            $raw = (string) Storage::disk('local')->get(self::VERDICT_PATH);
            $decoded = json_decode($raw, true, 8, JSON_THROW_ON_ERROR);
        } catch (\Throwable) {
            return null;
        }

        if (! is_array($decoded) || ! array_key_exists('passed', $decoded)) {
            return null;
        }

        return [
            'passed' => (bool) $decoded['passed'],
            // 🛑 `is_numeric` then cast, never `is_int` — Phase 20's finding
            // applies to anything that round-tripped through JSON.
            'status' => is_numeric($decoded['status'] ?? null) ? (int) $decoded['status'] : 0,
            'summary' => is_string($decoded['summary'] ?? null) ? $decoded['summary'] : '',
            'host' => is_string($decoded['host'] ?? null) ? $decoded['host'] : null,
            'at' => is_string($decoded['at'] ?? null) ? $decoded['at'] : '',
        ];
    }

    /**
     * 🛑 The three states the health endpoint reports, as one function.
     *
     * `not_applicable` only when there is genuinely nothing private to probe —
     * which this class decides from the database, not from a flag an operator
     * could set.
     */
    public function state(): string
    {
        $verdict = $this->verdict();

        if ($verdict !== null) {
            return $verdict['passed'] ? 'passed' : 'failed';
        }

        return $this->plan() === null ? 'not_applicable' : 'never_run';
    }
}
