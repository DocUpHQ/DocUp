<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Branding;

use App\Branding\ThemeAssets;
use App\Console\Commands\DoctorCommand;
use Illuminate\Support\Facades\Artisan;
use Tests\TestCase;

/**
 * 🛑 §8.14.11's "dedicated asset host", as `doctor` reports it.
 *
 * {@see DoctorCommand} grew this check because
 * `docs/operator/docs/branding.md` says it has one — and a documentation page
 * promising a report nobody emits is the defect class this phase spent its time
 * avoiding. A check with no test is the same thing one layer down: it would
 * report on an installation nobody had measured.
 *
 * Three states, three outcomes, and the middle one is the shipped default.
 */
final class AssetHostDoctorTest extends TestCase
{
    /** Unset: a warning, because the installation still works. */
    public function test_an_unset_asset_host_is_a_warning(): void
    {
        config()->set('docup.origins.assets', null);

        $this->assertFalse(ThemeAssets::hasDedicatedHost());

        $report = $this->doctor();

        $this->assertSame('warn', $report['status'], $report['detail']);
        $this->assertStringContainsString('DOCUP_ASSET_HOST is unset', $report['detail']);
    }

    /**
     * 🛑 Sharing the **dashboard's** registrable domain is a failure.
     *
     * §8.1.4's whole argument is that attacker-controlled content must not sit
     * beside the dashboard session, and an uploaded SVG is attacker-controlled
     * content — so this is the one asset-host misconfiguration that is not a
     * degradation.
     */
    public function test_sharing_the_dashboard_domain_is_a_failure(): void
    {
        config()->set('docup.origins.app', 'docup.example');
        config()->set('docup.origins.assets', 'assets.docup.example');

        $report = $this->doctor();

        $this->assertSame('fail', $report['status'], $report['detail']);
        $this->assertStringContainsString('shares the registrable domain', $report['detail']);
        $this->assertStringContainsString('the dashboard', $report['detail']);
    }

    /**
     * Sharing the documentation apex is a warning, and it is the shipped
     * default — so this test is asserting what an operator who changes nothing
     * will actually be told.
     */
    public function test_sharing_the_documentation_apex_is_a_warning(): void
    {
        config()->set('docup.origins.app', 'docup.example');
        config()->set('docup.origins.docs', 'docup-docs.example');
        config()->set('docup.origins.assets', 'assets.docup-docs.example');

        $report = $this->doctor();

        $this->assertSame('warn', $report['status'], $report['detail']);
        $this->assertStringContainsString('documentation apex', $report['detail']);
        $this->assertStringContainsString('fourth registrable domain', $report['detail']);
    }

    /** A fourth registrable domain passes. */
    public function test_a_domain_of_its_own_passes(): void
    {
        config()->set('docup.origins.app', 'docup.example');
        config()->set('docup.origins.docs', 'docup-docs.example');
        config()->set('docup.origins.assets', 'docup-assets.example');

        $report = $this->doctor();

        $this->assertSame('pass', $report['status'], $report['detail']);
    }

    /**
     * The branding asset-host row of `docup:doctor --json`.
     *
     * 🛑 Read from the **JSON** output rather than scraped from the table,
     * because the table wraps its detail across lines and a test matching
     * wrapped text asserts the terminal width as much as the finding.
     *
     * @return array{status: string, detail: string}
     */
    private function doctor(): array
    {
        Artisan::call('docup:doctor', ['--json' => true]);

        /** @var list<array{check?: string, status?: string, detail?: string}> $results */
        $results = json_decode(Artisan::output(), true, 512, JSON_THROW_ON_ERROR);

        foreach ($results as $result) {
            if (($result['check'] ?? null) === 'Branding asset host') {
                return [
                    'status' => (string) ($result['status'] ?? ''),
                    'detail' => (string) ($result['detail'] ?? ''),
                ];
            }
        }

        $this->fail('docup:doctor no longer reports on the branding asset host');
    }
}
