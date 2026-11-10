<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Support;

use App\Auth\OrganisationContext;
use Illuminate\Support\Facades\DB;

/**
 * 🛑 **InnoDB FULLTEXT cannot see rows inserted in an uncommitted
 * transaction**, so a §8.16 test cannot use `DatabaseTransactions`.
 *
 * Measured on MySQL 8.4, and it cost an hour: the documents were in
 * `search_documents`, the scope rows were right, the authorised scope held one
 * fact, the parsed query held one term — and `MATCH … AGAINST` returned
 * **nothing**. InnoDB maintains a FULLTEXT index through auxiliary tables that
 * are written at **commit**, so inside the wrapping transaction every row is
 * invisible to a match while being perfectly visible to a `SELECT`.
 *
 * That is not a quirk of the test harness. It is why this trait exists rather
 * than a `DatabaseTransactions` with a workaround: there is no workaround. A
 * search test has to commit.
 *
 * ## What that costs, and how it is paid
 *
 * Every other feature test in this project rolls back. These do not, so they
 * clean up explicitly — and the cleanup is deliberately **by organisation**,
 * because §8.2.1's cascades do most of the work: deleting an organisation
 * removes its projects, versions, manifests, mounts, domains and
 * `search_mount_scopes` rows with it.
 *
 * 🛑 The three search tables are swept separately, because §8.16.11 declines
 * foreign keys on `search_documents` "because the retention sweep must not
 * cascade" — so nothing removes them when their organisation goes, by design.
 * `search_build_index` is the same. That is the requirement working as
 * specified, and the price of it is these four lines.
 *
 * Added to §14.3's trap list, beside the two other InnoDB FULLTEXT findings
 * ADR 0004 records: the `FTS_DOC_ID` insert failure and the one-index-per-ALTER
 * limit.
 */
trait CommitsSearchDocuments
{
    /** @var list<SearchFixture> */
    private array $searchFixtures = [];

    /** A tracked fixture; {@see self::cleanUpCommittedSearchData()} removes its rows. */
    protected function searchFixture(string $label): SearchFixture
    {
        $fixture = new SearchFixture(app(OrganisationContext::class), $label);

        $this->searchFixtures[] = $fixture;

        return $fixture;
    }

    /**
     * Remove everything the tracked fixtures wrote.
     *
     * Called from `tearDown()`, which PHPUnit runs even when a test fails — so
     * a failing search test does not leave its documents behind for the next
     * one to find.
     */
    protected function cleanUpCommittedSearchData(): void
    {
        $context = app(OrganisationContext::class);

        foreach ($this->searchFixtures as $fixture) {
            $fixture->cleanUp();
        }

        $organisations = array_map(
            static fn (SearchFixture $fixture): string => $fixture->organisation->id,
            $this->searchFixtures,
        );

        $this->searchFixtures = [];

        if ($organisations === []) {
            return;
        }

        $context->spanAllOrganisations();

        /*
         * 🛑 `DB::table()` and not Eloquent. §8.2.1's global scope would need a
         * declared tenant per organisation, and a `delete()` through the model
         * would then be three queries per fixture where this is one — in
         * teardown, where an exception is reported against the next test rather
         * than this one.
         */
        DB::table('search_documents')->delete();
        DB::table('search_build_index')->delete();
        DB::table('organisations')->whereIn('id', $organisations)->delete();

        /*
         * §20.3's decision log carries no foreign key to an organisation — it
         * is day-partitioned and §10.7 says partitioned InnoDB cannot carry
         * one — so its rows are swept by organisation rather than left to
         * accumulate across a suite run.
         */
        DB::table('access_decisions')->whereIn('organisation_id', $organisations)->delete();

        /*
         * 🛑 `audit_events` is **truncated**, not deleted from, and the
         * distinction is §8.22.1's.
         *
         * These tests commit, so the audit rows the real `Publisher` and
         * `Invalidation` write during them survive the test — and
         * `AuditExportTest` legitimately expects the table to hold only its
         * own event, because §8.22's export is installation-wide unless
         * `--organisation` narrows it. Left behind, 169 of these rows made
         * that test fail.
         *
         * `DELETE` is not an option: §8.22.1 makes the table append-only
         * with a trigger, and the trigger answers for itself —
         * `SQLSTATE[45000] … 1644 audit_events is append-only; purge by
         * DROP PARTITION (SPEC 20.3)`. The first version of this trait tried
         * it and every search test failed, **but only once the triggers
         * existed**, which is CI's state and was not this container's.
         *
         * `TRUNCATE` is DDL: it does not fire a row trigger, it is what
         * §20.3 means by purging a partitioned table wholesale, and it acts
         * on a **disposable test schema** rather than on an installation's
         * trail. Nothing is lost: every other suite rolls back, so the only
         * rows here are the ones these tests just made.
         *
         * 🛑 It is deliberately NOT a helper anything else can reach. An
         * application path that truncated this table would be the one thing
         * §8.22.1 exists to prevent, and `SearchArchitectureTest` asserts no
         * code under `app/` mentions it.
         */
        DB::statement('TRUNCATE TABLE `audit_events`');
        DB::statement('TRUNCATE TABLE `audit_anchors`');

        $context->forget();
    }
}
