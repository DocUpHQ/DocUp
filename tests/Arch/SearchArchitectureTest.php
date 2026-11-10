<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Arch;

use App\Egress\MeilisearchTransport;
use App\Search\AuthorisedScope;
use App\Search\Engines\MeilisearchEngine;
use App\Search\Engines\MysqlFulltextEngine;
use App\Search\LiteralTerm;
use App\Search\SearchEngine;
use App\Search\SearchGenerations;
use App\Search\SearchQuery;
use App\Search\SearchResult;
use App\Search\SearchScopes;
use App\Search\SearchTransport;
use App\Search\SearchUrls;
use Tests\Support\CommitsSearchDocuments;
use Tests\TestCase;

/**
 * §8.16's structural invariants, enforced by CI rather than by intention.
 *
 * Every assertion here is a promise some docblock in `app/Search` makes. The
 * same reasoning as `ArchitectureTest`: these read the source tree, crudely and
 * on purpose, because a test that needed the application to boot would stop
 * protecting the thing it was written for at the moment that code failed to
 * load.
 *
 * ## 🛑 What these defend
 *
 * §8.16.6 requires visibility filtering to be "server-side only" and §8.16.12
 * forbids a client filter expression "in any form". Both are properties of the
 * **call graph**, not of a value: they hold because an engine is only reachable
 * through {@see SearchQuery}, which cannot be called without
 * {@see SearchScopes} having produced an
 * {@see AuthorisedScope} first. Nothing in a type system says so,
 * so these say so.
 */
final class SearchArchitectureTest extends TestCase
{
    /** @return list<string> */
    private function searchFiles(): array
    {
        $files = [];

        /** @var \SplFileInfo $file */
        foreach (new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator(base_path('app/Search'))) as $file) {
            if ($file->isFile() && $file->getExtension() === 'php') {
                $files[] = $file->getPathname();
            }
        }

        /*
         * Plus the one file outside `app/Search` that speaks to an engine.
         *
         * 🛑 **Not** the whole of `app/Egress`. `HardenedEgressClient` has a
         * `request()` method of its own and §8.3.9 is its requirement, not
         * §8.16's — scanning the namespace made this test fail on a class it
         * has nothing to say about, which is the shape of an architecture test
         * that outgrows its own rule.
         */
        $files[] = base_path('app/Egress/MeilisearchTransport.php');

        sort($files);

        return $files;
    }

    /** @return list<string> */
    private function appFiles(): array
    {
        $files = [];

        /** @var \SplFileInfo $file */
        foreach (new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator(base_path('app'))) as $file) {
            if ($file->isFile() && $file->getExtension() === 'php') {
                $files[] = $file->getPathname();
            }
        }

        sort($files);

        return $files;
    }

    private function relative(string $path): string
    {
        return str_replace(DIRECTORY_SEPARATOR, '/', str_replace(base_path().DIRECTORY_SEPARATOR, '', $path));
    }

    /** Source with comments stripped, for the reason `ArchitectureTest::code()` gives. */
    private function code(string $file): string
    {
        $out = '';

        foreach (token_get_all((string) file_get_contents($file)) as $token) {
            if (is_array($token)) {
                if (! in_array($token[0], [T_COMMENT, T_DOC_COMMENT], true)) {
                    $out .= $token[1];
                }

                continue;
            }

            $out .= $token;
        }

        return $out;
    }

    /**
     * 🛑 §8.16.6: "Search MUST be proxied server-side."
     *
     * One caller of a {@see SearchEngine} on a reader's behalf, and it is
     * {@see SearchQuery}. An engine reached from anywhere else is an
     * engine reached without {@see SearchScopes} having run, so the
     * authorisation filter would be a convention rather than a structure.
     *
     * The indexer and the retention sweep hold an engine too, which is why they
     * are named: they write and delete rather than answer a reader, and neither
     * takes a request.
     */
    public function test_only_the_query_path_and_the_indexer_hold_a_search_engine(): void
    {
        $allowed = [
            'app/Search/SearchQuery.php',
            'app/Search/Indexer.php',
            'app/Search/SearchRetention.php',
            'app/Search/SearchEngine.php',
            'app/Search/Engines/MysqlFulltextEngine.php',
            'app/Search/Engines/MeilisearchEngine.php',
            // Binding a class in a container is not calling it — the same
            // exemption, by path, that the §8.3.9 egress test grants.
            'app/Providers/AppServiceProvider.php',
            // §8.16.1's operator surfaces: a command and `doctor` ask the
            // engine about itself (limits, reachability, section count) and
            // never on a reader's behalf.
            'app/Console/Commands/SearchIndexCommand.php',
            'app/Console/Commands/SearchRetentionCommand.php',
            'app/Console/Commands/DoctorCommand.php',
            'app/Http/Controllers/Projects/SearchSettingsController.php',
        ];

        $offenders = [];

        foreach ($this->appFiles() as $file) {
            $relative = $this->relative($file);

            if (in_array($relative, $allowed, true)) {
                continue;
            }

            $source = $this->code($file);

            if (str_contains($source, 'SearchEngine')) {
                $offenders[] = $relative;
            }
        }

        $this->assertSame(
            [],
            $offenders,
            '§8.16.6: only the query path, the indexer and the operator surfaces may hold a SearchEngine. '
            .'Offenders: '.implode(', ', $offenders),
        );
    }

    /**
     * 🛑 §8.16.12: "Filter expressions MUST NOT be accepted from the client in
     * any form."
     *
     * So nothing in `app/Search` reads a request, a session, a cookie or an
     * input bag. The query string arrives as a **string parameter** from a
     * caller that has already resolved the reader, and the scope arrives as an
     * {@see AuthorisedScope} the namespace built itself.
     *
     * A driver that could reach `request()` could reach a filter expression,
     * and the one in §8.16.6 that matters is `scopes = "restricted"`.
     */
    public function test_nothing_in_the_search_namespace_reads_a_request(): void
    {
        $forbidden = [
            'request(' => 'reads the request helper',
            'Illuminate\\Http\\Request' => 'imports Request',
            '$_GET' => 'reads the query string directly',
            '$_POST' => 'reads the request body directly',
            'Session::' => 'reads the session',
            'Cookie::' => 'reads a cookie',
            'Auth::' => 'resolves the actor itself',
        ];

        $offenders = [];

        foreach ($this->searchFiles() as $file) {
            $relative = $this->relative($file);
            $source = $this->code($file);

            foreach ($forbidden as $needle => $what) {
                if (str_contains($source, $needle)) {
                    $offenders[] = $relative.' '.$what;
                }
            }

            /*
             * A `Request` **parameter**, with the word boundary a plain
             * `str_contains('Request $')` lacks: §8.16.12's own value object
             * is `ScopeRequest`, and `ScopeRequest $request` matched the
             * naive needle.
             */
            if (preg_match('/(?<![A-Za-z_])Request\\s+\\$/', $source) === 1) {
                $offenders[] = $relative.' takes a Request';
            }
        }

        $this->assertSame(
            [],
            $offenders,
            '§8.16.12: no request input may reach a search driver. Offenders: '.implode('; ', $offenders),
        );
    }

    /**
     * 🛑 Both drivers refuse an empty scope before building a query.
     *
     * §8.16.6 makes the scope the whole of the visibility filter, so a `MATCH`
     * or a Meilisearch `filter` built without one returns the installation.
     * Asserted on the **source** because it is a guard whose absence no
     * functional test would notice: every test has a non-empty scope.
     */
    public function test_every_driver_guards_an_empty_scope(): void
    {
        foreach ([MysqlFulltextEngine::class, MeilisearchEngine::class] as $driver) {
            $file = base_path('app/Search/Engines/'.class_basename($driver).'.php');
            $source = $this->code($file);

            $this->assertStringContainsString(
                '$scope->isEmpty()',
                $source,
                class_basename($driver).' must refuse an empty scope before building a query (§8.16.6)',
            );
        }
    }

    /**
     * 🛑 §8.16.5: documents are keyed to a build-relative path, "never to an
     * absolute URL".
     *
     * A driver that stored or returned a URL would have to be told which
     * project asked, which is the authorisation fact §8.16.6 keeps out of the
     * engines. So no driver and no extractor mentions a scheme, a host or
     * {@see SearchResult} — the URL is computed by
     * {@see SearchUrls} and nowhere else.
     */
    public function test_no_driver_or_extractor_knows_about_urls(): void
    {
        $files = [
            'app/Search/Engines/MysqlFulltextEngine.php',
            'app/Search/Engines/MeilisearchEngine.php',
            'app/Search/SectionExtractor.php',
            'app/Search/MaterialIndexReader.php',
            'app/Search/SphinxJsonReader.php',
        ];

        $offenders = [];

        foreach ($files as $relative) {
            $source = $this->code(base_path($relative));

            foreach (['SearchResult', 'url(', 'route(', 'https://'] as $needle) {
                if (str_contains($source, $needle)) {
                    $offenders[] = $relative.' mentions '.$needle;
                }
            }
        }

        $this->assertSame(
            [],
            $offenders,
            '§8.16.5 computes result URLs at query time, outside the engines. Offenders: '
            .implode('; ', $offenders),
        );
    }

    /**
     * 🛑 §8.16.12's degradation lives in one place, so two drivers cannot
     * disagree.
     *
     * {@see LiteralTerm} records what happened when each driver
     * stripped its own operator set: `~nuterm` found the document on MySQL and
     * nothing on Meilisearch, which made §8.16.12's "the identical suite passes
     * on both engines" false for exactly the clause §8.16.12 is about.
     */
    public function test_neither_driver_strips_operators_of_its_own(): void
    {
        $offenders = [];

        foreach (['MysqlFulltextEngine', 'MeilisearchEngine'] as $driver) {
            $source = $this->code(base_path('app/Search/Engines/'.$driver.'.php'));

            $this->assertStringContainsString(
                'LiteralTerm::',
                $source,
                $driver.' must reduce terms through LiteralTerm (§8.16.12)',
            );

            /*
             * The signature of a driver doing it itself: a `str_replace` over
             * an array of single characters. Crude, and it is the shape the
             * removed code had.
             */
            if (preg_match("/str_replace\(\s*\[\s*'[+~<>()*@\"\\\\^-]'/", $source) === 1) {
                $offenders[] = $driver;
            }
        }

        $this->assertSame([], $offenders, 'a driver is stripping operators itself: '.implode(', ', $offenders));
    }

    /**
     * 🛑 §8.12.21's gate is read live, never from the routing snapshot.
     *
     * {@see SearchGenerations} states the reason at length: the
     * snapshot is keyed on `routing_epoch` when it is cached, and §10.8 gives
     * that epoch "domain, mount, redirect, version pointer change" — none of
     * which indexing bumps. A cached `search_policy_generation` would therefore
     * keep a caught-up project failing the gate until something unrelated moved
     * its routing epoch: fail-closed, permanently, looking exactly like a
     * design decision.
     */
    public function test_the_search_generation_is_not_carried_in_the_routing_snapshot(): void
    {
        $this->assertStringNotContainsString(
            'search_policy_generation',
            $this->code(base_path('app/Serving/RoutingSnapshotLoader.php')),
            '§8.12.21: the gate reads the row, not the snapshot — SearchGenerations says why',
        );

        $this->assertStringNotContainsString(
            'searchPolicyGeneration',
            $this->code(base_path('app/Serving/SnapshotProject.php')),
        );
    }

    /**
     * 🛑 §8.16.8: the filterable set is a constant, not a settings call.
     *
     * "changing Meilisearch's `filterableAttributes` forces a mandatory full
     * reindex, which makes any later addition a migration event (§15.5)" — so
     * adding one is a reindex of every installation, and that decision belongs
     * in a diff with the requirement's citation beside it.
     */
    public function test_the_meilisearch_filterable_set_is_declared_as_a_constant(): void
    {
        $this->assertNotSame(
            [],
            MeilisearchEngine::FILTERABLE_ATTRIBUTES,
            '§8.16.8 requires the complete set declared in v1',
        );

        foreach (['build_generation', 'language', 'projects', 'versions', 'scopes'] as $required) {
            $this->assertContains(
                $required,
                MeilisearchEngine::FILTERABLE_ATTRIBUTES,
                '§8.16.8 names '.$required.' among the attributes that must be declared in v1',
            );
        }

        $this->assertContains(
            'build_id',
            MeilisearchEngine::FILTERABLE_ATTRIBUTES,
            'and the authorisation filter is built from build_id, so §8.16.8\'s own list needs it too',
        );
    }

    /**
     * 🛑 §8.12.21: "search-engine tenant tokens MUST NEVER reach a browser".
     *
     * DocUp mints none — §8.16.6 requires search to be proxied server-side — so
     * the only key in the system is the admin key, and
     * {@see MeilisearchTransport} exposes it through no method.
     * Asserted structurally: nothing anywhere returns or renders it.
     */
    public function test_no_search_engine_key_is_ever_exposed(): void
    {
        $offenders = [];

        foreach ($this->appFiles() as $file) {
            $relative = $this->relative($file);
            $source = $this->code($file);

            if (! str_contains($source, 'meilisearch.key')) {
                continue;
            }

            if ($relative !== 'app/Egress/MeilisearchTransport.php') {
                $offenders[] = $relative;
            }
        }

        $this->assertSame(
            [],
            $offenders,
            '§8.12.21: only the transport may read the engine key. Offenders: '.implode(', ', $offenders),
        );

        /* And it has no accessor: there is nothing to leak because nothing returns it. */
        $transport = new \ReflectionClass(MeilisearchTransport::class);

        foreach ($transport->getMethods(\ReflectionMethod::IS_PUBLIC) as $method) {
            $this->assertNotSame('key', $method->getName());
            $this->assertNotSame('apiKey', $method->getName());
        }
    }

    /**
     * 🛑 The Meilisearch transport takes a **path**, never a URL.
     *
     * That signature is the structural defence: no tenant input, no project
     * input and no reader input can influence where it connects. §8.3.9's
     * address policy exists for URLs derived from user-supplied configuration,
     * and this destination is `DB_HOST`-class installation configuration — so
     * what it needs is to be impossible to point elsewhere, which a path
     * parameter is and a URL parameter is not.
     */
    public function test_the_search_transport_takes_a_path_and_not_a_url(): void
    {
        $send = new \ReflectionMethod(SearchTransport::class, 'send');
        $names = array_map(
            static fn (\ReflectionParameter $p): string => $p->getName(),
            $send->getParameters(),
        );

        $this->assertSame(['method', 'path', 'payload'], $names);
        $this->assertNotContains('url', $names);
        $this->assertNotContains('host', $names);
        $this->assertNotContains('origin', $names);

        /* And the implementation refuses anything that is not origin-relative. */
        $this->assertStringContainsString(
            "str_starts_with(\$path, '//')",
            $this->code(base_path('app/Egress/MeilisearchTransport.php')),
            'a protocol-relative path would be a URL',
        );
    }

    /**
     * 🛑 Nothing under `app/` truncates the audit trail.
     *
     * §8.22.1 makes `audit_events` append-only with a database trigger, and a
     * trigger only guards `UPDATE` and `DELETE` — `TRUNCATE` is DDL and goes
     * straight through it. So the one statement that could empty the audit
     * trail without tripping the control is the one nothing in the
     * application may contain.
     *
     * Here because Phase 29's test harness needed exactly that statement to
     * clean up after tests that commit ({@see CommitsSearchDocuments}),
     * and a capability a test needs is a capability worth fencing off from
     * everything else.
     */
    public function test_no_application_code_truncates_the_audit_trail(): void
    {
        $offenders = [];

        foreach ($this->appFiles() as $file) {
            $source = $this->code($file);

            if (preg_match('/TRUNCATE\\s+TABLE\\s+.?audit_/i', $source) === 1) {
                $offenders[] = $this->relative($file);
            }
        }

        $this->assertSame(
            [],
            $offenders,
            '§8.22.1: TRUNCATE bypasses the append-only trigger, so no application code may use it. '
            .'Offenders: '.implode(', ', $offenders),
        );
    }

    /**
     * 🛑 §8.16.11: no foreign keys on `search_documents`, asserted in the
     * migration's source as well as in the live schema.
     *
     * `SearchSchemaTest` asserts the schema. This asserts the **intent**: a
     * later migration adding one would be caught here even on a database that
     * had not been migrated.
     */
    public function test_the_search_migration_declares_no_foreign_key_on_the_document_table(): void
    {
        $migration = (string) file_get_contents(
            base_path('database/migrations/2026_11_14_090000_create_search_tables.php'),
        );

        $start = strpos($migration, "Schema::create('search_documents'");
        $end = strpos($migration, 'ALTER TABLE');

        $this->assertIsInt($start);
        $this->assertIsInt($end);

        $block = substr($migration, $start, $end - $start);

        $this->assertStringNotContainsString(
            '->foreign(',
            $block,
            '§8.16.11 declines foreign keys here: the retention sweep must not cascade',
        );
    }
}
