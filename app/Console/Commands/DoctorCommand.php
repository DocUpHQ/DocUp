<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Console\Commands;

use App\Audit\Audit;
use App\Builds\Runner\Spool;
use App\Builds\Sandbox\EgressAllowlist;
use App\Builds\Sandbox\SandboxPolicy;
use App\Support\Origins;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Mail;

/**
 * `docup:doctor` - the pre-flight and misconfiguration check (SPEC 8.1.9).
 *
 * The specification's reasoning is that an enterprise self-host product is
 * judged in its first ten minutes, and that the failures which lose an
 * evaluator are configuration failures the application could have detected and
 * explained. So every check here reports what is wrong, why it matters, and the
 * section that says so - never just a red cross.
 *
 * Checks arrive with the phases that make them meaningful. SPEC 8.1.9 lists the
 * full set; this is Phase 01's subset, and each later phase appends its own.
 * The ones listed there and not yet implemented are reported as PENDING rather
 * than silently absent, so the gap is visible instead of assumed covered.
 */
final class DoctorCommand extends Command
{
    protected $signature = 'docup:doctor {--json : Machine-readable output}';

    protected $description = 'Check this installation for misconfiguration (SPEC 8.1.9)';

    /** @var list<array{status: string, check: string, detail: string, ref: string}> */
    private array $results = [];

    public function handle(): int
    {
        $this->checkOrigins();
        $this->checkUnsafeModes();
        $this->checkDatabase();
        $this->checkArgon();
        $this->checkDevelopmentServices();
        $this->checkMail();
        $this->checkAuditKey();
        $this->checkAuditPartitions();
        $this->checkAuditAppendOnly();
        $this->checkBuildSandbox();
        $this->notePending();

        if ($this->option('json')) {
            $this->line((string) json_encode($this->results, JSON_PRETTY_PRINT));
        } else {
            $this->render();
        }

        return $this->hasFailures() ? self::FAILURE : self::SUCCESS;
    }

    /**
     * 🛑 §8.22.1: the audit chain needs `k_audit`, held outside `APP_KEY`.
     *
     * A failure rather than a warning. Without the key every audited action
     * throws, and §8.22.4 commits the audit row in the same transaction as the
     * mutation — so an installation missing this key cannot perform a
     * state-changing action at all. Reporting that as a warning would describe
     * a dead installation as merely imperfect.
     */
    private function checkAuditKey(): void
    {
        if (! Audit::hasKey()) {
            $this->recordFail(
                'Audit key',
                'DOCUP_AUDIT_KEY is not set; every audited action will fail',
                'SPEC 8.22.1',
            );

            return;
        }

        $appKey = config('app.key');
        $auditKey = config('docup.audit.key');

        // The one way to satisfy the check while defeating its purpose: set the
        // audit key to APP_KEY. §8.22.1 separates them so that holding the key
        // the application needs daily is not enough to forge the log.
        if (is_string($appKey) && is_string($auditKey) && hash_equals($appKey, $auditKey)) {
            $this->recordFail(
                'Audit key',
                'DOCUP_AUDIT_KEY is the same value as APP_KEY, which defeats the separation',
                'SPEC 8.22.1',
            );

            return;
        }

        $this->recordPass('Audit key', 'set, and distinct from APP_KEY', 'SPEC 8.22.1');
    }

    /**
     * 🛑 §16 pairs the `MAXVALUE` catch-all partition with alerting, and this is
     * that alerting.
     *
     * The catch-all exists so that a lapse in monthly maintenance degrades
     * instead of failing: without it, an insert past the last boundary is
     * rejected, and because §8.22.4 commits the audit row in the same
     * transaction as the mutation, the whole dashboard would stop accepting
     * writes. With it, events pile into one fat partition and nothing appears
     * wrong — which is precisely why it has to be reported. A silent safety net
     * is a safety net nobody notices has been load-bearing for a year.
     */
    private function checkAuditPartitions(): void
    {
        $nextMonth = now('UTC')->startOfMonth()->addMonth();

        /** @var list<object{PARTITION_NAME: string|null, PARTITION_DESCRIPTION: string|null, TABLE_ROWS: int|string|null}> $partitions */
        $partitions = DB::select(
            'SELECT PARTITION_NAME, PARTITION_DESCRIPTION, TABLE_ROWS
               FROM information_schema.PARTITIONS
              WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? AND PARTITION_NAME IS NOT NULL',
            [DB::connection()->getDatabaseName(), 'audit_events'],
        );

        if ($partitions === []) {
            $this->recordFail(
                'Audit log partitions',
                'audit_events is not partitioned; monthly retention by DROP PARTITION is impossible',
                'SPEC 8.22.1',
            );

            return;
        }

        $covered = false;
        $catchAllRows = 0;

        foreach ($partitions as $partition) {
            $description = (string) $partition->PARTITION_DESCRIPTION;

            if ($description === 'MAXVALUE') {
                $catchAllRows = (int) $partition->TABLE_ROWS;

                continue;
            }

            // RANGE COLUMNS boundaries come back quoted, e.g. "'2026-12-01'".
            $boundary = trim($description, "'\"");

            if ($boundary > $nextMonth->format('Y-m-d')) {
                $covered = true;
            }
        }

        if (! $covered) {
            $this->recordWarn(
                'Audit log partitions',
                'no partition covers beyond '.$nextMonth->format('Y-m').
                '; events will fall into the MAXVALUE catch-all until maintenance adds more',
                'SPEC 8.22.1',
            );

            return;
        }

        if ($catchAllRows > 0) {
            $this->recordWarn(
                'Audit log partitions',
                "the MAXVALUE catch-all holds ~{$catchAllRows} rows, so some events landed outside a monthly partition",
                'SPEC 8.22.1',
            );

            return;
        }

        $this->recordPass(
            'Audit log partitions',
            count($partitions).' partitions, next month covered, catch-all empty',
            'SPEC 8.22.1',
        );
    }

    /**
     * 🛑 §8.22.1: the audit log must be insert-only for the application.
     *
     * A failure, not a warning. An operator who skipped the setup script has a
     * log that looks chained and verifies, while being rewritable by the very
     * application that writes it — a worse position than having no audit log,
     * because it is believed.
     *
     * Checked by looking for the guards rather than by attempting an UPDATE:
     * `doctor` must be safe to run against a production installation, and a
     * diagnostic that writes to the audit log in order to prove it cannot
     * write to the audit log is not one anybody should run twice.
     */
    private function checkAuditAppendOnly(): void
    {
        /** @var list<object{EVENT_OBJECT_TABLE: string, EVENT_MANIPULATION: string}> $triggers */
        $triggers = DB::select(
            'SELECT EVENT_OBJECT_TABLE, EVENT_MANIPULATION
               FROM information_schema.TRIGGERS
              WHERE TRIGGER_SCHEMA = ? AND EVENT_OBJECT_TABLE IN (?, ?)',
            [DB::connection()->getDatabaseName(), 'audit_events', 'audit_anchors'],
        );

        $present = [];

        foreach ($triggers as $trigger) {
            $present[$trigger->EVENT_OBJECT_TABLE.':'.$trigger->EVENT_MANIPULATION] = true;
        }

        $missing = array_values(array_filter(
            ['audit_events:UPDATE', 'audit_events:DELETE', 'audit_anchors:UPDATE', 'audit_anchors:DELETE'],
            static fn (string $guard): bool => ! isset($present[$guard]),
        ));

        if ($missing !== []) {
            $this->recordFail(
                'Audit log is append-only',
                'missing guards ('.implode(', ', $missing).'); apply '
                .'deploy/mysql/init/10-audit-append-only.sql as a database administrator',
                'SPEC 8.22.1',
            );

            return;
        }

        $this->recordPass('Audit log is append-only', 'UPDATE and DELETE refused on both tables', 'SPEC 8.22.1');
    }

    private function recordPass(string $check, string $detail, string $ref): void
    {
        $this->results[] = ['status' => 'pass', 'check' => $check, 'detail' => $detail, 'ref' => $ref];
    }

    private function recordWarn(string $check, string $detail, string $ref): void
    {
        $this->results[] = ['status' => 'warn', 'check' => $check, 'detail' => $detail, 'ref' => $ref];
    }

    private function recordFail(string $check, string $detail, string $ref): void
    {
        $this->results[] = ['status' => 'fail', 'check' => $check, 'detail' => $detail, 'ref' => $ref];
    }

    private function recordPending(string $check, string $detail, string $ref): void
    {
        $this->results[] = ['status' => 'pending', 'check' => $check, 'detail' => $detail, 'ref' => $ref];
    }

    private function hasFailures(): bool
    {
        foreach ($this->results as $result) {
            if ($result['status'] === 'fail') {
                return true;
            }
        }

        return false;
    }

    /** 🛑 The invariant that loses an evaluator in minute one if it is wrong. */
    private function checkOrigins(): void
    {
        $app = config('docup.origins.app');
        $docs = config('docup.origins.docs');
        $preview = config('docup.origins.preview');

        try {
            Origins::assert(
                is_string($app) ? $app : null,
                is_string($docs) ? $docs : null,
                is_string($preview) ? $preview : null,
                (bool) config('docup.unsafe.single_origin'),
            );

            if ((bool) config('docup.unsafe.single_origin')) {
                $this->recordWarn(
                    'Origin separation',
                    'DOCUP_UNSAFE_SINGLE_ORIGIN is set: every project is forced public and '
                    .'private sharing and tenant CSS are disabled.',
                    'SPEC 8.1.5',
                );
            } else {
                $this->recordPass(
                    'Origin separation',
                    sprintf('dashboard %s, docs %s', Origins::registrable((string) $app), Origins::registrable((string) $docs)),
                    'SPEC 8.1.4',
                );
            }
        } catch (\Throwable $e) {
            $this->recordFail('Origin separation', $e->getMessage(), 'SPEC 8.1.4');
        }

        if (! Origins::previewsEnabled()) {
            $this->recordWarn(
                'Pull-request previews',
                'DOCUP_PREVIEW_APEX is unset, so previews are disabled. That is a supported '
                .'configuration, not an error - previews need a third registrable domain.',
                'SPEC 8.1.4',
            );
        }
    }

    private function checkUnsafeModes(): void
    {
        $enabled = [];

        foreach ((array) config('docup.unsafe') as $flag => $value) {
            if ((bool) $value) {
                $enabled[] = (string) $flag;
            }
        }

        if ($enabled === []) {
            $this->recordPass('Unsafe modes', 'all closed', 'SPEC 8.22.11');

            return;
        }

        $this->recordWarn(
            'Unsafe modes',
            'enabled: '.implode(', ', $enabled).'. Each one disables a control the rest of the '
            .'specification assumes is present.',
            'SPEC 20.4',
        );
    }

    private function checkDatabase(): void
    {
        try {
            $version = (string) DB::scalar('SELECT VERSION()');

            // SPEC 11.1: MySQL 8.4 LTS minimum; 8.0 reached EOL in April 2026.
            if (preg_match('/^(\d+)\.(\d+)/', $version, $m) === 1) {
                $major = (int) $m[1];
                $minor = (int) $m[2];
                $tooOld = $major < 8 || ($major === 8 && $minor < 4);

                if ($tooOld) {
                    $this->recordFail(
                        'Database version',
                        "MySQL {$version} is below the 8.4 LTS floor; 8.0 reached end of life in April 2026.",
                        'SPEC 11.1',
                    );
                } else {
                    $this->recordPass('Database version', "MySQL {$version}", 'SPEC 11.1');
                }
            }

            // ADR 0004: the default search driver's three-character minimum
            // token is a documented limit operators ask about, so surface it.
            $minToken = DB::scalar('SELECT @@innodb_ft_min_token_size');
            $this->recordPass(
                'Search driver',
                sprintf(
                    '%s, FULLTEXT minimum token %s characters (terms shorter than this are not findable)',
                    (string) config('docup.search.driver'),
                    (string) $minToken,
                ),
                'SPEC 8.16.2',
            );
        } catch (\Throwable $e) {
            $this->recordFail('Database', $e->getMessage(), 'SPEC 11.1');
        }
    }

    /** 🛑 A weak framework default, not a DocUp one - which is why it is checked. */
    private function checkArgon(): void
    {
        $memory = (int) config('hashing.argon.memory');

        if ($memory < 19456) {
            $this->recordFail(
                'Password hashing',
                "Argon2id memory is {$memory} KiB, below the OWASP floor of 19456 KiB. Laravel's "
                .'own default is 1024, so this is a configuration that must be set, not inherited.',
                'SPEC 8.12.16',
            );

            return;
        }

        $this->recordPass('Password hashing', "Argon2id m={$memory} KiB, t=".(int) config('hashing.argon.time'), 'SPEC 8.12.16');
    }

    private function checkDevelopmentServices(): void
    {
        if (! app()->environment('production')) {
            $this->recordPass('Development services', 'not a production environment; MailPit and phpMyAdmin are expected', 'SPEC 8.1.3');

            return;
        }

        $reachable = [];

        foreach (['mailpit' => 8025, 'phpmyadmin' => 80] as $host => $port) {
            $socket = @fsockopen($host, $port, $errno, $errstr, 0.3);

            if ($socket !== false) {
                fclose($socket);
                $reachable[] = $host;
            }
        }

        if ($reachable !== []) {
            $this->recordFail(
                'Development services',
                'reachable in production: '.implode(', ', $reachable)
                .'. These must not exist in a production deployment.',
                'SPEC 8.1.3',
            );

            return;
        }

        $this->recordPass('Development services', 'not reachable', 'SPEC 8.1.3');
    }

    /**
     * 🛑 SPEC 8.18.5: doctor MUST test mail delivery, because a self-hoster with
     * no working SMTP otherwise gets silent failure on exactly the notification
     * that matters most - the build-failure email.
     */
    private function checkMail(): void
    {
        $mailer = (string) config('mail.default');

        if (in_array($mailer, ['log', 'array'], true)) {
            $this->recordWarn(
                'Mail delivery',
                "the [{$mailer}] mailer is configured, so no mail leaves this installation. "
                .'Build-failure notifications will be written to the log and nowhere else.',
                'SPEC 8.18.5',
            );

            return;
        }

        try {
            Mail::raw('DocUp doctor connectivity check.', static function ($message): void {
                $message->to('doctor@localhost')->subject('DocUp doctor');
            });

            $this->recordPass('Mail delivery', "sent a test message via [{$mailer}]", 'SPEC 8.18.5');
        } catch (\Throwable $e) {
            $this->recordFail('Mail delivery', $e->getMessage(), 'SPEC 8.18.5');
        }
    }

    /**
     * Checks SPEC 8.1.9 requires that this phase cannot yet perform.
     *
     * Reported rather than omitted: a doctor command that silently lacks half
     * its checks reads as a clean bill of health.
     */
    /**
     * §8.1.9's "an unsandboxed build runtime", plus everything else §8.5.9
     * and §8.5.12 give an operator to get wrong.
     *
     * 🛑 **Four separate findings rather than one "sandbox ok".** Each has
     * a different fix and a different severity, and collapsing them would
     * mean an operator with a perfectly good proxy and no isolation
     * declaration reading one red line that does not say which.
     */
    private function checkBuildSandbox(): void
    {
        $policy = SandboxPolicy::fromConfig();

        if (! $policy->buildsEnabled) {
            $this->recordPass(
                'Build sandbox',
                'hosting-only mode: no repository code runs on this installation',
                'SPEC 8.1.7',
            );

            return;
        }

        /*
         * A failure rather than a warning in production, because that is
         * what §8.5.11 makes it: the application refuses to boot. Reporting
         * it as a warning here would describe an installation that will not
         * start as merely imperfect.
         */
        if ($policy->isolation === null) {
            $this->recordFail(
                'Build isolation declaration',
                'DOCUP_BUILD_ISOLATION is unset. Production boot is refused without it, because '
                .'builds execute code from the repositories you connect and the choice of what '
                .'separates that code from this host is not one DocUp makes for you. Set gvisor '
                .'(recommended) or runc.',
                'SPEC 8.5.11',
            );
        } elseif ($policy->isolation === 'runc') {
            $this->recordWarn(
                'Build isolation declaration',
                'hardened runc: builds share this host kernel. gVisor (runsc) is the documented '
                .'production recommendation; runc is supported and is the default for '
                .'compatibility reasons, not security ones.',
                'SPEC 8.5.11',
            );
        } else {
            $this->recordPass('Build isolation declaration', $policy->isolation, 'SPEC 8.5.11');
        }

        if ($policy->egress->isUnrestricted()) {
            $this->recordWarn(
                'Build egress',
                'unrestricted: builds can reach any address this host can. The §8.5.9 allowlist '
                .'and the nftables backstop are both off.',
                'SPEC 8.5.9',
            );
        } else {
            $allowlist = EgressAllowlist::load();

            if ($allowlist->isEmpty()) {
                $this->recordFail(
                    'Build egress allowlist',
                    'no hosts could be read from '.$allowlist->path.'. The proxy refuses to start on '
                    .'an unreadable allowlist, so builds have no network at all - including the '
                    .'fetcher, which cannot reach a git host.',
                    'SPEC 8.5.9',
                );
            } else {
                $this->recordPass(
                    'Build egress allowlist',
                    count($allowlist->hosts).' hosts',
                    'SPEC 8.5.9',
                );
            }
        }

        /*
         * 🛑 Read from the spool, because this process has no runtime
         * socket and cannot run the self-test itself (§8.5.13). A missing
         * verdict is reported as missing rather than as unknown: no runner
         * has started since this spool existed, so nothing has checked.
         */
        $verdict = app(Spool::class)->readSelfTest();

        if ($verdict === null) {
            $this->recordFail(
                'Build network isolation self-test',
                'no verdict in the spool. The runner writes one at start-up (§8.5.12); if the '
                .'runner is running and this is empty, it is not sharing this spool directory.',
                'SPEC 8.5.12',
            );
        } elseif (! $verdict['passed']) {
            $this->recordFail('Build network isolation self-test', $verdict['summary'], 'SPEC 8.5.12');
        } else {
            $this->recordPass(
                'Build network isolation self-test',
                'passed '.(int) ((time() - $verdict['at']) / 60).' minutes ago',
                'SPEC 8.5.12',
            );
        }
    }

    private function notePending(): void
    {
        $this->recordPending('DNS wildcard for the docs zone', 'arrives with custom domains', 'Phase 18');
        $this->recordPending('Private-asset containment probe', 'arrives with the authorisation kernel', 'Phase 22');
        $this->recordPending('Search index size threshold', 'arrives with the search index', 'Phase 29');
    }

    private function render(): void
    {
        $icons = ['pass' => '<fg=green>  ok  </>', 'warn' => '<fg=yellow> warn </>', 'fail' => '<fg=red> FAIL </>', 'pending' => '<fg=gray>  --  </>'];

        $this->newLine();
        $this->line('  <options=bold>DocUp doctor</>');
        $this->newLine();

        foreach ($this->results as $result) {
            $this->line(sprintf(
                '  %s  %-34s %s',
                $icons[$result['status']],
                $result['check'],
                "<fg=gray>{$result['ref']}</>",
            ));

            if ($result['status'] !== 'pass') {
                $this->line('          <fg=gray>'.wordwrap($result['detail'], 96, "\n          ").'</>');
            }
        }

        $this->newLine();

        $counts = array_count_values(array_column($this->results, 'status'));

        $this->line(sprintf(
            '  %d ok, %d warnings, %d failures, %d pending',
            $counts['pass'] ?? 0,
            $counts['warn'] ?? 0,
            $counts['fail'] ?? 0,
            $counts['pending'] ?? 0,
        ));
        $this->newLine();
    }
}
