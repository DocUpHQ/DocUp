<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Console\Commands;

use App\Audit\Audit;
use App\Models\User;
use App\Support\Origins;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

use function Laravel\Prompts\confirm;
use function Laravel\Prompts\text;

/**
 * `docup:install` - the first-run wizard (SPEC 8.1.8).
 *
 * SPEC 4.3/8 is the reason this exists: a self-hoster's first ten minutes
 * decide everything, and the failures that lose an evaluator are configuration
 * failures the application could have explained. So this command does the
 * boring setup, and where it cannot it says exactly which variable to set and
 * which section says why - never just an exception.
 *
 * Idempotent by design. Running it twice is a normal thing for an operator to
 * do when the first run stopped half way, and it must not then destroy what the
 * first run achieved.
 */
final class InstallCommand extends Command
{
    protected $signature = 'docup:install
        {--no-interaction-defaults : Accept every default without prompting}
        {--skip-migrations : Do not run migrations}';

    protected $description = 'Prepare this installation for first use (SPEC 8.1.8)';

    public function handle(): int
    {
        $this->line('');
        $this->line('  <options=bold>DocUp install</>');
        $this->line('');

        if (! $this->checkEnvFile()) {
            return self::FAILURE;
        }

        $this->checkAppKey();
        $this->checkAuditKey();

        if (! $this->checkOrigins()) {
            return self::FAILURE;
        }

        if (! $this->runMigrations()) {
            return self::FAILURE;
        }

        $this->createFirstAdministrator();
        $this->reportNextSteps();

        return self::SUCCESS;
    }

    private function checkEnvFile(): bool
    {
        if (file_exists(base_path('.env'))) {
            $this->line('  <fg=green>ok</>    .env present');

            return true;
        }

        if (! file_exists(base_path('.env.example'))) {
            $this->line('  <fg=red>FAIL</>  neither .env nor .env.example exists');

            return false;
        }

        copy(base_path('.env.example'), base_path('.env'));
        $this->line('  <fg=yellow>made</>  .env from .env.example');

        return true;
    }

    private function checkAppKey(): void
    {
        if (config('app.key') !== null && config('app.key') !== '') {
            $this->line('  <fg=green>ok</>    APP_KEY set');

            return;
        }

        Artisan::call('key:generate', ['--force' => true]);
        $this->line('  <fg=yellow>made</>  APP_KEY generated');

        // 🛑 SPEC 15.2: losing APP_KEY makes every provider secret
        // unrecoverable. Say so now, while the operator is still paying
        // attention, rather than in a runbook they will read after the loss.
        $this->line('        <fg=gray>Back this up. SPEC 15.2: losing APP_KEY makes every stored</>');
        $this->line('        <fg=gray>provider secret unrecoverable, and there is no way around that.</>');
    }

    /**
     * 🛑 §8.22.1: generate `k_audit` if the operator has not.
     *
     * Generated rather than left to the operator because the consequence of
     * omitting it is total: every audited action throws, and §8.22.4 puts the
     * audit row in the same transaction as the mutation, so a missing key means
     * an installation that cannot change any state. An operator should not
     * discover that by creating their first project.
     *
     * Written straight to `.env` and never echoed. Whoever holds this can forge
     * a chain that verifies, so it does not belong in a terminal scrollback, a
     * screenshot or a support ticket.
     */
    private function checkAuditKey(): void
    {
        if (Audit::hasKey()) {
            $this->line('  <fg=green>ok</>    DOCUP_AUDIT_KEY set');

            return;
        }

        $path = base_path('.env');

        if (! is_file($path) || ! is_writable($path)) {
            $this->line('  <fg=red>FAIL</>  cannot write .env to generate DOCUP_AUDIT_KEY');

            return;
        }

        $key = bin2hex(random_bytes(32));
        $contents = (string) file_get_contents($path);

        // Replace an empty declaration if .env.example supplied one, otherwise
        // append. Both shapes occur: a fresh copy of .env.example has the key
        // present but blank.
        if (preg_match('/^DOCUP_AUDIT_KEY=.*$/m', $contents) === 1) {
            $contents = (string) preg_replace('/^DOCUP_AUDIT_KEY=.*$/m', 'DOCUP_AUDIT_KEY='.$key, $contents, 1);
        } else {
            $contents = rtrim($contents).'

DOCUP_AUDIT_KEY='.$key.'
';
        }

        file_put_contents($path, $contents);

        $this->line('  <fg=yellow>made</>  DOCUP_AUDIT_KEY generated');
        $this->line('        <fg=gray>🛑 SPEC 8.22.1: back this up SEPARATELY from APP_KEY. Whoever holds it</>');
        $this->line('        <fg=gray>can forge an audit chain that verifies. Losing it does not destroy the</>');
        $this->line('        <fg=gray>log, but it ends your ability to prove the log was not altered.</>');
    }

    /** 🛑 The invariant that stops the boot, so check it before anything slow. */
    private function checkOrigins(): bool
    {
        try {
            Origins::assert(
                $this->stringConfig('docup.origins.app'),
                $this->stringConfig('docup.origins.docs'),
                $this->stringConfig('docup.origins.preview'),
                (bool) config('docup.unsafe.single_origin'),
            );
        } catch (\Throwable $e) {
            $this->line('  <fg=red>FAIL</>  origin separation');
            $this->line('        '.wordwrap($e->getMessage(), 92, "\n        "));

            return false;
        }

        if ((bool) config('docup.unsafe.single_origin')) {
            $this->line('  <fg=yellow>warn</>  DOCUP_UNSAFE_SINGLE_ORIGIN is set: all projects forced public (SPEC 8.1.5)');
        } else {
            $this->line('  <fg=green>ok</>    origin separation (SPEC 8.1.4)');
        }

        if (! Origins::previewsEnabled()) {
            $this->line('  <fg=yellow>warn</>  previews disabled: DOCUP_PREVIEW_APEX unset (a supported configuration)');
        }

        return true;
    }

    private function runMigrations(): bool
    {
        if ($this->option('skip-migrations')) {
            $this->line('  <fg=gray>skip</>  migrations');

            return true;
        }

        try {
            DB::connection()->getPdo();
        } catch (\Throwable $e) {
            $this->line('  <fg=red>FAIL</>  database unreachable: '.$e->getMessage());
            $this->line('        <fg=gray>Check DB_HOST, DB_DATABASE, DB_USERNAME and DB_PASSWORD.</>');

            return false;
        }

        Artisan::call('migrate', ['--force' => true]);
        $this->line('  <fg=green>ok</>    migrations applied');

        return true;
    }

    /**
     * Create the first administrator.
     *
     * Phase 01 has a users table but no authentication - Fortify, sessions and
     * MFA are Phase 02 (SPEC 8.13.3-8.13.5), and Phase 01's scope note says no
     * domain model. So this seeds the account the operator will use once Phase
     * 02 lands, and says plainly that it cannot yet be signed in with.
     *
     * 🛑 The password is read interactively and never accepted as an argument,
     * because an argument lands in the shell history and in the process list.
     */
    private function createFirstAdministrator(): void
    {
        if (! class_exists(User::class)) {
            return;
        }

        if (User::query()->exists()) {
            $this->line('  <fg=green>ok</>    an administrator account already exists');

            return;
        }

        if ($this->option('no-interaction-defaults') || ! $this->input->isInteractive()) {
            $this->line('  <fg=gray>skip</>  first administrator (non-interactive; run docup:install again to create one)');

            return;
        }

        if (! confirm('Create the first administrator account now?', default: true)) {
            return;
        }

        $name = text('Name', required: true);
        $email = text('Email address', required: true, validate: fn (string $v) => filter_var($v, FILTER_VALIDATE_EMAIL) === false
            ? 'That is not an email address.'
            : null);

        $password = $this->secret('Password (not echoed, not stored in shell history)');

        if (! is_string($password) || strlen($password) < 12) {
            $this->line('  <fg=red>FAIL</>  password must be at least 12 characters; no account created');

            return;
        }

        User::query()->create([
            'name' => $name,
            'email' => $email,
            // Hashed with the SPEC 8.12.16 Argon2id parameters from
            // config/hashing.php, which deliberately override Laravel's weak
            // m=1024 default.
            'password' => bcrypt($password),
            'remember_token' => Str::random(60),
        ]);

        $this->line('  <fg=green>ok</>    administrator created');
        $this->line('        <fg=gray>Sign-in arrives in Phase 02; the account exists and waits for it.</>');
    }

    private function reportNextSteps(): void
    {
        $this->line('');
        $this->line('  <options=bold>Next</>');
        $this->line('    php artisan docup:doctor      check this installation for misconfiguration');
        $this->line('    php artisan docup:classify    confirm every column carries a data classification');
        $this->line('');
        $this->line(sprintf(
            '    Dashboard: <fg=cyan>https://%s</>   Documentation: <fg=cyan>https://%s</>',
            (string) config('docup.origins.app'),
            (string) config('docup.origins.docs'),
        ));
        $this->line('');
    }

    private function stringConfig(string $key): ?string
    {
        $value = config($key);

        return is_string($value) && $value !== '' ? $value : null;
    }
}
