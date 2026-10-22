<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Credentials;

use App\Auth\OrganisationContext;
use App\Credentials\CredentialKind;
use App\Credentials\CredentialVault;
use App\Credentials\SecretRedactor;
use App\Credentials\SecretRegistry;
use App\Credentials\SecretString;
use App\Logging\RedactSecrets;
use App\Models\Organisation;
use App\Source\Provider;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\Log;
use Tests\TestCase;

/**
 * 🛑 Phase 05's exit criterion: **no token appears in any log, at any log
 * level.**
 *
 * The level is the easy half — Monolog runs a processor over every record a
 * channel accepts, whatever its level, so all eight are asserted here mostly
 * to prove the wiring is not level-conditional.
 *
 * The hard half is the **route**. A credential does not reach a log because
 * somebody decided to log it; it reaches a log through
 * `Log::debug('…', ['repository' => $model])` on something that happens to
 * carry one, through `"$exception"` on a message that interpolated a URL, or
 * through a `dd()` left behind. So the cases below are those routes, not a
 * developer logging a token on purpose:
 *
 *  - the literal value, and its base64 and URL-encoded forms (§8.5.21);
 *  - a value nested inside a context array, and inside an exception;
 *  - a value that never passed through the vault at all, caught by shape;
 *  - a {@see SecretString} cast to a string, JSON-encoded, and dumped.
 */
final class NoTokenInLogsTest extends TestCase
{
    use DatabaseTransactions;

    private const TOKEN = 'ghp_s3cr3tTOKENvalue0123456789abcdefABCD';

    private const DEPLOY_KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----";

    private OrganisationContext $context;

    private string $logPath;

    protected function setUp(): void
    {
        parent::setUp();

        SecretRegistry::flush();

        $this->context = app(OrganisationContext::class);
        $this->context->spanAllOrganisations();

        $this->logPath = storage_path('logs/phase05-redaction-'.bin2hex(random_bytes(4)).'.log');

        // A real channel with a real file, built the way `config/logging.php`
        // builds `single` — tap included. Asserting on a file rather than on a
        // fake is the point: the criterion is about what is written to disk.
        config()->set('logging.channels.phase05', [
            'driver' => 'single',
            'path' => $this->logPath,
            'level' => 'debug',
            'replace_placeholders' => true,
            'tap' => [RedactSecrets::class],
        ]);
    }

    protected function tearDown(): void
    {
        $this->context->forget();
        SecretRegistry::flush();

        if (is_file($this->logPath)) {
            unlink($this->logPath);
        }

        parent::tearDown();
    }

    /**
     * 🛑 Every level, and every route, against a real log file.
     */
    public function test_no_credential_reaches_the_log_at_any_level(): void
    {
        $organisation = Organisation::query()->create([
            'name' => 'Logging Co',
            'slug' => 'logging-'.bin2hex(random_bytes(4)),
        ]);

        $this->context->for($organisation->id);

        // Stored through the vault, which is what registers the value.
        app(CredentialVault::class)->store(
            organisationId: $organisation->id,
            kind: CredentialKind::PersonalAccessToken,
            provider: Provider::GitHub,
            providerHost: 'github.com',
            displayName: 'CI',
            payload: ['token' => self::TOKEN],
        );

        $secret = new SecretString(self::TOKEN);
        $channel = Log::channel('phase05');

        foreach (['debug', 'info', 'notice', 'warning', 'error', 'critical', 'alert', 'emergency'] as $level) {
            // The literal, interpolated into the message.
            $channel->{$level}('fetching with '.self::TOKEN);

            // Its encodings (§8.5.21).
            $channel->{$level}('encoded '.base64_encode(self::TOKEN).' and '.rawurlencode(self::TOKEN));

            // Nested in context, which is how a model or an array carries it.
            $channel->{$level}('attaching repository', [
                'repository' => ['clone_url' => 'https://x:'.self::TOKEN.'@github.com/acme/docs.git'],
                'authorization' => 'Bearer '.self::TOKEN,
                'nested' => ['deep' => ['token' => self::TOKEN]],
            ]);

            // An exception whose message interpolated it.
            $channel->{$level}('failed', ['exception' => new \RuntimeException('401 for '.self::TOKEN)]);

            // A SecretString, by cast, by JSON and in context.
            $channel->{$level}("secret is {$secret}", ['secret' => $secret, 'json' => json_encode(['t' => $secret])]);

            // A credential that never passed through the vault — caught by
            // shape alone, which is the half the registry cannot do.
            $channel->{$level}('stray glpat-UNREGISTEREDvalue12345 and '.self::DEPLOY_KEY);
        }

        $written = (string) file_get_contents($this->logPath);

        $this->assertNotSame('', $written, 'nothing was logged, so nothing was proven');

        foreach ([
            'the literal token' => self::TOKEN,
            'base64' => base64_encode(self::TOKEN),
            'base64 unpadded' => rtrim(base64_encode(self::TOKEN), '='),
            'url-encoded' => rawurlencode(self::TOKEN),
            'the unregistered GitLab token' => 'glpat-UNREGISTEREDvalue12345',
            'the deploy key body' => 'b3BlbnNzaC1rZXktdjEAAAAA',
        ] as $what => $needle) {
            $this->assertStringNotContainsString($needle, $written, $what.' reached the log');
        }

        // 🛑 And the log is still useful: redaction that ate the whole line
        // would pass the assertions above and be worthless.
        $this->assertStringContainsString('attaching repository', $written);
        $this->assertStringContainsString('github.com/acme/docs.git', $written);
        $this->assertStringContainsString(SecretRedactor::MARKER, $written);
    }

    /**
     * A {@see SecretString} cannot be printed, encoded or dumped by accident.
     *
     * Asserted on the value object rather than through a log, because these
     * are the three casts every accidental leak goes through and they must
     * hold wherever the object ends up — a Blade template, an Inertia prop,
     * a queue payload.
     */
    public function test_a_secret_string_cannot_be_printed_or_encoded(): void
    {
        $secret = new SecretString(self::TOKEN);

        $this->assertSame('[redacted]', (string) $secret);
        $this->assertSame('"[redacted]"', (string) json_encode($secret));
        $this->assertSame(['value' => '[redacted]'], $secret->__debugInfo());
        $this->assertSame(self::TOKEN, $secret->reveal());

        // 🛑 Refused rather than redacted: a queued job holding the string
        // "[redacted]" would fail against the provider hours later and
        // nowhere near the cause.
        $this->expectException(\LogicException::class);
        serialize($secret);
    }

    /** The registry is bounded, so a long-lived worker cannot grow without limit. */
    public function test_the_secret_registry_is_bounded(): void
    {
        SecretRegistry::flush();

        for ($i = 0; $i < 400; $i++) {
            SecretRegistry::remember('secret-value-'.str_pad((string) $i, 8, '0', STR_PAD_LEFT));
        }

        $this->assertLessThanOrEqual(256, SecretRegistry::count());
    }

    /** Short values are ignored, or every log line would be redaction marks. */
    public function test_short_values_are_not_registered(): void
    {
        SecretRegistry::flush();
        SecretRegistry::remember('abc');

        $this->assertSame('abc appears here', SecretRegistry::scrub('abc appears here', '[redacted]'));
        $this->assertSame(0, SecretRegistry::count());
    }
}
