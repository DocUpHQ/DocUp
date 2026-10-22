<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Credentials;

use Monolog\LogRecord;
use Monolog\Processor\ProcessorInterface;

/**
 * Removes credentials from every log record, at every level (§8.5.21).
 *
 * Phase 05's exit criterion is "no token appears in any log, at any log
 * level". Two mechanisms, because either alone is insufficient:
 *
 * 1. 🛑 **Known values**, from {@see SecretRegistry} — the literal, its base64
 *    forms and its URL-encoded forms. This is the one §8.5.21 actually
 *    specifies, and it is the only mechanism that can redact a deploy key or
 *    an opaque self-hosted token, neither of which has a recognisable shape.
 * 2. **Known shapes**, below. This catches the credential that was never
 *    registered because it never passed through a {@see SecretString} — the
 *    token pasted into the wrong form field and echoed back in a validation
 *    error, the `Authorization` header captured by an HTTP debug dump, the
 *    PEM block in an exception from a library that knows nothing about us.
 *
 * Mechanism 2 exists precisely for the paths mechanism 1 cannot see, so a
 * reviewer should resist the urge to delete it as redundant: the day it fires
 * is the day something leaked outside the vault.
 *
 * 🛑 This is a **last line**, not the design. The design is that credentials
 * live in {@see SecretString} and are never interpolated. A redactor is what
 * stops a mistake becoming an incident; it is not a licence to be careless,
 * because it only knows the encodings it has been taught.
 */
final class SecretRedactor implements ProcessorInterface
{
    public const MARKER = '[redacted]';

    /**
     * Shapes that are credentials wherever they appear.
     *
     * Each is anchored on a vendor prefix or an unmistakable delimiter rather
     * than on entropy. An entropy heuristic redacts commit SHAs, UUIDs and
     * base64 payloads, which makes logs useless and gets the processor
     * removed — the same failure mode as an over-eager security control
     * anywhere else.
     *
     * @var list<string>
     */
    private const PATTERNS = [
        // GitHub: classic and fine-grained tokens, and the five prefixed kinds.
        '/\bgh[pousr]_[A-Za-z0-9]{16,255}\b/',
        '/\bgithub_pat_[A-Za-z0-9_]{20,255}\b/',

        // GitLab: personal, runner, deploy and feed tokens share the prefix shape.
        '/\bgl(?:pat|rt|dt|ft|soat|agent)-[A-Za-z0-9_\-]{16,255}\b/',

        // Atlassian / Bitbucket app passwords and API tokens.
        '/\bAT(?:BB|CTT)[A-Za-z0-9_\-=]{8,255}\b/',

        // DocUp's own tokens (§9.1.4), whatever prefix they were minted with.
        '/\bdocup(?:_[a-z]+)?_[A-Za-z0-9_\-]{16,255}\b/',

        // Any PEM private key, including the OpenSSH container a deploy key uses.
        '/-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----/s',

        // A credential in a URL authority. Keeps the scheme and the host, so
        // the line still says where the request was going.
        '/(?<=:\/\/)[^\/\s:@]+:[^\/\s@]+(?=@)/',

        // `Authorization: Bearer …`, `Authorization: Basic …`, and the bare
        // `token …` form several provider clients use.
        '/\b(?:Bearer|Basic|token)\s+[A-Za-z0-9_\-.=+\/]{12,}/i',
    ];

    /**
     * Context and extra keys whose **value** is always a credential,
     * regardless of shape.
     *
     * @var list<string>
     */
    private const SENSITIVE_KEYS = [
        'authorization', 'password', 'secret', 'token', 'access_token',
        'refresh_token', 'private_key', 'client_secret', 'api_key', 'passphrase',
        'credential', 'credentials', 'webhook_secret', 'app_key',
    ];

    public function __invoke(LogRecord $record): LogRecord
    {
        return $record->with(
            message: $this->scrub($record->message),
            context: $this->scrubArray($record->context),
            extra: $this->scrubArray($record->extra),
        );
    }

    /** Public so the redaction can be tested, and reused outside Monolog. */
    public function scrub(string $text): string
    {
        $text = SecretRegistry::scrub($text, self::MARKER);

        foreach (self::PATTERNS as $pattern) {
            $replaced = preg_replace($pattern, self::MARKER, $text);

            if ($replaced !== null) {
                $text = $replaced;
            }
        }

        return $text;
    }

    /**
     * @param  array<array-key, mixed>  $values
     * @return array<array-key, mixed>
     */
    public function scrubArray(array $values, int $depth = 0): array
    {
        // A record nested deeper than this is a cycle or a dumped object
        // graph; neither is worth unbounded work on the logging path.
        if ($depth > 8) {
            return [self::MARKER];
        }

        $scrubbed = [];

        foreach ($values as $key => $value) {
            if (is_string($key) && in_array(strtolower($key), self::SENSITIVE_KEYS, true)) {
                $scrubbed[$key] = self::MARKER;

                continue;
            }

            $scrubbed[$key] = match (true) {
                is_string($value) => $this->scrub($value),
                is_array($value) => $this->scrubArray($value, $depth + 1),
                $value instanceof SecretString => SecretString::REDACTED,
                $value instanceof \Throwable => $this->scrub($value->getMessage()),
                default => $value,
            };
        }

        return $scrubbed;
    }
}
