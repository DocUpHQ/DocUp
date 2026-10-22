<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Artifacts;

use App\Artifacts\Exceptions\IngestRejected;
use App\Audit\CanonicalJson;

/**
 * The per-build file manifest: `path → sha256, bytes, content type` (§8.4.18).
 *
 * 🛑 Not to be confused with the **version** manifest of §8.8.3, which is a
 * database row naming the mounted components a version serves. This is the
 * artifact-level index of one build's bytes, stored beside them. §8.4.18 gives
 * it five jobs and they share one property: all five must be answerable
 * **without a storage existence probe per request**. The 404 chain, strong
 * ETags, 404 suggestions, cross-version page existence and link validation are
 * all "does this path exist, and what is it" — asked once per request on the
 * hottest path in the product. A `HEAD` to S3 per request is the design this
 * replaces.
 *
 * 🛑 It must also never become a SQL routing table on the serving path
 * (§8.4.18). That is why it is stored as bytes in the artifact store rather
 * than exploded into rows: the serving edge loads one object and answers from
 * it, and no request pattern turns into a query.
 *
 * Encoded through {@see CanonicalJson}, so the same tree always produces
 * byte-identical manifest bytes — which is what lets {@see self::digest()} be
 * part of a build's identity and lets a rollback be proved byte-exact.
 */
final class FileManifest implements \Countable
{
    /**
     * The wire schema identifier.
     *
     * Versioned in the payload rather than implied, because a reader that
     * cannot tell which shape it has must guess, and §8.1.11's stability
     * promise means old manifests stay readable after the shape changes.
     */
    public const SCHEMA = 'docup.file-manifest/1';

    /** @var array<string, array{sha256: string, bytes: int, content_type: string}> */
    private array $files = [];

    /**
     * Record one file.
     *
     * @param  string  $path  manifest-relative, already validated by the ingestor
     * @param  string  $sha256  lowercase hex of the stored bytes
     *
     * @throws IngestRejected when the path is already present
     */
    public function add(string $path, string $sha256, int $bytes): void
    {
        /*
         * 🛑 The duplicate check lives here as well as in the ingestor's
         * validation pass. Belt and braces on purpose: this class is what the
         * strong ETag and the integrity check read, so a second write to one
         * path would silently replace a digest that something else had already
         * served. Cheaper to refuse twice than to debug once.
         */
        if (isset($this->files[$path])) {
            throw IngestRejected::because(RejectionCode::DuplicateEntry, $path);
        }

        $this->files[$path] = [
            'sha256' => $sha256,
            'bytes' => $bytes,
            'content_type' => ContentTypes::forPath($path),
        ];
    }

    public function has(string $path): bool
    {
        return isset($this->files[$path]);
    }

    /** @return array{sha256: string, bytes: int, content_type: string}|null */
    public function get(string $path): ?array
    {
        return $this->files[$path] ?? null;
    }

    /** @return list<string> sorted, so callers get a stable order */
    public function paths(): array
    {
        $paths = array_keys($this->files);
        sort($paths, SORT_STRING);

        return $paths;
    }

    public function totalBytes(): int
    {
        return array_sum(array_column($this->files, 'bytes'));
    }

    public function count(): int
    {
        return count($this->files);
    }

    /**
     * The wire form.
     *
     * @return array{schema: string, files: array<string, array{sha256: string, bytes: int, content_type: string}>}
     */
    public function toArray(): array
    {
        return ['schema' => self::SCHEMA, 'files' => $this->files];
    }

    /**
     * Canonical bytes, via §8.22's frozen encoder.
     *
     * Reusing the audit chain's encoder rather than `json_encode` is the whole
     * point: it sorts keys recursively and refuses floats, so two ingests of
     * one tree cannot differ by key order or by `serialize_precision`. A
     * manifest that is not byte-stable cannot be compared, and §8.8.5's
     * "rollback restores build 1's bytes exactly" is a claim about comparison.
     */
    public function encode(): string
    {
        return CanonicalJson::encode($this->toArray());
    }

    /** sha256 of the canonical bytes, for build provenance and integrity. */
    public function digest(): string
    {
        return hash('sha256', $this->encode());
    }

    /**
     * Read a manifest back from its stored bytes.
     *
     * Validates the shape rather than trusting it. The manifest is read by the
     * serving path, and a corrupt or truncated object there would otherwise
     * surface as a type error deep inside a response — so it is rejected at the
     * boundary, where the build id is still in hand.
     *
     * @throws IngestRejected when the bytes are not a manifest of this schema
     */
    public static function decode(string $json): self
    {
        try {
            /** @var mixed $payload */
            $payload = json_decode($json, true, 64, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw IngestRejected::because(RejectionCode::UnreadableArchive, detail: 'manifest is not JSON: '.$e->getMessage());
        }

        if (! is_array($payload) || ($payload['schema'] ?? null) !== self::SCHEMA || ! is_array($payload['files'] ?? null)) {
            throw IngestRejected::because(RejectionCode::UnreadableArchive, detail: 'manifest schema mismatch');
        }

        $manifest = new self;

        /** @var array<array-key, mixed> $files */
        $files = $payload['files'];

        foreach ($files as $path => $entry) {
            if (! is_string($path) || ! is_array($entry)) {
                throw IngestRejected::because(RejectionCode::UnreadableArchive, detail: 'malformed manifest entry');
            }

            $sha256 = $entry['sha256'] ?? null;
            $bytes = $entry['bytes'] ?? null;

            if (! is_string($sha256) || preg_match('/^[0-9a-f]{64}$/', $sha256) !== 1 || ! is_int($bytes) || $bytes < 0) {
                throw IngestRejected::because(RejectionCode::UnreadableArchive, $path, 'malformed manifest entry');
            }

            $manifest->add($path, $sha256, $bytes);
        }

        return $manifest;
    }
}
