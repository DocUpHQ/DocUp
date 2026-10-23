<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds;

use App\Models\ProjectVersion;

/**
 * §11.4's `PublishSource` seam: where a publishable tree came from.
 *
 * 🛑 §8.21.6 is the requirement, and it is a statement about **power**, not
 * about code reuse:
 *
 * > "A **direct artifact upload** API MUST accept a validated archive … and
 * > reuse the collect, compose, store and publish stages unchanged. The
 * > built-in runner MUST be implemented as the **first consumer** of this
 * > path, not a privileged special case, so bring-your-own-CI is a permanent
 * > capability rather than a deferred feature."
 *
 * The failure mode it rules out is the familiar one: the built-in runner gets
 * a direct route into the store because it is "ours and therefore trusted",
 * the upload API gets a second route with its own validation, and within a
 * year the two disagree about something — usually about what the output
 * contract permits. Then bring-your-own-CI is a second-class citizen whose
 * bugs nobody reproduces, because the maintainers only ever exercise the
 * built-in path.
 *
 * With one seam there is one ingest, one set of §8.8.2 validations and one
 * §8.4.5 contract check. The runner gets no capability an operator's CI does
 * not have, which also means an operator's CI gets every capability the
 * runner has.
 */
interface PublishSource
{
    /**
     * A local archive of the tree to publish.
     *
     * A path rather than a stream, because `ArtifactIngestor` reads an archive
     * twice — once to validate it entirely and once to extract — and §8.8.2's
     * guarantee that nothing is written before the whole tree has been judged
     * depends on being able to.
     */
    public function archivePath(): string;

    public function version(): ProjectVersion;

    /** Raw 16 bytes, or null when the system did it rather than a person. */
    public function actorId(): ?string;

    /**
     * §8.5.24's provenance inputs: "plan digest, image digest, tool versions,
     * source SHAs, actor".
     *
     * An upload from somebody else's CI legitimately knows less than the
     * built-in runner does, so this returns what the source can honestly say
     * rather than a fixed shape padded with nulls. {@see Provenance} records
     * the difference explicitly, because "we do not know" and "there was
     * nothing" are not the same claim about a build.
     *
     * @return array<string, mixed>
     */
    public function provenanceFacts(): array;
}
