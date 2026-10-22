<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Serving;

/** The three things file resolution can conclude. */
enum FileKind: string
{
    /** A manifest entry, ready for the §8.9.8 handoff. */
    case File = 'file';

    /** A directory reached without its trailing slash (SPEC 8.9.7). */
    case Directory = 'directory';

    /** Nothing in the manifest answers this path. */
    case Rejected = 'rejected';
}
