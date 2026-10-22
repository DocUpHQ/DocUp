<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Serving;

/** The three things resolution can conclude. */
enum RouteKind: string
{
    /** A version was found; a file path remains for the manifest to answer. */
    case Resolved = 'resolved';

    /** §8.9.7: the empty path, or a directory without its trailing slash. */
    case Redirect = 'redirect';

    /** Nothing matched, or something matched that may not be served. */
    case Rejected = 'rejected';
}
