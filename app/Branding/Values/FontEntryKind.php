<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding\Values;

/** What one entry in a {@see FontStackValue} names. */
enum FontEntryKind: string
{
    /** One of CSS's own generic families. Never fetched. */
    case Generic = 'generic';

    /** A family the installation self-hosts, from `config/branding.php`. */
    case Catalogue = 'catalogue';

    /** 🛑 §8.14.2's "self-hosted WOFF2 asset reference": `asset:<id>`. */
    case Asset = 'asset';
}
