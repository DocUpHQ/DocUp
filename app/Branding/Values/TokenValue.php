<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding\Values;

use App\Branding\TokenGrammar;

/**
 * 🛑 §8.14.2's re-serialisation contract, as an interface.
 *
 * > "Every emitted value MUST be **re-serialised from the parsed
 * > representation**, never echoed from storage."
 *
 * Why an interface and not a convention: the stylesheet writer takes
 * `TokenValue` objects and calls {@see self::serialise()} on each. It has no
 * method that accepts a string, so there is no code path by which a stored
 * byte reaches a stylesheet without having been parsed — the type system
 * carries the requirement rather than a comment asking people to remember it.
 *
 * The round trip is not required to be byte-identical to what the operator
 * typed; it is required to be derived only from the parsed components. A
 * colour authored `#FFF` serialises as `#ffffff`, and that is the point: the
 * output is the parser's opinion of the value, not the input.
 */
interface TokenValue
{
    /** The CSS or JSON text this value emits, built from its components. */
    public function serialise(): string;

    /**
     * The value as JSON-storable data.
     *
     * Deliberately the *authored* shape rather than the serialised CSS, so a
     * round trip through storage re-parses and re-serialises rather than
     * trusting what was written. {@see TokenGrammar} is the only
     * thing that turns this back into a value.
     */
    public function toStorage(): string|int|float|bool;
}
