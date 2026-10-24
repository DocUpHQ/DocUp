<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Config;

use App\Builds\FailureCatalogue;

/**
 * A configuration file that will not be built from.
 *
 * Thrown rather than returned, for the reason `BuildFailure` and
 * `EgressRefused` are: a result object that must be inspected is one somebody
 * eventually does not inspect, and what would go uninspected here is whether
 * a repository's configuration was valid at all.
 *
 * 🛑 **`detail` never carries a value from the file.** It carries the *key*
 * that was wrong, or the JSON Pointer to it. A rejection message is written
 * into the build log, which §8.5.21 redacts secrets from on the way in — and
 * the one way to put an un-redactable secret into that log is to echo back a
 * line of a file nobody has scanned yet. The key is enough to act on.
 */
final class ConfigRefused extends \RuntimeException
{
    /**
     * @param  string  $detail  a key name or JSON Pointer, never a value
     * @param  list<string>  $offendingKeys  for a rejection that names several
     */
    private function __construct(
        public readonly ConfigRejection $rejection,
        public readonly string $detail = '',
        public readonly array $offendingKeys = [],
    ) {
        parent::__construct($rejection->identifier().($detail === '' ? '' : ': '.$detail));
    }

    /**
     * @param  list<string>  $offendingKeys
     */
    public static function of(ConfigRejection $rejection, string $detail = '', array $offendingKeys = []): self
    {
        return new self($rejection, $detail, $offendingKeys);
    }

    /** `config.unknown_key`. */
    public function identifier(): string
    {
        return $this->rejection->identifier();
    }

    /**
     * The sentence, plus the key it is about.
     *
     * The catalogue owns the prose and this appends the location, so the two
     * halves keep their separate obligations: the sentence is reworded freely,
     * the key comes from the file.
     */
    public function userMessage(): string
    {
        $message = FailureCatalogue::message($this->identifier());

        if ($this->offendingKeys !== []) {
            return $message.' Offending keys: '.implode(', ', $this->offendingKeys).'.';
        }

        return $this->detail === '' ? $message : $message.' At: '.$this->detail.'.';
    }
}
