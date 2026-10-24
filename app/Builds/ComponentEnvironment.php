<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds;

use App\Credentials\EnvelopeCipher;
use App\Credentials\SecretString;
use App\Models\Component;
use App\Models\ComponentVariable;

/**
 * §8.5.25's component variables, resolved for one build.
 *
 * > "Each variable carries a `public` flag: a public variable enters
 * > `public_env` and therefore the fragment digest; a secret does not, and
 * > marks the fragment non-cacheable (§8.5.19). Secrets MUST be
 * > envelope-encrypted, never returned by any API or UI, never present
 * > during `fetch` (only the credential helper of §8.5.7 operates there),
 * > redacted from logs in all encodings (§8.5.21), and 🛑 **withheld
 * > entirely from fork and pull-request builds** (§8.5.10, §8.20.2)
 * > regardless of the `public` flag."
 *
 * 🛑 **"Regardless of the `public` flag" is why a fork build gets nothing at
 * all, not just the secrets.** A public variable is public to the people who
 * can read the component's settings, not to whoever opened a pull request
 * from a fork — and the values a team marks public are things like a private
 * index *hostname*, which is exactly the reconnaissance a fork build should
 * not return.
 *
 * 🛑 **Nothing here is ever resolved for the `fetch` stage.** §8.5.7 gives
 * that stage one channel for one credential and this is not it;
 * {@see forStage()} refuses outright rather than returning an empty map, so
 * a caller that asked the wrong question finds out.
 */
final readonly class ComponentEnvironment
{
    /**
     * @param  array<string, string>  $public  §8.5.19's `public_env`, in the digest
     * @param  array<string, SecretString>  $secret  never in a digest, never in a log
     */
    private function __construct(
        public array $public,
        public array $secret,
    ) {}

    public static function none(): self
    {
        return new self([], []);
    }

    /**
     * Read a component's variables.
     *
     * @param  bool  $fromFork  §8.5.10: a fork build receives nothing
     */
    public static function forComponent(Component $component, bool $fromFork, ?EnvelopeCipher $cipher = null): self
    {
        if ($fromFork) {
            return self::none();
        }

        $cipher ??= EnvelopeCipher::fromConfig();

        $public = [];
        $secret = [];

        $rows = ComponentVariable::query()
            ->where('component_id', $component->id)
            ->orderBy('name')
            ->get();

        foreach ($rows as $row) {
            if ($row->is_public) {
                $public[$row->name] = (string) $row->public_value;

                continue;
            }

            $sealed = $row->sealed();

            if ($sealed === null) {
                continue;
            }

            $opened = $cipher->open($sealed, EnvelopeCipher::variableAad(
                $row->id,
                $row->organisation_id,
                $row->component_id,
                $row->name,
            ));

            /*
             * One field, named `value`. The payload is a map because
             * `EnvelopeCipher` seals maps — a credential needs several
             * fields — and a variable needs exactly one; naming it rather
             * than taking the first entry means a payload that somehow has
             * two is a bug here rather than whichever one PHP ordered first.
             */
            $value = $opened['value'] ?? null;

            if ($value instanceof SecretString) {
                $secret[$row->name] = $value;
            }
        }

        return new self($public, $secret);
    }

    /**
     * What actually enters the container, for one stage.
     *
     * @return array<string, string>
     *
     * @throws \LogicException for the fetch stage
     */
    public function forStage(Stage $stage): array
    {
        if ($stage === Stage::Fetch) {
            throw new \LogicException(
                'component variables are never present during fetch (§8.5.25); only the §8.5.7 credential helper is',
            );
        }

        $environment = $this->public;

        foreach ($this->secret as $name => $value) {
            $environment[$name] = $value->reveal();
        }

        return $environment;
    }

    /**
     * 🛑 §8.5.19: "Any configuration referencing a secret MUST mark its
     * fragment **non-cacheable**."
     *
     * Read as "a build that was given a secret", not "a build that used
     * one": whether the generator actually read the variable is unknowable
     * from outside it, and the safe side of that uncertainty is the one that
     * does not cache.
     */
    public function makesFragmentUncacheable(): bool
    {
        return $this->secret !== [];
    }

    /**
     * The names, for the build log and the provenance record. Never the values.
     *
     * @return array{public: list<string>, secret: list<string>}
     */
    public function names(): array
    {
        return [
            'public' => array_keys($this->public),
            'secret' => array_keys($this->secret),
        ];
    }
}
