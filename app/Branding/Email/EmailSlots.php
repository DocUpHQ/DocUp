<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding\Email;

use App\Branding\TokenRefused;
use App\Branding\TokenRejection;

/**
 * §8.14.13's slot overrides for one theme revision.
 *
 * 🛑 **Validated on save, rendered on send, and the stored value is the
 * tenant's Markdown rather than DocUp's HTML.** The alternative — storing the
 * rendered HTML — would mean a release that tightened {@see SlotMarkdown}
 * could not re-render what was already stored, so every tenant would keep
 * whatever the old renderer produced for as long as the row lived. Storing the
 * source means the renderer's current rules apply to every email, and a
 * tightening takes effect on the next send rather than on the next save.
 */
final readonly class EmailSlots
{
    /**
     * @param  array<string, string>  $slots  slot value => authored Markdown
     */
    private function __construct(public array $slots) {}

    public static function none(): self
    {
        return new self([]);
    }

    /**
     * Parse an authored slot map.
     *
     * @param  array<array-key, mixed>  $authored
     *
     * @throws TokenRefused
     */
    public static function parse(array $authored): self
    {
        $slots = [];

        foreach ($authored as $name => $value) {
            $slot = EmailSlot::tryFrom((string) $name);

            if ($slot === null) {
                throw TokenRefused::of(
                    TokenRejection::UnknownEmailSlot,
                    'email.'.(string) $name,
                    'the slots are '.implode(', ', array_map(
                        static fn (EmailSlot $candidate): string => $candidate->value,
                        EmailSlot::cases(),
                    )),
                );
            }

            if ($value === null || $value === '') {
                continue;
            }

            if (! is_string($value)) {
                throw TokenRefused::of(TokenRejection::WrongType, 'email.'.$slot->value, 'Markdown text');
            }

            /*
             * 🛑 Rendered here purely to validate, and the result discarded.
             * A slot that cannot render is a slot that would fail at send time
             * — in a queued job, to a recipient, with the operator finding out
             * from a bounce. Failing on save is the only place the author is
             * still looking.
             */
            $slots[$slot->value] = SlotMarkdown::assertValid(
                $value,
                'email.'.$slot->value,
                $slot->maxCharacters(),
                EmailVariables::availableTo($slot),
            );
        }

        return new self($slots);
    }

    /** @param array<array-key, mixed> $stored */
    public static function fromStorage(array $stored): self
    {
        return self::parse($stored);
    }

    /** @return array<string, string> */
    public function toStorage(): array
    {
        return $this->slots;
    }

    public function has(EmailSlot $slot): bool
    {
        return array_key_exists($slot->value, $this->slots);
    }

    /**
     * One slot's rendered HTML, with the variable map substituted.
     *
     * @param  array<string, string>  $escaped  from {@see EmailVariables::escape()}
     *
     * @throws TokenRefused
     */
    public function render(EmailSlot $slot, array $escaped): ?string
    {
        $markdown = $this->slots[$slot->value] ?? null;

        if (! is_string($markdown)) {
            return null;
        }

        return SlotMarkdown::substitute(
            SlotMarkdown::render($markdown, 'email.'.$slot->value, $slot->maxCharacters(), array_keys($escaped)),
            $escaped,
        );
    }
}
