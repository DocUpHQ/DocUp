<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers\Federation;

/**
 * 🛑 What an inbound provisioning request asked for, as a value rather than an
 * action.
 *
 * {@see ProvisioningDriver::interpret()} returns one of these and
 * {@see ReaderProvisioning} performs it. The class note there says why; the
 * short version is that a driver which acted could not be **dry-run**, and the
 * first SCIM sync against a real directory is exactly when a mapping mistake
 * deactivates everybody.
 *
 * 🛑 **No email field, anywhere.** §8.12.1: "Reader identities MUST be keyed
 * `(binding_id, subject_hash)`, **email MUST NEVER be used for linking or
 * lookup**." SCIM's `userName` is very often an email address, which is exactly
 * why the subject is carried as the directory's opaque `id` and the display
 * label goes through {@see ReaderSubject::displayLabel()} — whose `@` test
 * exists because "a provider that puts the email in `preferred_username` —
 * Entra does — would otherwise put it in this column by a route nobody chose".
 */
final readonly class ProvisioningIntent
{
    /**
     * @param  ProvisioningAction  $action  what the directory asked for
     * @param  string  $subject  the directory's own opaque identifier, which
     *                           {@see ReaderSubject::hash()} keys. 🛑 Never an
     *                           email, even when the directory's `userName` is
     *                           one
     * @param  list<string>  $groups  group identifiers, for §8.13.7's
     *                                reconciliation — **added and removed**, so
     *                                this is the whole membership rather than a
     *                                delta
     * @param  string|null  $displayLabel  a human-readable label, or null to
     *                                     derive one. 🛑 Passed through
     *                                     {@see ReaderSubject::displayLabel()},
     *                                     which refuses anything containing `@`
     * @param  array<string, mixed>  $attributes  everything else the directory
     *                                            sent, for an operator's
     *                                            diagnosis only. Never read by
     *                                            a decision
     */
    public function __construct(
        public ProvisioningAction $action,
        public string $subject,
        public array $groups = [],
        public ?string $displayLabel = null,
        public array $attributes = [],
    ) {}

    /**
     * 🛑 Whether performing this would take access away.
     *
     * Read by the dry-run report, because "this sync would deactivate 1,400
     * readers" is the sentence that stops a bad mapping from being applied —
     * and because §8.12.26's latency only matters for the intents that do this.
     */
    public function withdrawsAccess(): bool
    {
        return $this->action === ProvisioningAction::Deactivate
            || $this->action === ProvisioningAction::Delete;
    }
}
