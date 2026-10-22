<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Credentials;

/**
 * The four credential kinds of §8.3.3.
 *
 * > "The system MUST support GitHub App installation tokens, OAuth, personal
 * > access tokens and deploy keys, storing every credential with envelope
 * > encryption and never returning it in any API or UI response."
 *
 * Each kind seals a different **set** of fields, which is why the payload is
 * a map rather than a single string: a GitHub App needs an app id, an
 * installation id and a PEM private key, while a PAT is one token. Sealing a
 * JSON object for all four means one cipher, one AAD and one rotation path
 * instead of four.
 */
enum CredentialKind: string
{
    /**
     * A GitHub App installation: app id, installation id and the app's RSA
     * private key, from which short-lived installation tokens are minted.
     *
     * The preferred kind for GitHub, because the token DocUp holds at rest is
     * an app key scoped to an installation rather than a user's standing
     * access to everything they can see.
     */
    case GitHubApp = 'github_app';

    /** An OAuth access token, with its refresh token and expiry. */
    case OAuth = 'oauth';

    /** A personal access token. One field, and the one most often pasted into the wrong box. */
    case PersonalAccessToken = 'pat';

    /**
     * An SSH deploy key: the private key, and the public half for the
     * operator to install at the provider.
     *
     * 🛑 The public half is **not** secret and is stored outside the sealed
     * payload, because an operator has to be able to read it to complete the
     * attachment — and a UI that must unseal a credential to show a public
     * key is a UI with an unseal path §8.3.3 does not want it to have.
     */
    case DeployKey = 'deploy_key';

    /**
     * The fields this kind seals.
     *
     * Used to validate a payload before it is sealed, so a malformed
     * credential is refused at the boundary rather than discovered when a
     * fetch fails with an unhelpful 401 months later.
     *
     * @return list<string>
     */
    public function requiredFields(): array
    {
        return match ($this) {
            self::GitHubApp => ['app_id', 'installation_id', 'private_key'],
            self::OAuth => ['access_token'],
            self::PersonalAccessToken => ['token'],
            self::DeployKey => ['private_key'],
        };
    }

    /**
     * Fields that may be present but are not required.
     *
     * @return list<string>
     */
    public function optionalFields(): array
    {
        return match ($this) {
            self::GitHubApp => [],
            self::OAuth => ['refresh_token', 'token_type', 'scope'],
            self::PersonalAccessToken => ['username'],
            self::DeployKey => ['passphrase'],
        };
    }

    /** True when this kind authenticates over SSH rather than HTTPS. */
    public function isSsh(): bool
    {
        return $this === self::DeployKey;
    }
}
