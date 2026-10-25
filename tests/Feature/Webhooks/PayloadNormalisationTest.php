<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Webhooks;

use App\Source\Provider;
use App\Versions\RefKind;
use App\Webhooks\DeliveryHeaders;
use App\Webhooks\ProviderProfile;
use App\Webhooks\PushEvent;
use Tests\TestCase;

/**
 * §8.5.3's normalisation and §8.5.4's truncation detection, per provider.
 *
 * Five providers describe one push five ways. The payloads below are the
 * shapes each one actually sends, trimmed to the fields DocUp reads — which
 * is the point of having them here rather than inside the fan-out tests: a
 * failure says "GitLab's tag_push changed" rather than "something did not
 * build".
 */
final class PayloadNormalisationTest extends TestCase
{
    public function test_github_push_normalises(): void
    {
        $events = $this->parse(Provider::GitHub, 'push', [
            'ref' => 'refs/heads/main',
            'after' => 'aa'.str_repeat('0', 38),
            'deleted' => false,
            'repository' => ['id' => 4242],
            'commits' => [
                ['id' => 'aa1', 'message' => 'docs: first', 'added' => ['docs/a.md']],
                ['id' => 'aa2', 'message' => 'docs: second', 'modified' => ['docs/b.md'], 'removed' => ['docs/a.md']],
            ],
        ]);

        $this->assertCount(1, $events);

        $event = $events[0];

        $this->assertSame('main', $event->refName, 'the short name, not refs/heads/main');
        $this->assertSame(RefKind::Branch, $event->refKind);
        $this->assertSame('4242', $event->repositoryIdentifier);
        $this->assertSame(['docs/a.md', 'docs/b.md'], $event->changedPaths, 'added, modified and removed, deduplicated');
        $this->assertStringContainsString('docs: second', $event->commitMessageBlob());
        $this->assertFalse($event->payloadTruncated);
        $this->assertFalse($event->refDeleted);
    }

    /** 🛑 A deleted branch is read as deleted, by either signal. */
    public function test_github_signals_a_deleted_branch(): void
    {
        $byFlag = $this->parse(Provider::GitHub, 'push', [
            'ref' => 'refs/heads/gone',
            'after' => 'bb'.str_repeat('0', 38),
            'deleted' => true,
            'repository' => ['id' => 4242],
        ]);

        $byNullSha = $this->parse(Provider::GitHub, 'push', [
            'ref' => 'refs/heads/gone',
            'after' => str_repeat('0', 40),
            'repository' => ['id' => 4242],
        ]);

        $this->assertTrue($byFlag[0]->refDeleted, 'the flag');
        $this->assertTrue($byNullSha[0]->refDeleted, 'and the null object id, because the two have disagreed for tags');
    }

    /**
     * 🛑 §8.5.4 case (b): GitHub publishes no truncation flag, so the
     * configured ceiling is what detects it.
     */
    public function test_a_github_push_at_the_commit_ceiling_is_treated_as_truncated(): void
    {
        $commits = [];

        for ($i = 0; $i < 20; $i++) {
            $commits[] = ['id' => 'c'.$i, 'message' => 'commit '.$i, 'modified' => ['docs/'.$i.'.md']];
        }

        $events = $this->parse(Provider::GitHub, 'push', [
            'ref' => 'refs/heads/main',
            'after' => 'cc'.str_repeat('0', 38),
            'repository' => ['id' => 4242],
            'commits' => $commits,
        ]);

        $this->assertTrue(
            $events[0]->payloadTruncated,
            'GitHub caps `commits` at 20 and says nothing; at the ceiling we assume everything changed',
        );

        $this->assertFalse($events[0]->changedPathsAreTrustworthy());
    }

    /** The ceiling is configuration, per §8.5.4, so raising it changes the answer. */
    public function test_the_commit_ceiling_is_read_from_configuration(): void
    {
        config(['webhooks.truncation.github.commits' => 500]);

        $commits = [];

        for ($i = 0; $i < 20; $i++) {
            $commits[] = ['id' => 'c'.$i, 'message' => 'commit '.$i, 'modified' => ['docs/'.$i.'.md']];
        }

        $events = $this->parse(Provider::GitHub, 'push', [
            'ref' => 'refs/heads/main',
            'after' => 'cc'.str_repeat('0', 38),
            'repository' => ['id' => 4242],
            'commits' => $commits,
        ]);

        $this->assertFalse(
            $events[0]->payloadTruncated,
            '🛑 §8.5.4: "never as a hard-coded fact, because providers change these limits without notice"',
        );
    }

    /**
     * 🛑 §8.5.4 case (a): GitLab is the one provider that tells us.
     *
     * `total_commits_count` carries the real number while `commits` is
     * capped, so comparing them is exact where a ceiling is a heuristic.
     */
    public function test_gitlab_reports_its_own_truncation(): void
    {
        $events = $this->parse(Provider::GitLab, 'Push Hook', [
            'object_kind' => 'push',
            'ref' => 'refs/heads/main',
            'after' => 'dd'.str_repeat('0', 38),
            'checkout_sha' => 'dd'.str_repeat('0', 38),
            'project_id' => 15,
            'total_commits_count' => 97,
            'commits' => [['id' => 'dd1', 'message' => 'one', 'modified' => ['docs/x.md']]],
        ]);

        $this->assertTrue($events[0]->payloadTruncated, '97 commits reported, 1 sent');
        $this->assertSame('15', $events[0]->repositoryIdentifier);
    }

    /** GitLab's tag_push is a tag, and the ref must agree with the object kind. */
    public function test_gitlab_tag_push_normalises_and_disagreement_is_refused(): void
    {
        $tag = $this->parse(Provider::GitLab, 'Tag Push Hook', [
            'object_kind' => 'tag_push',
            'ref' => 'refs/tags/v3.0.0',
            'after' => 'ee'.str_repeat('0', 38),
            'checkout_sha' => 'ff'.str_repeat('0', 38),
            'project_id' => 15,
        ]);

        $this->assertSame(RefKind::Tag, $tag[0]->refKind);
        $this->assertSame('v3.0.0', $tag[0]->refName);
        $this->assertSame(
            'ff'.str_repeat('0', 38),
            $tag[0]->commitSha,
            'checkout_sha, not after: an annotated tag\'s `after` is the tag object, and §8.5.1 pins a commit',
        );

        $mismatched = $this->parse(Provider::GitLab, 'Tag Push Hook', [
            'object_kind' => 'tag_push',
            'ref' => 'refs/heads/main',
            'checkout_sha' => 'ee'.str_repeat('0', 38),
            'project_id' => 15,
        ]);

        $this->assertSame([], $mismatched, 'a tag_push naming a branch is refused rather than reconciled');
    }

    /**
     * 🛑 Bitbucket sends several refs in one delivery, and no file lists at
     * all (§8.5.4 case (c)).
     */
    public function test_bitbucket_cloud_yields_one_event_per_change_and_is_always_truncated(): void
    {
        $events = $this->parse(Provider::BitbucketCloud, 'repo:push', [
            'repository' => ['uuid' => '{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}'],
            'push' => ['changes' => [
                ['new' => ['name' => 'main', 'type' => 'branch', 'target' => ['hash' => 'a1']],
                    'commits' => [['message' => 'docs: one']]],
                ['new' => ['name' => 'v4.0.0', 'type' => 'tag', 'target' => ['hash' => 'b2']]],
                ['new' => null, 'old' => ['name' => 'old-branch', 'type' => 'branch'], 'closed' => true],
            ]],
        ]);

        $this->assertCount(3, $events, 'git push --all arrives as one delivery with one entry per ref');

        $this->assertSame('main', $events[0]->refName);
        $this->assertSame(RefKind::Tag, $events[1]->refKind);
        $this->assertTrue($events[2]->refDeleted, 'a closed change is a deleted ref');

        foreach ($events as $event) {
            $this->assertTrue(
                $event->payloadTruncated,
                '🛑 §8.5.4 case (c): Bitbucket sends no file arrays, so every push is "everything changed"',
            );
        }

        $this->assertSame(
            '{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}',
            $events[0]->repositoryIdentifier,
            'the braced UUID is carried as sent; canonicalisation happens at comparison',
        );
    }

    /** 🛑 And the delivery id is suffixed per change, or §8.5.4 layer 1 would collapse them. */
    public function test_bitbucket_delivery_ids_are_unique_per_change(): void
    {
        $events = $this->parse(Provider::BitbucketCloud, 'repo:push', [
            'repository' => ['uuid' => '{AAAA}'],
            'push' => ['changes' => [
                ['new' => ['name' => 'main', 'type' => 'branch', 'target' => ['hash' => 'a1']]],
                ['new' => ['name' => 'dev', 'type' => 'branch', 'target' => ['hash' => 'b2']]],
            ]],
        ], ['X-Request-UUID' => 'req-1']);

        $this->assertSame('req-1#0', $events[0]->deliveryId);
        $this->assertSame('req-1#1', $events[1]->deliveryId);
    }

    public function test_bitbucket_server_normalises_its_own_shape(): void
    {
        $events = $this->parse(Provider::BitbucketServer, 'repo:refs_changed', [
            'eventKey' => 'repo:refs_changed',
            'repository' => ['id' => 7],
            'changes' => [
                ['ref' => ['id' => 'refs/heads/main', 'type' => 'BRANCH'], 'toHash' => 'c3', 'type' => 'UPDATE'],
                ['ref' => ['id' => 'refs/tags/v1', 'type' => 'TAG'], 'toHash' => 'd4', 'type' => 'ADD'],
                ['ref' => ['id' => 'refs/heads/dead', 'type' => 'BRANCH'], 'toHash' => str_repeat('0', 40), 'type' => 'DELETE'],
            ],
        ]);

        $this->assertCount(3, $events);
        $this->assertSame('7', $events[0]->repositoryIdentifier);
        $this->assertSame(RefKind::Tag, $events[1]->refKind);
        $this->assertTrue($events[2]->refDeleted);
    }

    /**
     * 🛑 Gitea sends tags as `create`, not as `push`.
     *
     * A parser that only handled `push` would never create a version for a
     * release tag — the single most important thing §8.6.1 asks for.
     */
    public function test_gitea_creates_a_version_from_a_create_event(): void
    {
        $events = $this->parse(Provider::Gitea, 'create', [
            'ref' => 'v5.0.0',
            'ref_type' => 'tag',
            'sha' => 'e5'.str_repeat('0', 38),
            'repository' => ['id' => 11],
        ]);

        $this->assertCount(1, $events);
        $this->assertSame('v5.0.0', $events[0]->refName, 'the ref is the SHORT name here, not a refs/ path');
        $this->assertSame(RefKind::Tag, $events[0]->refKind);
        $this->assertFalse($events[0]->refDeleted);

        $deleted = $this->parse(Provider::Gitea, 'delete', [
            'ref' => 'v5.0.0',
            'ref_type' => 'tag',
            'repository' => ['id' => 11],
        ]);

        $this->assertTrue($deleted[0]->refDeleted);
    }

    /** Forgejo's payload is Gitea's; only the headers differ. */
    public function test_forgejo_uses_the_same_parser(): void
    {
        $events = $this->parse(Provider::Forgejo, 'push', [
            'ref' => 'refs/heads/main',
            'after' => 'f6'.str_repeat('0', 38),
            'repository' => ['id' => 12],
            'commits' => [['id' => 'f1', 'message' => 'docs', 'modified' => ['docs/i.md']]],
        ], ['X-Forgejo-Delivery' => 'forgejo-1', 'X-Forgejo-Event' => 'push']);

        $this->assertSame('main', $events[0]->refName);
        $this->assertSame('forgejo-1', $events[0]->deliveryId);
    }

    /** 🛑 The signed generic contract: paths are honoured when supplied. */
    public function test_the_generic_payload_honours_its_declared_paths(): void
    {
        $events = $this->parse(Provider::Generic, 'push', [
            'ref' => 'refs/heads/main',
            'commit' => 'a7'.str_repeat('0', 38),
            'changed_paths' => ['docs/index.md'],
            'commit_message' => 'docs: update',
        ]);

        $this->assertSame(['docs/index.md'], $events[0]->changedPaths);
        $this->assertTrue($events[0]->changedPathsAreTrustworthy());

        // And a sender that cannot enumerate says so and gets a full rebuild.
        $vague = $this->parse(Provider::Generic, 'push', [
            'ref' => 'refs/heads/main',
            'commit' => 'a7'.str_repeat('0', 38),
            'changed_paths' => ['docs/index.md'],
            'truncated' => true,
        ]);

        $this->assertFalse($vague[0]->changedPathsAreTrustworthy());
    }

    /**
     * 🛑 A ref that is neither a branch nor a tag is not a version.
     *
     * `refs/pull/42/head` arrives at this endpoint on every pull request.
     * Treating it as a branch would create a reader-visible version for a
     * pull request, which §8.20 makes a preview on a different domain with
     * `no-store` — not this.
     */
    public function test_a_pull_request_ref_is_not_a_version(): void
    {
        foreach (['refs/pull/42/head', 'refs/merge-requests/7/head', 'refs/notes/commits'] as $ref) {
            $this->assertSame(
                [],
                $this->parse(Provider::GitHub, 'push', [
                    'ref' => $ref,
                    'after' => 'aa'.str_repeat('0', 38),
                    'repository' => ['id' => 4242],
                ]),
                $ref.' must not become a version',
            );
        }
    }

    /**
     * 🛑 A malformed payload yields no events rather than a TypeError.
     *
     * The signature proves the provider sent it; it proves nothing about
     * the shape. A 500 here would teach every provider to redeliver, which
     * is a denial of service we would have built ourselves.
     */
    public function test_a_structurally_wrong_payload_yields_nothing(): void
    {
        $this->assertSame([], $this->parse(Provider::GitHub, 'push', [
            'ref' => ['not', 'a', 'string'],
            'commits' => 'not an array',
            'repository' => 42,
        ]));

        $this->assertSame([], $this->parse(Provider::GitHub, 'push', []));
    }

    /** Non-string entries in a changed-path array are dropped, not stringified. */
    public function test_non_string_changed_paths_are_dropped(): void
    {
        $events = $this->parse(Provider::GitHub, 'push', [
            'ref' => 'refs/heads/main',
            'after' => 'aa'.str_repeat('0', 38),
            'repository' => ['id' => 4242],
            'commits' => [['id' => 'x', 'message' => 'm', 'modified' => ['docs/ok.md', ['nested'], 42, null]]],
        ]);

        $this->assertSame(['docs/ok.md'], $events[0]->changedPaths);
    }

    /**
     * @param  array<array-key, mixed>  $payload
     * @param  array<string, string>  $headers
     * @return list<PushEvent>
     */
    private function parse(Provider $provider, string $event, array $payload, array $headers = []): array
    {
        return ProviderProfile::for($provider)->parser->parse(
            $payload,
            $event,
            new DeliveryHeaders($headers),
        );
    }
}
