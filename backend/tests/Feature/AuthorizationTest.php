<?php

declare(strict_types=1);

namespace Tests\Feature;

use App\Enums\ScanStatus;
use App\Models\Project;
use App\Models\Scan;
use App\Models\User;
use App\Services\Security\TargetScopeService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Tests\TestCase;

/**
 * SEC-01: authentication and object-level authorization.
 *
 * These tests assert that a token is required, that a caller cannot reach
 * another user's records by guessing an id, and that a missing record is a 404
 * rather than an empty 200.
 */
class AuthorizationTest extends TestCase
{
    use RefreshDatabase;

    private function user(): User
    {
        return User::factory()->create(['password' => Hash::make('password123')]);
    }

    private function tokenFor(User $user): string
    {
        $token = Str::random(40);
        $user->forceFill(['api_token' => hash('sha256', $token)])->save();

        return $token;
    }

    private function asToken(User $user): static
    {
        return $this->withHeader('Authorization', 'Bearer '.$this->tokenFor($user));
    }

    public function test_api_requires_a_token(): void
    {
        $this->getJson('/api/projects')->assertStatus(401);
        $this->getJson('/api/scans/1')->assertStatus(401);
        $this->getJson('/api/reports')->assertStatus(401);
    }

    public function test_an_invalid_token_is_rejected(): void
    {
        $this->withHeader('Authorization', 'Bearer not-a-real-token')
            ->getJson('/api/projects')
            ->assertStatus(401)
            ->assertJsonPath('code', 'unauthenticated');
    }

    public function test_project_index_only_returns_owned_projects(): void
    {
        $owner = $this->user();
        $stranger = $this->user();

        $mine = Project::factory()->create(['user_id' => $owner->id, 'name' => 'Mine']);
        Project::factory()->create(['user_id' => $stranger->id, 'name' => 'Theirs']);

        $response = $this->asToken($owner)->getJson('/api/projects')->assertOk();

        $ids = collect($response->json('data'))->pluck('id')->all();

        $this->assertSame([$mine->id], $ids);
    }

    public function test_a_user_cannot_read_another_users_project(): void
    {
        $owner = $this->user();
        $stranger = $this->user();
        $project = Project::factory()->create(['user_id' => $owner->id]);

        $this->asToken($stranger)
            ->getJson("/api/projects/{$project->id}")
            ->assertStatus(403);
    }

    public function test_a_user_cannot_update_or_delete_another_users_project(): void
    {
        $owner = $this->user();
        $stranger = $this->user();
        $project = Project::factory()->create(['user_id' => $owner->id, 'name' => 'Original']);

        $this->asToken($stranger)
            ->putJson("/api/projects/{$project->id}", ['name' => 'Hijacked'])
            ->assertStatus(403);

        $this->asToken($stranger)
            ->deleteJson("/api/projects/{$project->id}")
            ->assertStatus(403);

        $this->assertSame('Original', $project->fresh()->name);
    }

    public function test_a_user_cannot_read_another_users_scan_or_results(): void
    {
        $owner = $this->user();
        $stranger = $this->user();
        $project = Project::factory()->create(['user_id' => $owner->id]);
        $scan = Scan::factory()->create(['project_id' => $project->id, 'status' => ScanStatus::Completed]);

        $this->asToken($stranger)->getJson("/api/scans/{$scan->id}")->assertStatus(403);
        $this->asToken($stranger)->getJson("/api/scans/{$scan->id}/results")->assertStatus(403);
        $this->asToken($stranger)->getJson("/api/projects/{$project->id}/scans")->assertStatus(403);
    }

    public function test_a_missing_resource_is_404_not_500(): void
    {
        $user = $this->user();

        $this->asToken($user)->getJson('/api/projects/999999')->assertStatus(404);
    }

    public function test_the_report_download_endpoint_requires_authentication(): void
    {
        $this->getJson('/api/reports/1/download')->assertStatus(401);
    }

    public function test_registration_is_disabled_by_default(): void
    {
        config(['security.allow_registration' => false]);

        $this->postJson('/api/register', [
            'name' => 'Mallory',
            'email' => 'mallory@example.com',
            'password' => 'password123456',
            'password_confirmation' => 'password123456',
        ])->assertStatus(403);
    }

    public function test_login_failure_returns_a_machine_readable_code(): void
    {
        $user = $this->user();

        $this->postJson('/api/login', ['email' => $user->email, 'password' => 'wrong'])
            ->assertStatus(401)
            ->assertJsonPath('code', 'invalid_credentials');
    }

    public function test_login_is_rate_limited(): void
    {
        $user = $this->user();

        for ($i = 0; $i < 6; $i++) {
            $response = $this->postJson('/api/login', ['email' => $user->email, 'password' => 'wrong']);
        }

        $response->assertStatus(429);
    }

    public function test_login_succeeds_and_issues_a_token(): void
    {
        $user = $this->user();

        $this->postJson('/api/login', ['email' => $user->email, 'password' => 'password123'])
            ->assertOk()
            ->assertJsonStructure(['user' => ['id', 'email'], 'token']);
    }
}
