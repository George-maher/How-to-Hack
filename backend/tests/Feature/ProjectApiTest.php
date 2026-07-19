<?php

namespace Tests\Feature;

use App\Models\Project;
use App\Models\User;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

class ProjectApiTest extends TestCase
{
    private User $user;

    protected function setUp(): void
    {
        parent::setUp();
        $this->user = User::factory()->create();
    }

    #[Test]
    public function it_can_list_projects(): void
    {
        Project::factory()->count(3)->create(['user_id' => $this->user->id]);
        Project::factory()->count(2)->create();

        $response = $this->getJson('/api/projects');

        $response->assertOk();
        $response->assertJsonCount(5);
    }

    #[Test]
    public function it_can_create_a_project(): void
    {
        $data = [
            'name' => 'Test Site',
            'target_url' => 'https://example.com',
            'description' => 'A test project',
        ];

        $response = $this->postJson('/api/projects', $data);

        $response->assertCreated();
        $response->assertJsonFragment(['name' => 'Test Site']);
        $this->assertDatabaseHas('projects', ['target_url' => 'https://example.com']);
    }

    #[Test]
    public function it_can_show_a_project(): void
    {
        $project = Project::factory()->create(['user_id' => $this->user->id]);

        $response = $this->getJson("/api/projects/{$project->id}");

        $response->assertOk();
        $response->assertJsonFragment(['id' => $project->id]);
    }

    #[Test]
    public function it_returns_404_for_missing_project(): void
    {
        $response = $this->getJson('/api/projects/99999');
        $response->assertNotFound();
    }

    #[Test]
    public function it_can_delete_a_project(): void
    {
        $project = Project::factory()->create(['user_id' => $this->user->id]);

        $response = $this->deleteJson("/api/projects/{$project->id}");

        $response->assertOk();
        $this->assertSoftDeleted('projects', ['id' => $project->id]);
    }
}
