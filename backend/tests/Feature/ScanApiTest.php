<?php

namespace Tests\Feature;

use App\Models\Project;
use App\Models\Scan;
use App\Models\User;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

class ScanApiTest extends TestCase
{
    private User $user;
    private Project $project;

    protected function setUp(): void
    {
        parent::setUp();
        $this->user = User::factory()->create();
        $this->project = Project::factory()->create(['user_id' => $this->user->id]);
    }

    #[Test]
    public function it_can_initiate_a_scan(): void
    {
        $response = $this->postJson("/api/projects/{$this->project->id}/scan");

        $response->assertAccepted();
        $response->assertJsonStructure(['message', 'scan_id']);
        $this->assertDatabaseHas('scans', [
            'project_id' => $this->project->id,
            'status' => 'pending',
        ]);
    }

    #[Test]
    public function it_can_list_scans_for_a_project(): void
    {
        Scan::factory()->count(3)->create(['project_id' => $this->project->id]);

        $response = $this->getJson("/api/projects/{$this->project->id}/scans");

        $response->assertOk();
        $response->assertJsonCount(3);
    }

    #[Test]
    public function it_can_show_a_scan_with_results(): void
    {
        $scan = Scan::factory()->create(['project_id' => $this->project->id]);

        $response = $this->getJson("/api/scans/{$scan->id}");

        $response->assertOk();
        $response->assertJsonFragment(['id' => $scan->id]);
    }

    #[Test]
    public function it_can_cancel_a_pending_scan(): void
    {
        $scan = Scan::factory()->create([
            'project_id' => $this->project->id,
            'status' => 'pending',
        ]);

        $response = $this->postJson("/api/scans/{$scan->id}/cancel");

        $response->assertOk();
        $this->assertEquals('cancelled', $scan->fresh()->status);
    }
}
