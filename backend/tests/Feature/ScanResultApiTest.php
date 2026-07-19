<?php

namespace Tests\Feature;

use App\Models\Project;
use App\Models\Scan;
use App\Models\ScanResult;
use App\Models\User;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

class ScanResultApiTest extends TestCase
{
    private Scan $scan;

    protected function setUp(): void
    {
        parent::setUp();
        $user = User::factory()->create();
        $project = Project::factory()->create(['user_id' => $user->id]);
        $this->scan = Scan::factory()->create(['project_id' => $project->id]);
    }

    #[Test]
    public function it_can_list_scan_results(): void
    {
        ScanResult::factory()->count(5)->create([
            'scan_id' => $this->scan->id,
        ]);

        $response = $this->getJson("/api/scans/{$this->scan->id}/results");

        $response->assertOk();
        $response->assertJsonCount(5);
    }

    #[Test]
    public function it_returns_severity_breakdown(): void
    {
        ScanResult::factory()->create([
            'scan_id' => $this->scan->id,
            'severity' => 'high',
        ]);
        ScanResult::factory()->count(3)->create([
            'scan_id' => $this->scan->id,
            'severity' => 'medium',
        ]);

        $response = $this->getJson("/api/scans/{$this->scan->id}/results/severity");

        $response->assertOk();
        $response->assertJsonFragment(['high' => 1]);
        $response->assertJsonFragment(['medium' => 3]);
    }
}
