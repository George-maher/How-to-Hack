<?php

namespace Tests\Integration;

use App\DTOs\ScanContext;
use App\Models\Project;
use App\Models\Scan;
use App\Services\Ai\AiAgentService;
use App\Services\Ai\ReasoningChain;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

class AiAgentTest extends TestCase
{
    #[Test]
    public function it_suggests_port_scanner_first(): void
    {
        $project = Project::factory()->create();
        $scan = Scan::factory()->create(['project_id' => $project->id]);

        $context = new ScanContext(
            project: $project,
            scan: $scan,
            completedScanners: [],
            availableScanners: ['port_scanner', 'dns_enumerator', 'http_analyzer'],
        );

        $agent = app(AiAgentService::class);
        $decision = $agent->decideNextScanner($scan, $context);

        $this->assertNotNull($decision);
    }

    #[Test]
    public function it_returns_null_when_all_scanners_used(): void
    {
        $project = Project::factory()->create();
        $scan = Scan::factory()->create(['project_id' => $project->id]);

        $allScanners = ['port_scanner', 'dns_enumerator', 'http_analyzer'];
        $context = new ScanContext(
            project: $project,
            scan: $scan,
            completedScanners: $allScanners,
            availableScanners: $allScanners,
        );

        $agent = app(AiAgentService::class);
        $decision = $agent->decideNextScanner($scan, $context);

        $this->assertNull($decision);
    }
}
