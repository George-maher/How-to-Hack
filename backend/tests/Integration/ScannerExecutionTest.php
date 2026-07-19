<?php

namespace Tests\Integration;

use App\Models\Project;
use App\Scanners\PortScanner;
use App\Scanners\DnsEnumerator;
use App\Scanners\HttpAnalyzer;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

class ScannerExecutionTest extends TestCase
{
    #[Test]
    public function port_scanner_executes_without_errors(): void
    {
        $project = Project::factory()->create([
            'target_url' => 'https://example.com',
        ]);

        $scanner = app(PortScanner::class);
        $results = $scanner->execute($project);

        $this->assertNotNull($results);
        $this->assertIsArray($results->toArray());
    }

    #[Test]
    public function dns_enumerator_executes_without_errors(): void
    {
        $project = Project::factory()->create([
            'target_url' => 'https://example.com',
        ]);

        $scanner = app(DnsEnumerator::class);
        $results = $scanner->execute($project);

        $this->assertNotNull($results);
    }

    #[Test]
    public function http_analyzer_executes_without_errors(): void
    {
        $project = Project::factory()->create([
            'target_url' => 'https://example.com',
        ]);

        $scanner = app(HttpAnalyzer::class);
        $results = $scanner->execute($project);

        $this->assertNotNull($results);
    }

    #[Test]
    public function scanners_have_unique_names(): void
    {
        $names = [];
        foreach (config('scanners.registry') as $class) {
            $scanner = app($class);
            $name = $scanner->name();
            $this->assertArrayNotHasKey($name, $names, "Duplicate scanner name: {$name}");
            $names[$name] = true;
        }
    }

    #[Test]
    public function all_scanners_implement_required_methods(): void
    {
        foreach (config('scanners.registry') as $class) {
            $scanner = app($class);
            $this->assertNotEmpty($scanner->name());
            $this->assertNotEmpty($scanner->description());
            $this->assertNotEmpty($scanner->category());
            $this->assertNotEmpty($scanner->severity());
        }
    }
}
