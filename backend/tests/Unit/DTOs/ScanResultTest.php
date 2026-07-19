<?php

namespace Tests\Unit\DTOs;

use App\DTOs\ScanResult;
use App\Enums\SeverityLevel;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

class ScanResultTest extends TestCase
{
    #[Test]
    public function it_creates_from_array(): void
    {
        $data = [
            'scanner_name' => 'port_scanner',
            'severity' => 'high',
            'title' => 'Open port 22',
            'description' => 'SSH port is open',
            'details' => ['port' => 22],
        ];

        $result = ScanResult::fromArray($data);

        $this->assertEquals('port_scanner', $result->scannerName);
        $this->assertEquals(SeverityLevel::High, $result->severity);
        $this->assertEquals('Open port 22', $result->title);
    }

    #[Test]
    public function it_converts_to_array(): void
    {
        $result = new ScanResult(
            scannerName: 'test_scanner',
            severity: SeverityLevel::Medium,
            title: 'Test finding',
            description: 'Test description',
            details: ['key' => 'value'],
        );

        $array = $result->toArray();

        $this->assertEquals('test_scanner', $array['scanner_name']);
        $this->assertEquals('medium', $array['severity']);
        $this->assertEquals(['key' => 'value'], $array['details']);
    }
}
