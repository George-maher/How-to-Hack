<?php

namespace Database\Factories;

use App\Models\Scan;
use App\Models\ScanResult;
use Illuminate\Database\Eloquent\Factories\Factory;

class ScanResultFactory extends Factory
{
    protected $model = ScanResult::class;

    public function definition(): array
    {
        $scanners = ['port_scanner', 'dns_enumerator', 'http_analyzer', 'ssl_scanner'];
        $severities = ['info', 'low', 'medium', 'high', 'critical'];

        return [
            'scan_id' => Scan::factory(),
            'scanner_name' => fake()->randomElement($scanners),
            'severity' => fake()->randomElement($severities),
            'title' => fake()->sentence(4),
            'description' => fake()->paragraph(2),
            'details' => ['detail_key' => 'detail_value'],
            'file_path' => null,
        ];
    }
}
