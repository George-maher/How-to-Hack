<?php

namespace Database\Factories;

use App\Models\Project;
use App\Models\Scan;
use Illuminate\Database\Eloquent\Factories\Factory;

class ScanFactory extends Factory
{
    protected $model = Scan::class;

    public function definition(): array
    {
        return [
            'project_id' => Project::factory(),
            'status' => 'completed',
            'ai_reasoning' => [],
            'completed_scanners' => [],
            'metadata' => null,
            'outcome_reason' => 'completed',
            'started_at' => now()->subMinutes(10),
            'completed_at' => now(),
        ];
    }

    public function pending(): static
    {
        return $this->state(fn(array $attrs) => [
            'status' => 'queued',
            'started_at' => null,
            'completed_at' => null,
        ]);
    }

    public function running(): static
    {
        return $this->state(fn(array $attrs) => [
            'status' => 'running',
            'started_at' => now(),
            'completed_at' => null,
        ]);
    }
}
