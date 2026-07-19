<?php

namespace Database\Factories;

use App\Models\Project;
use App\Models\User;
use Illuminate\Database\Eloquent\Factories\Factory;

class ProjectFactory extends Factory
{
    protected $model = Project::class;

    public function definition(): array
    {
        return [
            'user_id' => User::factory(),
            'name' => fake()->company() . ' Security Audit',
            'target_url' => fake()->url(),
            'description' => fake()->sentence(),
            'status' => 'active',
            'metadata' => null,
        ];
    }
}
