<?php

namespace App\Contracts;

use App\Models\Project;
use Illuminate\Database\Eloquent\Collection;

interface ProjectRepositoryInterface
{
    public function all(): Collection;
    public function findById(int $id): ?Project;
    public function create(array $data): Project;
    public function update(Project $project, array $data): Project;
    public function delete(Project $project): bool;
    public function findWithScans(int $id): ?Project;
}
