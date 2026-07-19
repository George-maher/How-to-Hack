<?php

namespace App\Repositories\Eloquent;

use App\Contracts\ProjectRepositoryInterface;
use App\Models\Project;
use Illuminate\Database\Eloquent\Collection;

class ProjectRepository implements ProjectRepositoryInterface
{
    public function all(): Collection
    {
        return Project::withCount('scans')->latest()->get();
    }

    public function findById(int $id): ?Project
    {
        return Project::find($id);
    }

    public function create(array $data): Project
    {
        return Project::create($data);
    }

    public function update(Project $project, array $data): Project
    {
        $project->update($data);
        return $project->fresh();
    }

    public function delete(Project $project): bool
    {
        return $project->delete();
    }

    public function findWithScans(int $id): ?Project
    {
        return Project::with(['scans' => fn($q) => $q->latest()])->find($id);
    }
}
