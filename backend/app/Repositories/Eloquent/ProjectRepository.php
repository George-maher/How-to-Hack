<?php

declare(strict_types=1);

namespace App\Repositories\Eloquent;

use App\Contracts\ProjectRepositoryInterface;
use App\Models\Project;
use App\Models\User;
use Illuminate\Database\Eloquent\Collection;

class ProjectRepository implements ProjectRepositoryInterface
{
    /**
     * Scoped to the owner. There is deliberately no "all projects" method:
     * an unscoped list is how cross-tenant leaks start.
     */
    public function allForUser(User $user): Collection
    {
        return Project::query()
            ->where('user_id', $user->getKey())
            ->withCount('scans')
            ->latest()
            ->get();
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
        return (bool) $project->delete();
    }

    public function findWithScans(Project $project): Project
    {
        return $project->load([
            'scans' => fn ($q) => $q->withCount('results')->latest(),
        ]);
    }
}
