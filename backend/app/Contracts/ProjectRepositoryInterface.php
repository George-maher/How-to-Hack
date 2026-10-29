<?php

namespace App\Contracts;

use App\Models\Project;
use App\Models\User;
use Illuminate\Database\Eloquent\Collection;

interface ProjectRepositoryInterface
{
    /**
     * Every project visible to a user. Ownership is applied in SQL, never after
     * the fact, so an unscoped query cannot leak rows by accident.
     */
    public function allForUser(User $user): Collection;

    public function create(array $data): Project;

    public function update(Project $project, array $data): Project;

    public function delete(Project $project): bool;

    public function findWithScans(Project $project): Project;
}
