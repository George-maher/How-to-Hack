<?php

declare(strict_types=1);

namespace App\Policies;

use App\Models\Project;
use App\Models\User;

/**
 * Object-level authorization for projects.
 *
 * The application is single-user by design, but ownership is still enforced:
 * "there is only one user" must never become the reason a request can touch a
 * record it does not own.
 */
final class ProjectPolicy
{
    public function viewAny(User $user): bool
    {
        return true;
    }

    public function view(User $user, Project $project): bool
    {
        return $this->owns($user, $project);
    }

    public function create(User $user): bool
    {
        return true;
    }

    public function update(User $user, Project $project): bool
    {
        return $this->owns($user, $project);
    }

    public function delete(User $user, Project $project): bool
    {
        return $this->owns($user, $project);
    }

    /**
     * Starting a scan is a separate permission from editing the project.
     */
    public function scan(User $user, Project $project): bool
    {
        return $this->owns($user, $project);
    }

    private function owns(User $user, Project $project): bool
    {
        return (int) $project->user_id === (int) $user->getKey();
    }
}
