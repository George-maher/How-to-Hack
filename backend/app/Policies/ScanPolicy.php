<?php

declare(strict_types=1);

namespace App\Policies;

use App\Models\Scan;
use App\Models\User;

final class ScanPolicy
{
    public function viewAny(User $user, ?int $projectId = null): bool
    {
        return true;
    }

    public function view(User $user, Scan $scan): bool
    {
        return $this->owns($user, $scan);
    }

    /**
     * Cancelling a scan is allowed for the owner while it is still in flight;
     * terminal scans cannot be "cancelled" retroactively.
     */
    public function cancel(User $user, Scan $scan): bool
    {
        return $this->owns($user, $scan) && $scan->isInFlight();
    }

    /**
     * Approving an active scan. Deliberately separate from `view` so that the
     * approval decision is explicit and greppable.
     */
    public function approve(User $user, Scan $scan): bool
    {
        return $this->owns($user, $scan);
    }

    public function viewResults(User $user, Scan $scan): bool
    {
        return $this->owns($user, $scan);
    }

    private function owns(User $user, Scan $scan): bool
    {
        $scan->loadMissing('project');

        return $scan->project !== null && (int) $scan->project->user_id === (int) $user->getKey();
    }
}
