<?php

declare(strict_types=1);

namespace App\Policies;

use App\Models\Report;
use App\Models\User;

/**
 * Reports contain the full scan evidence, so access is derived from the owning
 * project — never from the fact that a caller happens to know the report id.
 */
final class ReportPolicy
{
    public function viewAny(User $user): bool
    {
        return true;
    }

    public function view(User $user, Report $report): bool
    {
        return $this->owns($user, $report);
    }

    public function download(User $user, Report $report): bool
    {
        return $this->owns($user, $report);
    }

    public function create(User $user, Report $report): bool
    {
        return $this->owns($user, $report);
    }

    public function delete(User $user, Report $report): bool
    {
        return $this->owns($user, $report);
    }

    private function owns(User $user, Report $report): bool
    {
        $report->loadMissing('scan.project');

        return $report->scan?->project !== null
            && (int) $report->scan->project->user_id === (int) $user->getKey();
    }
}
