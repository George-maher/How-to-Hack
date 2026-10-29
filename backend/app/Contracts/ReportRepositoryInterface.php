<?php

namespace App\Contracts;

use App\Models\Report;
use App\Models\User;
use Illuminate\Database\Eloquent\Collection;

interface ReportRepositoryInterface
{
    public function findById(int $id): ?Report;
    /**
     * Reports belonging to the user's projects. Scoped in SQL.
     */
    public function findAllForUser(User $user): Collection;
    public function findByScan(int $scanId): Collection;
    public function create(array $data): Report;
    public function update(Report $report, array $data): Report;
    public function delete(Report $report): bool;
}
