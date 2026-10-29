<?php

namespace App\Repositories\Eloquent;

use App\Contracts\ReportRepositoryInterface;
use App\Models\Report;
use App\Models\User;
use Illuminate\Database\Eloquent\Collection;

class ReportRepository implements ReportRepositoryInterface
{
    public function findById(int $id): ?Report
    {
        return Report::with('scan.project')->find($id);
    }

    public function findAllForUser(User $user): Collection
    {
        return Report::query()
            ->whereHas('scan.project', fn ($q) => $q->where('user_id', $user->getKey()))
            ->with('scan.project')
            ->latest()
            ->limit(200)
            ->get();
    }

    public function findByScan(int $scanId): Collection
    {
        return Report::where('scan_id', $scanId)->latest()->get();
    }

    public function create(array $data): Report
    {
        return Report::create($data);
    }

    public function update(Report $report, array $data): Report
    {
        $report->update($data);
        return $report->fresh();
    }

    public function delete(Report $report): bool
    {
        return $report->delete();
    }
}
