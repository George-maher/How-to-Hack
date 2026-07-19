<?php

namespace App\Repositories\Eloquent;

use App\Contracts\ReportRepositoryInterface;
use App\Models\Report;
use Illuminate\Database\Eloquent\Collection;

class ReportRepository implements ReportRepositoryInterface
{
    public function findById(int $id): ?Report
    {
        return Report::with('scan.project')->find($id);
    }

    public function findAll(): Collection
    {
        return Report::with('scan.project')->latest()->get();
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
