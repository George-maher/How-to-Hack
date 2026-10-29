<?php

namespace App\Repositories\Eloquent;

use App\Contracts\ScanRepositoryInterface;
use App\Enums\ScanStatus;
use App\Models\Scan;
use Illuminate\Database\Eloquent\Collection;

class ScanRepository implements ScanRepositoryInterface
{
    public function findById(int $id): ?Scan
    {
        return Scan::find($id);
    }

    public function findByProject(int $projectId): Collection
    {
        return Scan::where('project_id', $projectId)
            ->withCount('results')
            ->latest()
            ->get();
    }

    public function create(array $data): Scan
    {
        return Scan::create($data);
    }

    public function update(Scan $scan, array $data): Scan
    {
        $scan->update($data);
        return $scan->fresh();
    }

    public function delete(Scan $scan): bool
    {
        return $scan->delete();
    }

    public function findWithResults(int $id): ?Scan
    {
        return Scan::with(['project', 'scannerRuns', 'approvedScope'])
            ->withCount('results')
            ->find($id);
    }

    public function getActiveScans(): Collection
    {
        return Scan::whereIn('status', [
            ScanStatus::Queued->value,
            ScanStatus::AwaitingApproval->value,
            ScanStatus::Running->value,
            ScanStatus::CancelRequested->value,
        ])->get();
    }

    public function getStaleScans(): Collection
    {
        $threshold = now()->subSeconds((int) config('security.execution.heartbeat_stale_seconds', 300));

        return Scan::whereIn('status', [
            ScanStatus::Running->value,
            ScanStatus::CancelRequested->value,
        ])
            ->where(function ($query) use ($threshold) {
                $query->where('heartbeat_at', '<', $threshold)
                    ->orWhere(function ($q) use ($threshold) {
                        $q->whereNull('heartbeat_at')->where('started_at', '<', $threshold);
                    });
            })
            ->get();
    }
}
