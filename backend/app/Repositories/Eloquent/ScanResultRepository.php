<?php

namespace App\Repositories\Eloquent;

use App\Contracts\ScanResultRepositoryInterface;
use App\Models\ScanResult;
use Illuminate\Database\Eloquent\Collection;

class ScanResultRepository implements ScanResultRepositoryInterface
{
    public function findByScan(int $scanId): Collection
    {
        return ScanResult::where('scan_id', $scanId)->latest()->get();
    }

    public function findByScanner(int $scanId, string $scannerName): Collection
    {
        return ScanResult::where('scan_id', $scanId)
            ->where('scanner_name', $scannerName)
            ->get();
    }

    public function create(array $data): ScanResult
    {
        return ScanResult::create($data);
    }

    public function createMany(array $data): bool
    {
        if (empty($data)) {
            return true;
        }
        return ScanResult::insert($data);
    }

    public function deleteByScan(int $scanId): bool
    {
        return ScanResult::where('scan_id', $scanId)->delete();
    }

    public function countBySeverity(int $scanId): array
    {
        return ScanResult::where('scan_id', $scanId)
            ->selectRaw('severity, count(*) as count')
            ->groupBy('severity')
            ->pluck('count', 'severity')
            ->toArray();
    }
}
