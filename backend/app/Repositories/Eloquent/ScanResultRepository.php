<?php

namespace App\Repositories\Eloquent;

use App\Contracts\ScanResultRepositoryInterface;
use App\Models\Scan;
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

    public function severityBreakdown(int $scanId): array
    {
        $scan = Scan::find($scanId);

        $scannerRuns = $scan?->scannerRuns()
            ->get(['scanner', 'outcome', 'findings_count', 'error'])
            ->map(fn ($run) => [
                'scanner' => $run->scanner,
                'outcome' => $run->outcome,
                'findings' => $run->findings_count,
                'error' => $run->error,
                'inconclusive' => $run->isInconclusive(),
            ])->all() ?? [];

        $inconclusive = array_values(array_filter($scannerRuns, static fn ($r) => $r['inconclusive']));

        return [
            'severities' => $this->countBySeverity($scanId),
            'scanners' => $scannerRuns,
            'inconclusive_scanners' => array_map(static fn ($r) => $r['scanner'], $inconclusive),
            // An empty result set is only meaningful when no scanner was
            // inconclusive; the UI uses this to avoid showing a false "clean".
            'authoritative' => $inconclusive === [] && $scannerRuns !== [],
        ];
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
