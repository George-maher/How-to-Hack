<?php

namespace App\Contracts;

use App\Models\ScanResult;
use Illuminate\Database\Eloquent\Collection;

interface ScanResultRepositoryInterface
{
    public function findByScan(int $scanId): Collection;
    public function findByScanner(int $scanId, string $scannerName): Collection;
    public function create(array $data): ScanResult;
    public function createMany(array $data): bool;
    public function deleteByScan(int $scanId): bool;
    public function countBySeverity(int $scanId): array;

    /**
     * Severity counts plus a per-scanner outcome summary, so the UI can tell
     * "no findings" apart from "scanner broke".
     */
    public function severityBreakdown(int $scanId): array;
}
