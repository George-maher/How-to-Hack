<?php

namespace App\Contracts;

use App\Models\Scan;
use Illuminate\Database\Eloquent\Collection;

interface ScanRepositoryInterface
{
    public function findById(int $id): ?Scan;
    public function findByProject(int $projectId): Collection;
    public function create(array $data): Scan;
    public function update(Scan $scan, array $data): Scan;
    public function delete(Scan $scan): bool;
    public function findWithResults(int $id): ?Scan;

    /**
     * Scans still in flight (queued/awaiting approval/running/cancel requested).
     */
    public function getActiveScans(): Collection;

    /**
     * Scans that claim to be running but whose worker has stopped reporting.
     */
    public function getStaleScans(): Collection;
}
