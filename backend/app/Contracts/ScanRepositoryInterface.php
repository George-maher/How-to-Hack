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
    public function getActiveScans(): Collection;
}
