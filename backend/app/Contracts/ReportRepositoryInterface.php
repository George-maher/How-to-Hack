<?php

namespace App\Contracts;

use App\Models\Report;
use Illuminate\Database\Eloquent\Collection;

interface ReportRepositoryInterface
{
    public function findById(int $id): ?Report;
    public function findAll(): Collection;
    public function findByScan(int $scanId): Collection;
    public function create(array $data): Report;
    public function update(Report $report, array $data): Report;
    public function delete(Report $report): bool;
}
