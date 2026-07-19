<?php

namespace App\Services\Scan;

use App\Contracts\ScannerInterface;
use App\DTOs\ScanResultCollection;
use App\Models\Project;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Log;

class ParallelScanRunner
{
    private int $maxConcurrent;

    public function __construct()
    {
        $this->maxConcurrent = config('scanners.parallel.max_concurrent', 5);
    }

    public function run(Collection $scanners, Project $project, array $context = []): array
    {
        $results = [];
        $batches = $this->batchScanners($scanners);

        foreach ($batches as $batch) {
            $batchResults = $this->executeBatch($batch, $project, $context);
            foreach ($batchResults as $name => $collection) {
                $results[$name] = $collection;
            }
        }

        return $results;
    }

    private function executeBatch(Collection $batch, Project $project, array $context): array
    {
        $batchResults = [];

        foreach ($batch as $scanner) {
            try {
                $resultCollection = $scanner->execute($project, $context);
                $batchResults[$scanner->name()] = $resultCollection;
                Log::info("Scanner {$scanner->name()} completed", [
                    'findings' => $resultCollection->count(),
                ]);
            } catch (\Throwable $e) {
                Log::error("Scanner {$scanner->name()} failed", [
                    'error' => $e->getMessage(),
                ]);
                $batchResults[$scanner->name()] = new ScanResultCollection();
            }
        }

        return $batchResults;
    }

    private function batchScanners(Collection $scanners): array
    {
        $independent = [];
        $dependent = [];

        foreach ($scanners as $scanner) {
            if (empty($scanner->dependencies())) {
                $independent[] = $scanner;
            } else {
                $dependent[] = $scanner;
            }
        }

        $batches = [];
        if (!empty($independent)) {
            $batches[] = collect($independent);
        }
        foreach ($dependent as $dep) {
            $batches[] = collect([$dep]);
        }

        return $batches;
    }
}
