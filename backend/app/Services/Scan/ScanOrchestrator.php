<?php

namespace App\Services\Scan;

use App\Contracts\ScanRepositoryInterface;
use App\Contracts\ScanResultRepositoryInterface;
use App\DTOs\ScanContext;
use App\DTOs\ScanResultCollection;
use App\Models\Scan;
use App\Models\ScanResult;
use App\Scanners\Registry\ScannerRegistry;
use App\Services\Ai\AiAgentService;
use Illuminate\Support\Facades\Log;

class ScanOrchestrator
{
    public function __construct(
        private readonly ScannerRegistry $scannerRegistry,
        private readonly AiAgentService $aiAgent,
        private readonly ScanRepositoryInterface $scanRepository,
        private readonly ScanResultRepositoryInterface $scanResultRepository,
        private readonly ParallelScanRunner $parallelRunner,
    ) {}

    public function runScan(Scan $scan): void
    {
        $scan->markAsRunning();
        $project = $scan->project;
        $completedScanners = [];
        $allResults = [];
        $scanContext = new ScanContext(
            project: $project,
            scan: $scan,
            availableScanners: $this->scannerRegistry->all()->keys()->all(),
        );

        try {
            while (true) {
                $decision = $this->aiAgent->decideNextScanner($scan, $scanContext);

                if ($decision === null) {
                    Log::info('AI Agent decided to stop scanning', ['scan_id' => $scan->id]);
                    break;
                }

                $chosenScanners = $this->resolveScannerBatch($decision, $completedScanners);
                if (empty($chosenScanners)) {
                    break;
                }

                Log::info('Executing scanner batch', [
                    'scan_id' => $scan->id,
                    'scanners' => array_map(fn($s) => $s->name(), $chosenScanners),
                ]);

                $batchResults = $this->parallelRunner->run(
                    collect($chosenScanners),
                    $project,
                    $scanContext->toArray()
                );

                foreach ($batchResults as $scannerName => $resultCollection) {
                    $completedScanners[] = $scannerName;
                    $allResults[$scannerName] = $resultCollection->toArray();
                    $this->persistResults($scan, $scannerName, $resultCollection);

                    $scanContext = $scanContext->addResult($scannerName, $resultCollection->toArray());

                    $reasonEntry = "Scanner {$scannerName} completed with {$resultCollection->count()} finding(s)";
                    $scanContext = $scanContext->addReasoning($reasonEntry);
                }

                $scan->update(['completed_scanners' => $completedScanners]);

                if ($this->aiAgent->shouldStop($scan, $completedScanners, $allResults)) {
                    Log::info('AI Agent stopping criteria met', ['scan_id' => $scan->id]);
                    break;
                }
            }

            $scan->markAsCompleted();
            Log::info('Scan completed successfully', [
                'scan_id' => $scan->id,
                'total_scanners' => count($completedScanners),
                'total_findings' => array_sum(array_map(fn($r) => is_array($r) ? count($r) : 0, $allResults)),
            ]);
        } catch (\Throwable $e) {
            $scan->markAsFailed();
            Log::error('Scan failed', [
                'scan_id' => $scan->id,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
            ]);
            throw $e;
        }
    }

    private function resolveScannerBatch(string $primaryScanner, array $completedScanners): array
    {
        $scanners = [];
        try {
            $scanner = $this->scannerRegistry->get($primaryScanner);
            $scanners[] = $scanner;

            $independents = $this->scannerRegistry->getUnused($completedScanners)
                ->filter(fn($s) => empty($s->dependencies()) && $s->name() !== $primaryScanner)
                ->take(2);

            foreach ($independents as $indep) {
                if (!in_array($indep->name(), $completedScanners)) {
                    $scanners[] = $indep;
                }
            }
        } catch (\Throwable $e) {
            Log::warning("Could not resolve scanner batch", ['error' => $e->getMessage()]);
        }
        return $scanners;
    }

    private function persistResults(Scan $scan, string $scannerName, ScanResultCollection $results): void
    {
        $data = array_map(function ($result) use ($scan, $scannerName) {
            return [
                'scan_id' => $scan->id,
                'scanner_name' => $scannerName,
                'severity' => $result['severity'],
                'title' => $result['title'],
                'description' => $result['description'],
                'details' => json_encode($result['details'] ?? []),
                'file_path' => $result['file_path'] ?? null,
                'created_at' => now(),
                'updated_at' => now(),
            ];
        }, $results->toArray());

        if (!empty($data)) {
            ScanResult::insert($data);
        }
    }
}
