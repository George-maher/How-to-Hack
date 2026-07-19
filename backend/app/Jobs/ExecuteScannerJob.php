<?php

namespace App\Jobs;

use App\Contracts\ScannerInterface;
use App\Models\Scan;
use App\Models\ScanResult;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Log;

class ExecuteScannerJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    public int $timeout = 120;
    public int $tries = 3;

    public function __construct(
        public readonly Scan $scan,
        public readonly string $scannerClass,
    ) {}

    public function handle(): void
    {
        $scanner = app($this->scannerClass);

        if (!$scanner instanceof ScannerInterface) {
            Log::warning('Invalid scanner class', ['class' => $this->scannerClass]);
            return;
        }

        $project = $this->scan->project;

        Log::info('Executing scanner via job', [
            'scan_id' => $this->scan->id,
            'scanner' => $scanner->name(),
        ]);

        try {
            $results = $scanner->execute($project);

            $data = array_map(function ($result) {
                return [
                    'scan_id' => $this->scan->id,
                    'scanner_name' => $result['scanner_name'],
                    'severity' => $result['severity'],
                    'title' => $result['title'],
                    'description' => $result['description'],
                    'details' => $result['details'] ?? [],
                    'file_path' => $result['file_path'] ?? null,
                    'created_at' => now(),
                    'updated_at' => now(),
                ];
            }, $results->toArray());

            if (!empty($data)) {
                ScanResult::insert($data);
            }

            $completedScanners = $this->scan->completed_scanners ?? [];
            $completedScanners[] = $scanner->name();
            $this->scan->update(['completed_scanners' => $completedScanners]);

            Log::info('Scanner execution completed via job', [
                'scanner' => $scanner->name(),
                'findings' => count($data),
            ]);
        } catch (\Throwable $e) {
            Log::error('Scanner execution failed via job', [
                'scanner' => $scanner->name(),
                'error' => $e->getMessage(),
            ]);

            if ($this->attempts() >= $this->tries) {
                $completedScanners = $this->scan->completed_scanners ?? [];
                $completedScanners[] = $scanner->name() . ':failed';
                $this->scan->update(['completed_scanners' => $completedScanners]);
            }

            throw $e;
        }
    }
}
