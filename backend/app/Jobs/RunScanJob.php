<?php

namespace App\Jobs;

use App\Models\Scan;
use App\Services\Scan\ScanOrchestrator;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Log;

class RunScanJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    public int $timeout = 600;
    public int $tries = 1;

    public function __construct(
        public readonly Scan $scan,
    ) {}

    public function handle(ScanOrchestrator $orchestrator): void
    {
        Log::info('Starting scan job execution', [
            'scan_id' => $this->scan->id,
            'project_id' => $this->scan->project_id,
        ]);

        try {
            $orchestrator->runScan($this->scan);
            Log::info('Scan job completed successfully', [
                'scan_id' => $this->scan->id,
            ]);
        } catch (\Throwable $e) {
            Log::error('Scan job failed', [
                'scan_id' => $this->scan->id,
                'error' => $e->getMessage(),
            ]);
            $this->scan->markAsFailed();
            throw $e;
        }
    }

    public function failed(\Throwable $e): void
    {
        Log::error('Scan job completely failed', [
            'scan_id' => $this->scan->id,
            'error' => $e->getMessage(),
        ]);
    }
}
