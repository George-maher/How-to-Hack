<?php

declare(strict_types=1);

namespace App\Jobs;

use App\Enums\ScanOutcomeReason;
use App\Enums\ScanStatus;
use App\Models\Scan;
use App\Services\Runner\RunnerClient;
use App\Services\Security\AuditLogger;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Log;

/**
 * Best-effort process-level cancellation in the Runner.
 *
 * The runner is asked to kill any live container for this scan's jobs. Because
 * the worker and the Runner are separate processes, the outcome is *not*
 * guaranteed: when confirmation is missing the scan stays in cancel_requested
 * and a later reconciliation by the reaper turns it into `cancelled` only once
 * the worker is provably gone.
 */
class CancelScanJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    public int $timeout = 30;

    public int $tries = 1;

    public function __construct(public readonly int $scanId)
    {
    }

    public function handle(RunnerClient $runner, AuditLogger $audit): void
    {
        $scan = Scan::find($this->scanId);
        if ($scan === null) {
            return;
        }

        $jobs = $scan->scannerRuns()
            ->whereNotNull('runner_job_id')
            ->whereNull('finished_at')
            ->pluck('runner_job_id')
            ->all();

        if ($jobs === []) {
            $jobs = [RunnerClient::jobId($scan, 'nmap')];
        }

        $confirmed = false;
        foreach ($jobs as $jobId) {
            try {
                if ($runner->cancel((string) $jobId)) {
                    $confirmed = true;
                }
            } catch (\Throwable $e) {
                Log::warning('Runner cancel failed', ['job_id' => $jobId, 'error' => $e->getMessage()]);
            }
        }

        $audit->record(AuditLogger::SCAN_CANCEL_REQUESTED, $confirmed ? 'allowed' : 'unconfirmed', [
            'scan_id' => $scan->getKey(),
            'jobs' => $jobs,
            'runner_confirmed' => $confirmed,
        ], $scan);

        if (! $confirmed) {
            Log::info('Cancellation not confirmed by runner; left in cancel_requested', [
                'scan_id' => $scan->getKey(),
            ]);
        }
    }
}
