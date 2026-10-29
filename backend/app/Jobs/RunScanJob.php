<?php

declare(strict_types=1);

namespace App\Jobs;

use App\Enums\ScanOutcomeReason;
use App\Enums\ScanStatus;
use App\Exceptions\InvalidScanTransition;
use App\Models\Scan;
use App\Services\Scan\ScanOrchestrator;
use App\Services\Security\AuditLogger;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Log;
use Throwable;

/**
 * Runs one scan.
 *
 * The job's own timeout is intentionally shorter than the queue's `retry_after`
 * so a long scan is never re-delivered to a second worker while the first is
 * still running. `tries = 1`: a scan is not idempotent in the sense that
 * re-running it is free, and the approval it holds is single-use.
 */
class RunScanJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    public int $timeout = 90;

    public int $tries = 1;

    /** A scan that hits the job timeout is a failed scan, not a silent no-op. */
    public bool $failOnTimeout = true;

    public function __construct(public readonly Scan $scan)
    {
    }

    public function handle(ScanOrchestrator $orchestrator, AuditLogger $audit): void
    {
        $this->scan->refresh();

        $audit->record(AuditLogger::SCAN_STARTED, 'requested', [
            'scan_id' => $this->scan->getKey(),
            'status' => $this->scan->status,
        ], $this->scan);

        try {
            $orchestrator->run($this->scan);
        } catch (Throwable $e) {
            Log::error('Scan job failed', [
                'scan_id' => $this->scan->getKey(),
                'error' => $e->getMessage(),
            ]);

            $this->terminate(ScanOutcomeReason::InternalError, $e->getMessage());

            throw $e;
        }
    }

    /**
     * Last chance to avoid a permanently "running" scan: exhausted retries, a
     * killed worker, or a job that timed out.
     */
    public function failed(?Throwable $e): void
    {
        Log::error('Scan job abandoned by the queue', [
            'scan_id' => $this->scan->getKey(),
            'error' => $e?->getMessage(),
        ]);

        $this->terminate(ScanOutcomeReason::WorkerLost, $e?->getMessage());
    }

    private function terminate(ScanOutcomeReason $reason, ?string $detail): void
    {
        $scan = Scan::query()->find($this->scan->getKey());

        if ($scan === null || $scan->isTerminal()) {
            return;
        }

        $status = $scan->statusEnum() === ScanStatus::CancelRequested
            ? ScanStatus::Cancelled
            : ScanStatus::Failed;

        $outcome = $status === ScanStatus::Cancelled ? ScanOutcomeReason::Cancelled : $reason;

        try {
            $scan->transitionTo($status, [
                'outcome_reason' => $outcome->value,
                'failure_detail' => $detail !== null ? mb_substr($detail, 0, 4000) : null,
            ]);
        } catch (InvalidScanTransition $e) {
            Log::warning('Could not terminate scan', [
                'scan_id' => $scan->getKey(),
                'error' => $e->getMessage(),
            ]);
        }
    }
}
