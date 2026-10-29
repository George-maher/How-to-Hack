<?php

declare(strict_types=1);

namespace App\Console\Commands;

use App\Contracts\ScanRepositoryInterface;
use App\Enums\ScanOutcomeReason;
use App\Enums\ScanStatus;
use App\Exceptions\InvalidScanTransition;
use App\Models\Scan;
use App\Services\Security\ApprovalService;
use App\Services\Security\AuditLogger;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;

/**
 * Reconciles state that no live process is going to finish.
 *
 * This is the only place outside the worker that may move a scan out of
 * `running`, and only when the heartbeat proves the worker is gone. It also
 * expires approvals, so a scan cannot be approved on Monday and run on Friday.
 */
final class ReapStaleScans extends Command
{
    protected $signature = 'scans:reap {--dry-run : Report what would change without changing it}';

    protected $description = 'Fail abandoned scans and expire stale approvals';

    public function handle(
        ScanRepositoryInterface $scans,
        ApprovalService $approvals,
        AuditLogger $audit,
    ): int {
        $dryRun = (bool) $this->option('dry-run');
        $stale = $scans->getStaleScans();

        foreach ($stale as $scan) {
            /** @var Scan $scan */
            $cancelling = $scan->statusEnum() === ScanStatus::CancelRequested;
            $status = $cancelling ? ScanStatus::Cancelled : ScanStatus::Failed;
            $reason = $cancelling ? ScanOutcomeReason::Cancelled : ScanOutcomeReason::WorkerLost;

            $this->line(sprintf(
                'scan %d: %s -> %s (%s)',
                $scan->getKey(),
                (string) $scan->status,
                $status->value,
                $reason->value,
            ));

            if ($dryRun) {
                continue;
            }

            try {
                $scan->transitionTo($status, [
                    'outcome_reason' => $reason->value,
                    'failure_detail' => $cancelling
                        ? 'Cancellation completed after the worker stopped reporting.'
                        : 'The worker stopped reporting a heartbeat; the scan was abandoned.',
                ]);
            } catch (InvalidScanTransition $e) {
                Log::warning('Could not reap scan', ['scan_id' => $scan->getKey(), 'error' => $e->getMessage()]);

                continue;
            }

            $audit->record(AuditLogger::SCAN_REAPED, 'recorded', [
                'scan_id' => $scan->getKey(),
                'status' => $status->value,
                'reason' => $reason->value,
                'last_heartbeat' => $scan->heartbeat_at?->toIso8601String(),
            ], $scan);
        }

        $expired = $dryRun ? 0 : $approvals->expireStale();

        $this->info(sprintf(
            '%s %d stale scan(s), %d approval(s) expired.',
            $dryRun ? 'Would reap' : 'Reaped',
            $stale->count(),
            $expired,
        ));

        return self::SUCCESS;
    }
}
