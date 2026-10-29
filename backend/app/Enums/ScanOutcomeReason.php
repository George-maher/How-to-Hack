<?php

declare(strict_types=1);

namespace App\Enums;

/**
 * Why a scan ended the way it did.
 *
 * Kept separate from ScanStatus so that "the process ran" and "we learned
 * something" are never conflated: a scan can be `completed` with
 * `no_findings` (clean) or `failed` with `scanner_unavailable` (not a clean
 * scan, and not a failure of the target either).
 */
enum ScanOutcomeReason: string
{
    /** Every planned scanner completed and produced parseable output. */
    case Completed = 'completed';

    /** Every planned scanner completed and none reported findings. */
    case NoFindings = 'no_findings';

    /** Some scanners completed, others did not. Findings are partial. */
    case Partial = 'partial';

    /** Approval was never granted before the request expired. */
    case ApprovalExpired = 'approval_expired';

    /** Approval was rejected by the operator. */
    case ApprovalRejected = 'approval_rejected';

    /** The requested target failed the scope policy. */
    case TargetNotAllowed = 'target_not_allowed';

    /** A scanner binary was missing from the runner image. */
    case ScannerUnavailable = 'scanner_unavailable';

    /** The runner could not be reached or rejected the job. */
    case RunnerUnavailable = 'runner_unavailable';

    /** A scanner exceeded its per-scanner timeout. */
    case ScannerTimeout = 'scanner_timeout';

    /** The whole scan exceeded its wall-clock budget. */
    case ScanTimeout = 'scan_timeout';

    /** A scanner exited non-zero. */
    case ScannerFailed = 'scanner_failed';

    /** Scanner output could not be parsed. */
    case OutputInvalid = 'output_invalid';

    /** The worker died or abandoned the job. */
    case WorkerLost = 'worker_lost';

    case Cancelled = 'cancelled';

    case InternalError = 'internal_error';

    /** True when the scan produced trustworthy (possibly empty) findings. */
    public function isSuccessful(): bool
    {
        return in_array($this, [self::Completed, self::NoFindings], true);
    }

    /** True when findings exist but coverage was incomplete. */
    public function isPartial(): bool
    {
        return $this === self::Partial;
    }

    public function label(): string
    {
        return match ($this) {
            self::Completed => 'Completed',
            self::NoFindings => 'Completed — no findings',
            self::Partial => 'Completed with errors (partial results)',
            self::ApprovalExpired => 'Not run — approval expired',
            self::ApprovalRejected => 'Not run — approval rejected',
            self::TargetNotAllowed => 'Not run — target not authorised',
            self::ScannerUnavailable => 'Failed — scanner not available',
            self::RunnerUnavailable => 'Failed — scanner service unavailable',
            self::ScannerTimeout => 'Failed — scanner timed out',
            self::ScanTimeout => 'Failed — scan timed out',
            self::ScannerFailed => 'Failed — scanner error',
            self::OutputInvalid => 'Failed — invalid scanner output',
            self::WorkerLost => 'Failed — worker lost',
            self::Cancelled => 'Cancelled',
            self::InternalError => 'Failed — internal error',
        };
    }
}
