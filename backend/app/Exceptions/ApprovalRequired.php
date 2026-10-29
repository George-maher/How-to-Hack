<?php

declare(strict_types=1);

namespace App\Exceptions;

use App\Models\ScanApproval;
use RuntimeException;

/**
 * Thrown when execution is attempted without a usable approval.
 *
 * The response is always a refusal — there is no "proceed anyway" path, and
 * retries cannot bypass it because approval is re-verified inside the job.
 */
class ApprovalRequired extends RuntimeException
{
    public function __construct(
        public readonly string $code,
        string $message,
        public readonly ?int $approvalId = null,
        public readonly ?int $scanId = null,
    ) {
        parent::__construct($message);
    }

    public static function missing(int $scanId): self
    {
        return new self(
            'approval_required',
            'This scan contains active scanners and needs explicit operator approval before it can run.',
            null,
            $scanId,
        );
    }

    public static function expired(ScanApproval $approval): self
    {
        return new self(
            'approval_expired',
            'The approval for this scan has expired. Request a new approval.',
            $approval->getKey(),
            $approval->scan_id,
        );
    }

    public static function rejected(ScanApproval $approval): self
    {
        return new self(
            'approval_rejected',
            'The operator rejected this scan.',
            $approval->getKey(),
            $approval->scan_id,
        );
    }

    public static function mismatch(ScanApproval $approval, string $expected): self
    {
        return new self(
            'approval_mismatch',
            'The scan configuration changed after approval. Request a new approval.',
            $approval->getKey(),
            $approval->scan_id,
        );
    }

    public static function consumed(ScanApproval $approval): self
    {
        return new self(
            'approval_consumed',
            'This approval was already used. Request a new approval.',
            $approval->getKey(),
            $approval->scan_id,
        );
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'message' => $this->getMessage(),
            'code' => $this->code,
            'approval_id' => $this->approvalId,
        ];
    }
}
