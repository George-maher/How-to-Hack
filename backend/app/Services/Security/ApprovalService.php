<?php

declare(strict_types=1);

namespace App\Services\Security;

use App\Enums\ScanStatus;
use App\Exceptions\ApprovalRequired;
use App\Models\Scan;
use App\Models\ScanApproval;
use App\Models\User;
use App\Security\Scan\ScanPlan;
use App\Security\Target\ScopeDecision;
use Illuminate\Support\Facades\DB;

/**
 * Explicit, expiring, fingerprinted approval for active scanning.
 *
 * Properties this class guarantees:
 *  - An approval is bound to host + ports + tool set + options via a digest.
 *    Any change to any of those invalidates it (see verify()).
 *  - An approval expires. An expired approval is refused, never silently
 *    extended.
 *  - An approval is single-use per execution attempt; a retry must re-verify
 *    and cannot "replay" a consumed approval to escalate.
 *  - The AI planner has no way to call grant(): the only writer of an
 *    `approved` row is a human-initiated API call, which is audited.
 */
final class ApprovalService
{
    public function __construct(private readonly AuditLogger $audit)
    {
    }

    /**
     * Create (or refresh) the pending approval request for a scan.
     */
    public function request(Scan $scan, ScanPlan $plan, ScopeDecision $decision): ScanApproval
    {
        $fingerprint = $plan->fingerprint($decision->host, $decision->ports);
        $ttlMinutes = (int) config('security.approvals.request_ttl_minutes', 1440);

        $approval = ScanApproval::create([
            'scan_id' => $scan->getKey(),
            'project_id' => $scan->project_id,
            'user_id' => $scan->project?->user_id,
            'status' => ScanApproval::STATUS_PENDING,
            'target_url' => (string) $scan->target_url,
            'target_host' => $decision->host,
            'target_ports' => $decision->ports,
            'tools' => $plan->tools(),
            'options' => $plan->options(),
            'resolved_ips' => $decision->resolvedIps,
            'fingerprint' => $fingerprint,
            'scope_rule' => $decision->matchedRule,
            'requested_at' => now(),
            'expires_at' => now()->addMinutes($ttlMinutes),
        ]);

        $this->audit->record(
            AuditLogger::APPROVAL_REQUESTED,
            'pending',
            [
                'scan_id' => $scan->getKey(),
                'target' => $scan->target_url,
                'host' => $decision->host,
                'ports' => $decision->ports,
                'active_tools' => $plan->activeTools(),
                'passive_tools' => $plan->passiveTools(),
                'fingerprint' => $fingerprint,
                'expires_at' => $approval->expires_at?->toIso8601String(),
            ],
            $scan,
        );

        if ($scan->statusEnum() !== ScanStatus::AwaitingApproval) {
            $scan->transitionTo(ScanStatus::AwaitingApproval);
        }

        return $approval;
    }

    /**
     * Operator grants approval. Only a pending, unexpired request can be granted.
     */
    public function grant(ScanApproval $approval, User $operator, ?string $note = null): ScanApproval
    {
        if ($approval->status !== ScanApproval::STATUS_PENDING) {
            throw new \RuntimeException('Only a pending approval can be granted.');
        }

        if ($approval->isRequestExpired()) {
            $approval->update(['status' => ScanApproval::STATUS_EXPIRED]);
            $this->audit->record(AuditLogger::APPROVAL_EXPIRED, 'denied', [
                'approval_id' => $approval->getKey(),
                'scan_id' => $approval->scan_id,
            ], $approval, $operator);

            throw ApprovalRequired::expired($approval);
        }

        $ttl = (int) config('security.approvals.ttl_minutes', 120);

        $approval->update([
            'status' => ScanApproval::STATUS_APPROVED,
            'decided_at' => now(),
            'decided_by' => $operator->getKey(),
            'decision_note' => $note !== null ? mb_substr($note, 0, 500) : null,
            // The execution window starts when approval is granted.
            'expires_at' => now()->addMinutes($ttl),
        ]);

        $this->audit->record(AuditLogger::APPROVAL_GRANTED, 'allowed', [
            'approval_id' => $approval->getKey(),
            'scan_id' => $approval->scan_id,
            'target' => $approval->target_url,
            'host' => $approval->target_host,
            'ports' => $approval->target_ports,
            'tools' => $approval->tools,
            'fingerprint' => $approval->fingerprint,
            'valid_until' => $approval->expires_at?->toIso8601String(),
        ], $approval, $operator);

        $scan = $approval->scan;
        if ($scan !== null && $scan->statusEnum() === ScanStatus::AwaitingApproval) {
            $scan->transitionTo(ScanStatus::Queued);
        }

        return $approval->fresh();
    }

    public function reject(ScanApproval $approval, User $operator, ?string $note = null): ScanApproval
    {
        $approval->update([
            'status' => ScanApproval::STATUS_REJECTED,
            'decided_at' => now(),
            'decided_by' => $operator->getKey(),
            'decision_note' => $note !== null ? mb_substr($note, 0, 500) : null,
        ]);

        $this->audit->record(AuditLogger::APPROVAL_REJECTED, 'denied', [
            'approval_id' => $approval->getKey(),
            'scan_id' => $approval->scan_id,
            'target' => $approval->target_url,
        ], $approval, $operator);

        return $approval->fresh();
    }

    /**
     * Re-verify the approval for a scan that is about to execute.
     *
     * Called inside the job immediately before the Runner is contacted, so a
     * queued/injected job cannot act on an approval that has since lapsed or
     * been invalidated by a configuration change.
     *
     * @throws ApprovalRequired
     */
    public function verifyForExecution(Scan $scan, ScanPlan $plan): ScanApproval
    {
        $approval = $scan->approvals()
            ->whereIn('status', [ScanApproval::STATUS_APPROVED, ScanApproval::STATUS_CONSUMED])
            ->latest('id')
            ->first();

        if ($approval === null) {
            $this->audit->record(AuditLogger::APPROVAL_MISMATCH, 'denied', [
                'scan_id' => $scan->getKey(),
                'reason' => 'no_approval',
            ], $scan);

            throw ApprovalRequired::missing((int) $scan->getKey());
        }

        if ($approval->status === ScanApproval::STATUS_CONSUMED) {
            throw ApprovalRequired::consumed($approval);
        }

        if ($approval->isRequestExpired()) {
            $approval->update(['status' => ScanApproval::STATUS_EXPIRED]);
            $this->audit->record(AuditLogger::APPROVAL_EXPIRED, 'denied', [
                'scan_id' => $scan->getKey(),
                'approval_id' => $approval->getKey(),
            ], $scan);

            throw ApprovalRequired::expired($approval);
        }

        $host = (string) $scan->target_host;
        $ports = is_array($scan->target_ports) ? $scan->target_ports : [];
        $expected = $plan->fingerprint($host, $ports);

        if (! hash_equals((string) $approval->fingerprint, $expected)) {
            $this->audit->record(AuditLogger::APPROVAL_MISMATCH, 'denied', [
                'scan_id' => $scan->getKey(),
                'approval_id' => $approval->getKey(),
                'expected' => $expected,
                'authorised' => $approval->fingerprint,
                'reason' => 'plan_changed',
            ], $scan);

            throw ApprovalRequired::mismatch($approval, $expected);
        }

        // Also refuse if the plan itself grew beyond the approved tool set: the
        // fingerprint above covers the plan's tools, but a defensive set check
        // catches a caller that replaced the plan object wholesale.
        $approvedTools = is_array($approval->tools) ? $approval->tools : [];
        $unexpected = array_diff($plan->tools(), $approvedTools);
        if ($unexpected !== []) {
            throw ApprovalRequired::mismatch($approval, $expected);
        }

        return $approval;
    }

    /**
     * Mark an approval as used. Compare-and-set so two concurrent workers
     * cannot both consume it.
     */
    public function consume(ScanApproval $approval): bool
    {
        $affected = DB::table('scan_approvals')
            ->where('id', $approval->getKey())
            ->where('status', ScanApproval::STATUS_APPROVED)
            ->update(['status' => ScanApproval::STATUS_CONSUMED, 'updated_at' => now()]);

        if ($affected === 1) {
            $this->audit->record(AuditLogger::APPROVAL_CONSUMED, 'allowed', [
                'approval_id' => $approval->getKey(),
                'scan_id' => $approval->scan_id,
            ], $approval);

            return true;
        }

        return false;
    }

    /**
     * Expire stale pending/approved approvals. Returns the number changed.
     */
    public function expireStale(): int
    {
        $stale = ScanApproval::query()
            ->whereIn('status', [ScanApproval::STATUS_PENDING, ScanApproval::STATUS_APPROVED])
            ->whereNotNull('expires_at')
            ->where('expires_at', '<', now())
            ->get();

        foreach ($stale as $approval) {
            $approval->update(['status' => ScanApproval::STATUS_EXPIRED]);

            $this->audit->record(AuditLogger::APPROVAL_EXPIRED, 'expired', [
                'approval_id' => $approval->getKey(),
                'scan_id' => $approval->scan_id,
            ], $approval);
        }

        return $stale->count();
    }
}
