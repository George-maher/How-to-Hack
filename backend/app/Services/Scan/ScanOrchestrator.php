<?php

declare(strict_types=1);

namespace App\Services\Scan;

use App\Contracts\ScannerInterface;
use App\DTOs\ScannerExecutionResult;
use App\DTOs\ScanContext;
use App\Enums\ScanOutcomeReason;
use App\Enums\ScanStatus;
use App\Enums\ScannerIntrusiveness;
use App\Exceptions\ApprovalRequired;
use App\Exceptions\InvalidScanTransition;
use App\Models\Project;
use App\Models\Scan;
use App\Models\ScanApproval;
use App\Models\ScanResult;
use App\Models\ScanScannerRun;
use App\Scanners\Registry\ScannerRegistry;
use App\Security\Scan\ScanPlan;
use App\Services\Ai\AiAgentService;
use App\Services\Security\ApprovalService;
use App\Services\Security\AuditLogger;
use App\Services\Security\TargetScopeService;
use Illuminate\Support\Facades\Log;
use Throwable;

/**
 * Drives one scan from `running` to a terminal state.
 *
 * Invariants:
 *  1. The scan enters `running` only through Scan::transitionTo(), which is a
 *     compare-and-set on the persisted status — a duplicate queue delivery
 *     cannot start the same scan twice.
 *  2. Approval is re-verified here, inside the worker, not at dispatch time.
 *  3. The AI planner picks the *order* of scanners from the approved plan. It
 *     cannot add a tool, change a target, or skip approval; a proposal outside
 *     the plan is refused and audited.
 *  4. Every scanner attempt is recorded with an explicit outcome, so "nothing
 *     found" is distinguishable from "the scanner never ran".
 *  5. Cancellation and the wall-clock budget are checked between scanners, and
 *     a partially-run scan is reported as such.
 */
final class ScanOrchestrator
{
    public function __construct(
        private readonly ScannerRegistry $registry,
        private readonly AiAgentService $ai,
        private readonly ScannerExecutor $executor,
        private readonly TargetScopeService $scope,
        private readonly AuditLogger $audit,
        private readonly ApprovalService $approvals,
    ) {
    }

    public function run(Scan $scan): void
    {
        $scan->refresh();

        if ($scan->isTerminal()) {
            Log::info('Scan already finished; ignoring duplicate delivery', ['scan_id' => $scan->getKey()]);

            return;
        }

        if ($scan->statusEnum() === ScanStatus::AwaitingApproval) {
            $this->finish($scan, ScanStatus::Cancelled, ScanOutcomeReason::ApprovalRejected, 'The scan was not approved.');

            return;
        }

        $project = $scan->project;
        $plan = $this->planFor($scan);

        if ($project === null || $plan === null) {
            $this->finish($scan, ScanStatus::Failed, ScanOutcomeReason::InternalError, 'The scan has no project or no plan.');

            return;
        }

        // Approval must still be valid *now*: the queue is not a permission.
        $approval = null;
        if ($plan->requiresApproval()) {
            [$approval, $denial] = $this->approvalProblem($scan, $plan);
            if ($denial !== null) {
                $this->audit->record(AuditLogger::APPROVAL_MISMATCH, 'denied', [
                    'scan_id' => $scan->getKey(),
                    'reason' => $denial,
                ], $scan);

                $this->finish($scan, ScanStatus::Failed, ScanOutcomeReason::ApprovalExpired, $denial);

                return;
            }
        }

        // Scope must still be valid *now*, including the DNS answers recorded at
        // approval time.
        $decision = $this->scope->evaluate(
            (string) $project->target_url,
            is_array($scan->target_ports) ? $scan->target_ports : [],
            is_array($scan->resolved_ips) ? $scan->resolved_ips : null,
        );

        if (! $decision->allowed) {
            $this->audit->denied(AuditLogger::SCOPE_DENIED, $decision->code(), [
                'scan_id' => $scan->getKey(),
                'target' => $project->target_url,
            ]);

            $this->finish($scan, ScanStatus::Failed, ScanOutcomeReason::TargetNotAllowed, $decision->message());

            return;
        }

        // Single use: consume before the first tool runs, so a retry or a
        // duplicate delivery cannot reuse the operator's consent.
        if ($approval !== null && ! $this->approvals->consume($approval)) {
            $this->audit->record(AuditLogger::APPROVAL_MISMATCH, 'denied', [
                'scan_id' => $scan->getKey(),
                'reason' => 'approval_already_consumed',
            ], $scan);

            $this->finish($scan, ScanStatus::Failed, ScanOutcomeReason::ApprovalExpired, 'The approval for this scan has already been used.');

            return;
        }

        try {
            $scan->transitionTo(ScanStatus::Running);
        } catch (InvalidScanTransition $e) {
            Log::warning('Refusing to start scan', ['scan_id' => $scan->getKey(), 'error' => $e->getMessage()]);

            return;
        }

        $this->audit->record(AuditLogger::SCAN_STARTED, 'allowed', [
            'scan_id' => $scan->getKey(),
            'tools' => $plan->tools(),
            'host' => $decision->host,
            'ports' => $decision->ports,
        ], $scan);

        $this->runPlan($scan, $project, $plan);
    }

    private function runPlan(Scan $scan, Project $project, ScanPlan $plan): void
    {
        $deadline = now()->addSeconds((int) config('security.execution.max_duration_seconds', 900));
        $maxScanners = (int) ($plan->option('max_scanners') ?? config('security.execution.max_scanners_per_scan', 20));

        $completed = [];
        $results = [];
        $runs = [];

        $context = new ScanContext(
            project: $project,
            scan: $scan,
            availableScanners: $plan->tools(),
        );

        try {
            while (true) {
                if ($this->shouldStop($scan)) {
                    $this->stopForCancellation($scan, $runs);

                    return;
                }

                if (now()->gt($deadline)) {
                    $this->finish($scan, ScanStatus::TimedOut, ScanOutcomeReason::ScanTimeout, 'The scan exceeded its time budget.');

                    return;
                }

                if (count($completed) >= $maxScanners) {
                    break;
                }

                $scanner = $this->nextScanner($scan, $plan, $completed, $context);

                if ($scanner === null) {
                    break;
                }

                $scan->heartbeat();

                $result = $this->executor->execute($scanner, $project, [
                    'scan' => $scan,
                    'job_id' => \App\Services\Runner\RunnerClient::jobId($scan, $scanner->name()),
                    'ports' => $scan->target_ports,
                    'pinned_ips' => $scan->resolved_ips,
                    'approval_fingerprint' => $scan->plan_fingerprint,
                    'scan_context' => $context->toArray(),
                ]);

                $runs[] = $this->recordRun($scan, $scanner, $result);

                if ($result->findings->count() > 0) {
                    $this->persistFindings($scan, $scanner->name(), $result);
                }

                $results[$scanner->name()] = $result;
                $completed[] = $scanner->name();

                $context = $context->addResult($scanner->name(), $result->findings->toArray());

                $scan->update(['completed_scanners' => $completed]);
            }

            $this->finishAfterRun($scan, $results);
        } catch (Throwable $e) {
            Log::error('Scan orchestration aborted', [
                'scan_id' => $scan->getKey(),
                'error' => $e->getMessage(),
            ]);

            $this->finish($scan, ScanStatus::Failed, ScanOutcomeReason::InternalError, $e->getMessage());

            throw $e;
        }
    }

    /**
     * Choose the next scanner: the AI proposes, the plan disposes.
     *
     * @param  list<string>  $completed
     */
    private function nextScanner(Scan $scan, ScanPlan $plan, array $completed, ScanContext $context): ?ScannerInterface
    {
        $remaining = array_values(array_diff($plan->tools(), $completed));

        if ($remaining === []) {
            return null;
        }

        $proposal = null;

        try {
            $proposal = $this->ai->decideNextScanner($scan, $context);
        } catch (Throwable $e) {
            Log::warning('AI planner failed; falling back to plan order', [
                'scan_id' => $scan->getKey(),
                'error' => $e->getMessage(),
            ]);
        }

        if (is_string($proposal) && $proposal !== '') {
            if (! $plan->has($proposal)) {
                // The planner tried to run something outside the approved plan.
                $this->audit->record(AuditLogger::AUTHZ_DENIED, 'denied', [
                    'scan_id' => $scan->getKey(),
                    'reason' => 'planner_proposed_unapproved_tool',
                    'tool' => $proposal,
                    'approved_plan' => $plan->tools(),
                ], $scan);

                Log::warning('Planner proposed a tool outside the approved plan', [
                    'scan_id' => $scan->getKey(),
                    'tool' => $proposal,
                ]);
            } elseif (! in_array($proposal, $remaining, true)) {
                // Already ran; ignore rather than loop.
                $proposal = null;
            } else {
                return $this->resolve($proposal);
            }
        }

        // Deterministic fallback: passive scanners first, then active ones, so a
        // broken planner cannot turn a scan into an approval-requiring surprise.
        usort($remaining, static function (string $a, string $b) use ($plan): int {
            $rank = static fn (string $name): int => $plan->intrusivenessOf($name) === ScannerIntrusiveness::Active ? 1 : 0;

            return [$rank($a), $a] <=> [$rank($b), $b];
        });

        foreach ($remaining as $name) {
            $scanner = $this->resolve($name);
            if ($scanner !== null) {
                return $scanner;
            }
        }

        return null;
    }

    private function resolve(string $name): ?ScannerInterface
    {
        try {
            return $this->registry->get($name);
        } catch (Throwable $e) {
            Log::warning('Scanner is not registered', ['scanner' => $name]);

            return null;
        }
    }

    private function recordRun(Scan $scan, ScannerInterface $scanner, ScannerExecutionResult $result): ScanScannerRun
    {
        return ScanScannerRun::create([
            'scan_id' => $scan->getKey(),
            'scanner' => $scanner->name(),
            'intrusiveness' => $scanner->intrusiveness()->value,
            'outcome' => $result->outcome->value,
            'attempts' => 1,
            'exit_code' => $result->exitCode,
            'duration_ms' => $result->durationMs,
            'findings_count' => $result->findings->count(),
            'error' => $result->error !== null ? mb_substr($result->error, 0, 500) : null,
            'stderr_excerpt' => $result->stderr,
            'runner_job_id' => $result->runnerJobId,
            'started_at' => now()->subMilliseconds(max(0, $result->durationMs)),
            'finished_at' => now(),
        ]);
    }

    private function persistFindings(Scan $scan, string $scannerName, ScannerExecutionResult $result): void
    {
        $rows = [];

        foreach ($result->findings->toArray() as $finding) {
            $rows[] = [
                'scan_id' => $scan->getKey(),
                'scanner_name' => $scannerName,
                'severity' => $finding['severity'],
                'title' => mb_substr((string) $finding['title'], 0, 500),
                'description' => (string) $finding['description'],
                'details' => json_encode($finding['details'] ?? []),
                'file_path' => $finding['file_path'] ?? null,
                'created_at' => now(),
                'updated_at' => now(),
            ];
        }

        if ($rows !== []) {
            ScanResult::insert($rows);
        }
    }

    /**
     * Decide the terminal state from what actually happened.
     *
     * @param  array<string, ScannerExecutionResult>  $results
     */
    private function finishAfterRun(Scan $scan, array $results): void
    {
        if ($results === []) {
            $this->finish($scan, ScanStatus::Failed, ScanOutcomeReason::InternalError, 'No scanner produced a result.');

            return;
        }

        $inconclusive = array_values(array_filter(
            $results,
            static fn (ScannerExecutionResult $r) => $r->isInconclusive(),
        ));

        $findings = array_sum(array_map(static fn (ScannerExecutionResult $r) => $r->findings->count(), $results));

        // Nothing trustworthy came back: this is a failure, not a clean scan.
        if (count($inconclusive) === count($results)) {
            $reason = $this->dominantReason($results);

            $this->finish($scan, ScanStatus::Failed, $reason, sprintf(
                'All %d scanner(s) failed to produce a usable result.',
                count($results),
            ));

            return;
        }

        $reason = $inconclusive === []
            ? ($findings === 0 ? ScanOutcomeReason::NoFindings : ScanOutcomeReason::Completed)
            : ScanOutcomeReason::Partial;

        $this->finish($scan, ScanStatus::Completed, $reason, $inconclusive === []
            ? null
            : sprintf('%d of %d scanner(s) did not complete.', count($inconclusive), count($results)));
    }

    /**
     * @param  array<string, ScannerExecutionResult>  $results
     */
    private function dominantReason(array $results): ScanOutcomeReason
    {
        $outcomes = array_map(static fn (ScannerExecutionResult $r) => $r->outcome, $results);

        return match (true) {
            in_array(\App\DTOs\ScannerOutcome::Unavailable, $outcomes, true) => ScanOutcomeReason::ScannerUnavailable,
            in_array(\App\DTOs\ScannerOutcome::TimedOut, $outcomes, true) => ScanOutcomeReason::ScannerTimeout,
            in_array(\App\DTOs\ScannerOutcome::InvalidOutput, $outcomes, true) => ScanOutcomeReason::OutputInvalid,
            in_array(\App\DTOs\ScannerOutcome::Blocked, $outcomes, true) => ScanOutcomeReason::TargetNotAllowed,
            default => ScanOutcomeReason::ScannerFailed,
        };
    }

    /**
     * @param  list<ScanScannerRun>  $runs
     */
    private function stopForCancellation(Scan $scan, array $runs): void
    {
        $this->audit->record(AuditLogger::SCAN_CANCELLED, 'allowed', [
            'scan_id' => $scan->getKey(),
            'completed_scanners' => $scan->completed_scanners,
        ], $scan);

        $this->finish($scan, ScanStatus::Cancelled, ScanOutcomeReason::Cancelled, 'Cancelled by the operator.');
    }

    private function shouldStop(Scan $scan): bool
    {
        // Re-read from the database: cancellation arrives out of band, from the
        // API process, and must be honoured between scanners.
        $status = Scan::query()->whereKey($scan->getKey())->value('status');

        return in_array($status, [ScanStatus::CancelRequested->value, ScanStatus::Cancelled->value], true);
    }

    private function finish(Scan $scan, ScanStatus $status, ScanOutcomeReason $reason, ?string $detail): void
    {
        $scan->refresh();

        if ($scan->isTerminal()) {
            return;
        }

        try {
            $attributes = [
                'outcome_reason' => $reason->value,
                'failure_detail' => $detail !== null ? mb_substr($detail, 0, 4000) : null,
            ];

            if ($reason === ScanOutcomeReason::Partial) {
                $attributes['degraded'] = true;
            }

            $scan->transitionTo($status, $attributes);
        } catch (InvalidScanTransition $e) {
            Log::warning('Refusing terminal transition', [
                'scan_id' => $scan->getKey(),
                'to' => $status->value,
                'error' => $e->getMessage(),
            ]);

            return;
        }

        $this->audit->record(
            $status === ScanStatus::Completed ? AuditLogger::SCAN_COMPLETED : AuditLogger::SCAN_FAILED,
            $status === ScanStatus::Completed ? 'allowed' : 'denied',
            [
                'scan_id' => $scan->getKey(),
                'status' => $status->value,
                'reason' => $reason->value,
                'detail' => $detail,
            ],
            $scan,
        );
    }

    /**
     * Explain why an approval is not (or no longer) valid.
     *
     * @return array{0: ?ScanApproval, 1: ?string} the approval row and the reason
     *                                             it cannot be used, if any
     */
    private function approvalProblem(Scan $scan, ScanPlan $plan): array
    {
        $approval = $scan->approvals()
            ->whereIn('status', [ScanApproval::STATUS_APPROVED, ScanApproval::STATUS_CONSUMED])
            ->latest('id')
            ->first();

        if ($approval === null) {
            return [null, 'This scan requires approval, and no approved request exists.'];
        }

        if ($approval->status === ScanApproval::STATUS_CONSUMED) {
            return [$approval, 'This approval has already been used.'];
        }

        if ($approval->expires_at === null || $approval->expires_at->isPast()) {
            return [$approval, 'The approval for this scan has expired.'];
        }

        $host = (string) $scan->target_host;
        $ports = is_array($scan->target_ports) ? $scan->target_ports : [];

        // Recomputed with the same function that produced it, from the same
        // inputs (host + ports + tool set + options).
        $expected = $plan->fingerprint($host, $ports);

        if (! hash_equals((string) $approval->fingerprint, $expected)) {
            return [$approval, 'The scan configuration changed after it was approved.'];
        }

        return [$approval, null];
    }

    /**
     * Rebuild the approved plan from the scan row.
     */
    private function planFor(Scan $scan): ?ScanPlan
    {
        $plan = is_array($scan->plan) ? $scan->plan : [];
        $tools = is_array($plan['tools'] ?? null) ? array_values($plan['tools']) : [];

        if ($tools === []) {
            return null;
        }

        return ScanPlan::fromArray($plan, $this->registry);
    }
}
