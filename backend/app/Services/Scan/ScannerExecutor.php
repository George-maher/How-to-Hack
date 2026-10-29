<?php

declare(strict_types=1);

namespace App\Services\Scan;

use App\Contracts\ScannerInterface;
use App\DTOs\ScannerExecutionResult;
use App\DTOs\ScannerOutcome;
use App\Models\Project;
use App\Models\Scan;
use App\Exceptions\TargetNotAuthorised;
use App\Services\Security\AuditLogger;
use App\Services\Security\TargetScopeService;
use Illuminate\Support\Facades\Log;
use Throwable;

/**
 * Runs exactly one scanner, once, and returns an honest result.
 *
 * Everything that could turn into a lie is handled here:
 *  - a scope refusal becomes `blocked`, not an empty result;
 *  - a thrown exception becomes `failed` with the message;
 *  - a timeout becomes `timed_out`;
 *  - a missing tool or unreachable Runner becomes `unavailable`.
 *
 * Callers persist the result; nothing in this class swallows a failure.
 */
final class ScannerExecutor
{
    public function __construct(
        private readonly TargetScopeService $scope,
        private readonly AuditLogger $audit,
    ) {
    }

    /**
     * @param  array<string, mixed>  $context
     */
    public function execute(ScannerInterface $scanner, Project $project, array $context = []): ScannerExecutionResult
    {
        /** @var Scan|null $scan */
        $scan = $context['scan'] ?? null;

        // Defence in depth: the worker re-checks the target it is about to touch
        // even though the API checked it before queueing and the Runner checks it
        // again before executing.
        try {
            $decision = $this->scope->evaluate(
                (string) $project->target_url,
                is_array($scan?->target_ports) ? $scan->target_ports : [],
                is_array($scan?->resolved_ips) ? $scan->resolved_ips : null,
            );
        } catch (Throwable) {
            return ScannerExecutionResult::failure($scanner->name(), ScannerOutcome::Blocked->value, 'Target policy could not be evaluated.');
        }

        if (! $decision->allowed) {
            if ($scan !== null) {
                $this->audit->denied(AuditLogger::SCOPE_DENIED, $decision->code(), [
                    'scan_id' => $scan->getKey(),
                    'scanner' => $scanner->name(),
                    'target' => $project->target_url,
                ]);
            }

            return ScannerExecutionResult::failure(
                $scanner->name(),
                ScannerOutcome::Blocked->value,
                $decision->message(),
            );
        }

        $startedAt = microtime(true);

        try {
            $result = $scanner->execute($project, [...$context, 'scope' => $decision]);
        } catch (TargetNotAuthorised $e) {
            return ScannerExecutionResult::failure(
                $scanner->name(),
                ScannerOutcome::Blocked->value,
                $e->getMessage(),
                $this->elapsedMs($startedAt),
            );
        } catch (Throwable $e) {
            Log::error('Scanner threw', [
                'scanner' => $scanner->name(),
                'scan_id' => $scan?->getKey(),
                'error' => $e->getMessage(),
            ]);

            return ScannerExecutionResult::failure(
                $scanner->name(),
                ScannerOutcome::Failed->value,
                $e->getMessage(),
                $this->elapsedMs($startedAt),
            );
        }

        if (! $result instanceof ScannerExecutionResult) {
            return ScannerExecutionResult::failure(
                $scanner->name(),
                ScannerOutcome::Failed->value,
                'Scanner did not return an execution result.',
                $this->elapsedMs($startedAt),
            );
        }

        return $result;
    }

    private function elapsedMs(float $since): int
    {
        return (int) round((microtime(true) - $since) * 1000);
    }
}
