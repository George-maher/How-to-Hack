<?php

declare(strict_types=1);

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Services\Runner\RunnerClient;
use App\Services\Security\TargetScopeService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * Read-only view of the active authorization policy, so the UI can explain a
 * block instead of showing a generic failure.
 */
class PolicyController extends Controller
{
    public function __construct(
        private readonly TargetScopeService $scope,
        private readonly RunnerClient $runner,
    ) {
    }

    public function show(): JsonResponse
    {
        $log = $this->scope->describe();

        return response()->json([
            'allowlist' => $log['allowlist'],
            'lab_exceptions' => $log['lab_exceptions'],
            'runner_configured' => $this->runner->isConfigured(),
            'approval_ttl_minutes' => (int) config('security.approvals.ttl_minutes', 120),
            'max_scan_duration_seconds' => (int) config('security.execution.max_duration_seconds', 900),
        ]);
    }
}
